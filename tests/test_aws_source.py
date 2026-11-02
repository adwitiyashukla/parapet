import io
import json
import zipfile

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from parapet.config import Config
from parapet.engine import run_rules
from parapet.model import is_unknown
from parapet.sources import SourceError
from parapet.sources.aws import (
    AwsSource,
    make_session,
    management_coverage,
    normalize_permission,
    parse_credential_report,
)

REGION = "us-east-1"
ADMIN = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
LAMBDA_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def lambda_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", "def handler(event, context):\n    return 1\n")
    return buffer.getvalue()


def build_account():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="open-bucket")
    s3.put_bucket_policy(
        Bucket="open-bucket",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Pub",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::open-bucket/*",
                    }
                ],
            }
        ),
    )
    s3.put_bucket_acl(Bucket="open-bucket", ACL="public-read")
    s3.create_bucket(Bucket="logs-bucket")
    s3.put_bucket_acl(Bucket="logs-bucket", ACL="log-delivery-write")
    s3.create_bucket(Bucket="good-bucket")
    s3.put_public_access_block(
        Bucket="good-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_versioning(Bucket="good-bucket", VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_encryption(
        Bucket="good-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "key"}}]
        },
    )
    s3.put_bucket_logging(
        Bucket="good-bucket",
        BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": "logs-bucket", "TargetPrefix": "good/"}},
    )
    s3.put_bucket_policy(
        Bucket="good-bucket",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": ["arn:aws:s3:::good-bucket", "arn:aws:s3:::good-bucket/*"],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ],
            }
        ),
    )
    iam = boto3.client("iam", region_name=REGION)
    iam.create_user(UserName="deploy")
    iam.create_login_profile(UserName="deploy", Password="Correct-Horse-Battery-1")
    iam.create_access_key(UserName="deploy")
    iam.put_user_policy(UserName="deploy", PolicyName="admin", PolicyDocument=ADMIN)
    iam.create_group(GroupName="ops")
    iam.put_group_policy(
        GroupName="ops",
        PolicyName="wide",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]}
        ),
    )
    policy_arn = iam.create_policy(
        PolicyName="storage",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        ),
    )["Policy"]["Arn"]
    iam.attach_group_policy(GroupName="ops", PolicyArn=policy_arn)
    iam.create_role(
        RoleName="open",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
            }
        ),
    )
    iam.put_role_policy(RoleName="open", PolicyName="inline", PolicyDocument=ADMIN)
    role_arn = iam.create_role(RoleName="lambda-role", AssumeRolePolicyDocument=LAMBDA_TRUST)["Role"]["Arn"]
    iam.update_account_password_policy(MinimumPasswordLength=8, PasswordReusePrevention=2)
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    group = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    )
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(
        ImageId=image,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet,
        MetadataOptions={"HttpTokens": "optional"},
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web-1"}]}],
    )
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=10, Encrypted=False)
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=10, Encrypted=True)
    kms = boto3.client("kms", region_name=REGION)
    key = kms.create_key(Description="app")["KeyMetadata"]["KeyId"]
    kms.create_alias(AliasName="alias/app", TargetKeyId=key)
    rotated = kms.create_key(Description="rotated")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=rotated)
    rds = boto3.client("rds", region_name=REGION)
    rds.create_db_instance(
        DBInstanceIdentifier="db1",
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="app",
        MasterUserPassword="Correct-Horse-1",
        PubliclyAccessible=True,
        StorageEncrypted=False,
        BackupRetentionPeriod=0,
    )
    cloudtrail = boto3.client("cloudtrail", region_name=REGION)
    s3.create_bucket(Bucket="trail-bucket")
    cloudtrail.create_trail(
        Name="main", S3BucketName="trail-bucket", IsMultiRegionTrail=True, EnableLogFileValidation=True
    )
    cloudtrail.start_logging(Name="main")
    client = boto3.client("lambda", region_name=REGION)
    client.create_function(
        FunctionName="api", Runtime="python3.8", Role=role_arn, Handler="app.handler", Code={"ZipFile": lambda_zip()}
    )
    client.add_permission(FunctionName="api", StatementId="public", Action="lambda:InvokeFunction", Principal="*")
    client.create_function_url_config(FunctionName="api", AuthType="NONE")
    client.create_function(
        FunctionName="quiet", Runtime="python3.12", Role=role_arn, Handler="app.handler", Code={"ZipFile": lambda_zip()}
    )


@pytest.fixture(scope="module")
def inventory():
    with mock_aws():
        build_account()
        return AwsSource(make_session(), [REGION], workers=4, label="moto").collect()


def test_inventory_shape(inventory):
    assert inventory.source == "aws"
    assert inventory.account_id == "123456789012"
    assert inventory.regions == [REGION]
    assert inventory.errors == []
    counts = {}
    for res in inventory.resources:
        counts[res.type] = counts.get(res.type, 0) + 1
    assert counts["aws_s3_bucket"] == 4
    assert counts["aws_iam_user"] == 1
    assert counts["aws_iam_group"] == 1
    assert counts["aws_iam_role"] == 2
    assert counts["aws_iam_policy"] == 1
    assert counts["aws_security_group"] == 1
    assert counts["aws_default_security_group"] >= 1
    assert counts["aws_instance"] == 1
    assert counts["aws_ebs_volume"] == 3
    assert counts["aws_kms_key"] == 2
    assert counts["aws_lambda_function"] == 2
    assert counts["aws_lambda_function_url"] == 1
    assert counts["aws_cloudtrail"] == 1
    assert counts["aws_config_configuration_recorder"] == 1
    assert counts["aws_account"] == 1


def test_bucket_attributes(inventory):
    good = inventory.find("aws_s3_bucket", "good-bucket")
    assert good.arn == "arn:aws:s3:::good-bucket"
    assert good.attrs["public_access_block"]["restrict_public_buckets"] is True
    assert good.attrs["versioning"] == {"enabled": True, "mfa_delete": False}
    assert good.attrs["encryption"]["sse_algorithm"] == "aws:kms"
    assert good.attrs["logging"]["target_bucket"] == "logs-bucket"
    assert "SecureTransport" in good.attrs["policy"]
    open_bucket = inventory.find("aws_s3_bucket", "open-bucket")
    assert open_bucket.attrs["public_access_block"] is None
    assert open_bucket.attrs["encryption"] is None or open_bucket.attrs["encryption"]["sse_algorithm"] == "AES256"
    assert any(g["uri"] and g["uri"].endswith("AllUsers") for g in open_bucket.attrs["acl"]["grants"])
    account_block = inventory.find("aws_s3_account_public_access_block", "123456789012")
    assert account_block.attrs["exists"] is False


def test_iam_attributes(inventory):
    user = inventory.find("aws_iam_user", "deploy")
    assert user.attrs["password_enabled"] is True
    assert user.attrs["mfa_active"] is False
    assert len(user.attrs["access_keys"]) == 1 and user.attrs["access_keys"][0]["active"] is True
    assert user.attrs["inline_policies"][0]["name"] == "admin"
    assert user.attrs["inline_policies"][0]["policy"]["Statement"][0]["Action"] == "*"
    group = inventory.find("aws_iam_group", "ops")
    assert len(group.attrs["attached_policy_arns"]) == 1
    assert group.attrs["inline_policies"][0]["name"] == "wide"
    role = inventory.find("aws_iam_role", "open")
    assert role.attrs["assume_role_policy"]["Statement"][0]["Principal"] == {"AWS": "*"}
    assert role.attrs["inline_policies"][0]["name"] == "inline"
    account = inventory.find("aws_account", "123456789012")
    assert account.attrs["root_mfa_enabled"] is False
    policy = inventory.find("aws_iam_account_password_policy", "123456789012")
    assert policy.attrs["minimum_password_length"] == 8


def test_regional_attributes(inventory):
    group = [r for r in inventory.of_type("aws_security_group")][0]
    assert group.name == "web"
    ports = sorted(rule["from_port"] for rule in group.attrs["ingress"])
    assert ports == [22, 443]
    assert group.attrs["ingress"][0]["cidr_blocks"] == ["0.0.0.0/0"]
    instance = inventory.of_type("aws_instance")[0]
    assert instance.name == "web-1"
    assert instance.attrs["metadata_options"]["http_tokens"] == "optional"
    assert instance.attrs["associate_public_ip_address"] in (True, False)
    volumes = inventory.of_type("aws_ebs_volume")
    assert sum(1 for v in volumes if v.attrs["encrypted"]) == 1 or sum(1 for v in volumes if v.attrs["encrypted"]) == 2
    keys = {k.name: k.attrs["enable_key_rotation"] for k in inventory.of_type("aws_kms_key")}
    assert keys == {"alias/app": False, "rotated": True}
    db = inventory.find("aws_db_instance", "db1")
    assert db.attrs["publicly_accessible"] is True
    assert db.attrs["backup_retention_period"] == 0
    trail = inventory.find("aws_cloudtrail", "main")
    assert trail.attrs["is_multi_region_trail"] is True
    assert trail.attrs["enable_logging"] is True
    assert trail.attrs["enable_log_file_validation"] is True
    function = inventory.find("aws_lambda_function", "api")
    assert "public" in function.attrs["policy"]
    assert inventory.find("aws_lambda_function", "quiet").attrs["policy"] is None
    url = inventory.find("aws_lambda_function_url", "api/url")
    assert url.attrs["authorization_type"] == "NONE"
    recorder = inventory.find("aws_config_configuration_recorder", REGION)
    assert recorder.attrs["exists"] is False
    default_encryption = inventory.find("aws_ebs_encryption_by_default", REGION)
    assert default_encryption.attrs["enabled"] is False


def test_findings_from_live_inventory(inventory):
    result = run_rules(inventory, Config())
    ids = {f.rule_id for f in result.active}
    expected = {
        "S3-001",
        "S3-002",
        "S3-003",
        "S3-004",
        "S3-005",
        "S3-006",
        "S3-007",
        "S3-008",
        "S3-009",
        "IAM-002",
        "IAM-003",
        "IAM-004",
        "IAM-005",
        "IAM-009",
        "IAM-010",
        "IAM-011",
        "IAM-012",
        "EC2-001",
        "EC2-005",
        "EC2-006",
        "EC2-007",
        "EC2-008",
        "EC2-009",
        "KMS-001",
        "RDS-001",
        "RDS-002",
        "RDS-003",
        "RDS-004",
        "LAMBDA-001",
        "LAMBDA-002",
        "LAMBDA-003",
        "CONFIG-001",
        "CT-003",
        "CT-004",
    }
    assert expected <= ids
    assert "CT-001" not in ids
    assert "CT-002" not in ids
    assert "CT-005" not in ids
    assert "EC2-002" not in ids
    assert "EC2-011" not in ids
    good = [f for f in result.active if f.resource_id == "good-bucket"]
    assert {f.rule_id for f in good} == {"S3-008"}
    logs = [f for f in result.active if f.resource_id == "logs-bucket"]
    assert not {"S3-005", "S3-006"} & {f.rule_id for f in logs}
    assert result.account_id == "123456789012"


@mock_aws
def test_collector_errors_are_recorded_not_raised():
    build_account()
    source = AwsSource(make_session(), [REGION], workers=2, label="moto")

    def broken(region):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "DescribeDBInstances")

    source.collect_rds = broken
    inventory = source.collect()
    assert inventory.errors == [
        {
            "service": "rds",
            "region": REGION,
            "error": "An error occurred (AccessDenied) when calling the DescribeDBInstances operation: nope",
        }
    ]
    assert inventory.of_type("aws_db_instance") == []
    assert inventory.of_type("aws_s3_bucket")


@mock_aws
def test_bucket_call_access_denied_marks_attribute_unknown():
    boto3.client("s3", region_name=REGION).create_bucket(Bucket="bucket-b")
    source = AwsSource(make_session(), [REGION], workers=1)
    source.account_id = "123456789012"

    def denied():
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GetBucketPolicy")

    assert is_unknown(source.bucket_call("bucket-b", denied, ("NoSuchBucketPolicy",)))
    assert source.errors[0]["service"] == "s3"

    def missing():
        raise ClientError({"Error": {"Code": "NoSuchBucketPolicy", "Message": "none"}}, "GetBucketPolicy")

    assert source.bucket_call("bucket-b", missing, ("NoSuchBucketPolicy",)) is None
    assert source.collect_bucket("bucket-b").attrs["policy"] is None


@mock_aws
def test_all_regions_are_resolved():
    source = AwsSource(make_session(), ["all"], workers=1)
    source.account_id = "123456789012"
    regions = source.resolve_regions()
    assert "us-east-1" in regions and "eu-west-1" in regions
    assert regions == sorted(regions)


def test_connection_failure_becomes_source_error(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "")
    monkeypatch.delenv("AWS_SESSION_TOKEN")
    monkeypatch.delenv("AWS_SECURITY_TOKEN")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/credentials")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/config")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    with pytest.raises(SourceError):
        AwsSource(make_session(), [REGION], workers=1).collect()


def test_credential_report_parsing():
    content = (
        b"user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,"
        b"access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,"
        b"access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,"
        b"cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n"
        b"<root_account>,arn:aws:iam::1:root,2020-01-01T00:00:00+00:00,not_supported,2026-01-01T00:00:00+00:00,not_supported,not_supported,true,"
        b"false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n"
        b"bob,arn:aws:iam::1:user/bob,2024-01-01T00:00:00+00:00,true,no_information,2024-01-01T00:00:00+00:00,N/A,false,"
        b"true,2024-01-01T00:00:00+00:00,2025-06-01T00:00:00+00:00,us-east-1,s3,true,2025-01-01T00:00:00+00:00,N/A,N/A,N/A,false,N/A,false,N/A\n"
    )
    report = parse_credential_report(content)
    assert report["<root_account>"]["access_keys"] == []
    assert report["<root_account>"]["mfa_active"] is True
    bob = report["bob"]
    assert bob["password_enabled"] is True
    assert bob["mfa_active"] is False
    assert len(bob["access_keys"]) == 2
    assert bob["access_keys"][0]["last_used"] == "2025-06-01T00:00:00+00:00"
    assert bob["access_keys"][1]["last_used"] == "N/A"


def test_normalize_permission_covers_all_sources():
    permission = {
        "IpProtocol": "-1",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        "UserIdGroupPairs": [{"GroupId": "sg-1"}],
        "PrefixListIds": [{"PrefixListId": "pl-1"}],
    }
    rule = normalize_permission(permission)
    assert rule["from_port"] is None and rule["protocol"] == "-1"
    assert rule["cidr_blocks"] == ["0.0.0.0/0"] and rule["ipv6_cidr_blocks"] == ["::/0"]
    assert rule["security_groups"] == ["sg-1"] and rule["prefix_list_ids"] == ["pl-1"]


def make_trail(region, name, multi_region=True):
    s3 = boto3.client("s3", region_name=region)
    bucket = f"{name}-logs"
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    client = boto3.client("cloudtrail", region_name=region)
    client.create_trail(Name=name, S3BucketName=bucket, IsMultiRegionTrail=multi_region, EnableLogFileValidation=True)
    client.start_logging(Name=name)


@mock_aws
def test_trail_from_unscanned_home_region_is_found():
    make_trail("us-west-2", "org-trail")
    inventory = AwsSource(make_session(), ["us-east-1", "eu-west-1"], workers=2).collect()
    trails = inventory.of_type("aws_cloudtrail")
    assert [(t.name, t.region) for t in trails] == [("org-trail", "us-west-2")]
    assert trails[0].attrs["enable_logging"] is True
    assert "CT-001" not in {f.rule_id for f in run_rules(inventory, Config()).active}


@mock_aws
def test_trail_in_scanned_home_region_is_listed_once():
    make_trail("us-west-2", "main-trail")
    make_trail("us-east-1", "local-trail", multi_region=False)
    inventory = AwsSource(make_session(), ["us-east-1", "us-west-2"], workers=4).collect()
    trails = sorted((t.name, t.region) for t in inventory.of_type("aws_cloudtrail"))
    assert trails == [("local-trail", "us-east-1"), ("main-trail", "us-west-2")]


@mock_aws
def test_trail_api_errors_keep_the_trail():
    make_trail("us-east-1", "main-trail")
    source = AwsSource(make_session(), ["us-east-1"], workers=1)
    source.collect()
    original = source.client

    def client(service, region=None):
        real = original(service, region)
        if service == "cloudtrail":

            def denied(**kwargs):
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GetEventSelectors")

            real.get_event_selectors = denied
        return real

    source.client = client
    source.errors = []
    trails = source.collect_cloudtrail("us-east-1")
    assert len(trails) == 1
    assert trails[0].attrs["management_events"] is None
    assert trails[0].attrs["enable_logging"] is True
    assert source.errors[0]["service"] == "cloudtrail"


def test_management_coverage_from_event_selectors():
    assert management_coverage({}) == (True, "All")
    assert management_coverage({"EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": True}]}) == (
        True,
        "All",
    )
    write_only = {"EventSelectors": [{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}]}
    assert management_coverage(write_only) == (True, "WriteOnly")
    split = {
        "EventSelectors": [
            {"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True},
            {"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True},
        ]
    }
    assert management_coverage(split) == (True, "All")
    data_only = {"EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": False}]}
    assert management_coverage(data_only) == (False, None)
    advanced = {
        "AdvancedEventSelectors": [
            {
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Management"]},
                    {"Field": "readOnly", "Equals": ["false"]},
                ]
            }
        ]
    }
    assert management_coverage(advanced) == (True, "WriteOnly")
    advanced_all = {
        "AdvancedEventSelectors": [{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}]
    }
    assert management_coverage(advanced_all) == (True, "All")
    data_events = {"AdvancedEventSelectors": [{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}]}]}
    assert management_coverage(data_events) == (False, None)
