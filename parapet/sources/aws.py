import csv
import io
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

from parapet.model import UNKNOWN, Inventory, Resource
from parapet.sources import SourceError

PUBLIC_ACCESS_BLOCK_KEYS = {
    "BlockPublicAcls": "block_public_acls",
    "BlockPublicPolicy": "block_public_policy",
    "IgnorePublicAcls": "ignore_public_acls",
    "RestrictPublicBuckets": "restrict_public_buckets",
}
PASSWORD_POLICY_KEYS = {
    "MinimumPasswordLength": "minimum_password_length",
    "RequireSymbols": "require_symbols",
    "RequireNumbers": "require_numbers",
    "RequireUppercaseCharacters": "require_uppercase_characters",
    "RequireLowercaseCharacters": "require_lowercase_characters",
    "AllowUsersToChangePassword": "allow_users_to_change_password",
    "ExpirePasswords": "expire_passwords",
    "MaxPasswordAge": "max_password_age",
    "PasswordReusePrevention": "password_reuse_prevention",
    "HardExpiry": "hard_expiry",
}


def make_session(profile: str = ""):
    return boto3.Session(profile_name=profile or None)


def error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


def tag_name(tags) -> str:
    for tag in tags or []:
        if tag.get("Key") == "Name":
            return str(tag.get("Value", ""))
    return ""


def parse_credential_report(content: bytes) -> dict:
    report = {}
    for row in csv.DictReader(io.StringIO(content.decode("utf-8"))):
        keys = []
        for slot in ("1", "2"):
            active = row.get(f"access_key_{slot}_active", "")
            if active not in ("true", "false"):
                continue
            rotated = row.get(f"access_key_{slot}_last_rotated", "")
            if rotated in ("", "N/A"):
                continue
            keys.append(
                {
                    "active": active == "true",
                    "last_rotated": rotated,
                    "last_used": row.get(f"access_key_{slot}_last_used_date", ""),
                }
            )
        report[row["user"]] = {
            "arn": row.get("arn", ""),
            "created": row.get("user_creation_time", ""),
            "password_enabled": row.get("password_enabled") == "true",
            "password_last_used": row.get("password_last_used", ""),
            "mfa_active": row.get("mfa_active") == "true",
            "access_keys": keys,
        }
    return report


def normalize_permission(permission: dict) -> dict:
    return {
        "from_port": permission.get("FromPort"),
        "to_port": permission.get("ToPort"),
        "protocol": permission.get("IpProtocol"),
        "cidr_blocks": [r["CidrIp"] for r in permission.get("IpRanges", []) if "CidrIp" in r],
        "ipv6_cidr_blocks": [r["CidrIpv6"] for r in permission.get("Ipv6Ranges", []) if "CidrIpv6" in r],
        "security_groups": [p.get("GroupId", "") for p in permission.get("UserIdGroupPairs", [])],
        "prefix_list_ids": [p.get("PrefixListId", "") for p in permission.get("PrefixListIds", [])],
        "self": False,
    }


class AwsSource:
    def __init__(self, session, regions: list, workers: int = 8, label: str = ""):
        self.session = session
        self.requested_regions = list(regions)
        self.workers = max(1, workers)
        self.label = label
        self.account_id = ""
        self.errors = []
        self._lock = threading.Lock()
        self._boto_config = BotoConfig(retries={"max_attempts": 8, "mode": "standard"}, user_agent_extra="parapet")

    def client(self, service: str, region: str | None = None):
        with self._lock:
            return self.session.client(service, region_name=region, config=self._boto_config)

    def record_error(self, service: str, region: str, exc: Exception) -> None:
        with self._lock:
            self.errors.append({"service": service, "region": region or "global", "error": str(exc)})

    def collect(self) -> Inventory:
        try:
            self.account_id = self.client("sts").get_caller_identity()["Account"]
            regions = self.resolve_regions()
        except (ClientError, BotoCoreError) as exc:
            raise SourceError(f"could not connect to AWS: {exc}") from None
        inventory = Inventory(
            source="aws", origin=self.label or "default credentials", account_id=self.account_id, regions=regions
        )
        jobs = [("iam", None, self.collect_iam), ("s3", None, self.collect_s3)]
        regional = (
            ("ec2", self.collect_ec2),
            ("rds", self.collect_rds),
            ("kms", self.collect_kms),
            ("cloudtrail", self.collect_cloudtrail),
            ("lambda", self.collect_lambda),
            ("config", self.collect_config),
        )
        for region in regions:
            for service, collector in regional:
                jobs.append((service, region, collector))
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(collector, region): (service, region) for service, region, collector in jobs}
            for future in as_completed(futures):
                service, region = futures[future]
                try:
                    inventory.resources.extend(future.result())
                except (ClientError, BotoCoreError) as exc:
                    self.record_error(service, region, exc)
        inventory.resources.sort(key=lambda r: (r.type, r.region, r.id))
        inventory.errors = sorted(self.errors, key=lambda e: (e["service"], e["region"]))
        return inventory

    def resolve_regions(self) -> list:
        if self.requested_regions != ["all"]:
            return list(self.requested_regions)
        ec2 = self.client("ec2", "us-east-1")
        names = [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]
        return sorted(names)

    def credential_report(self, iam) -> dict:
        for _ in range(30):
            state = iam.generate_credential_report()["State"]
            if state == "COMPLETE":
                return parse_credential_report(iam.get_credential_report()["Content"])
            time.sleep(1)
        return {}

    def collect_iam(self, region) -> list:
        iam = self.client("iam")
        resources = []
        summary = iam.get_account_summary()["SummaryMap"]
        try:
            report = self.credential_report(iam)
        except ClientError as exc:
            self.record_error("iam", "global", exc)
            report = {}
        root = report.get("<root_account>", {})
        root_keys = sum(1 for key in root.get("access_keys", []) if key["active"]) if root else None
        resources.append(
            Resource(
                type="aws_account",
                id=self.account_id,
                region="global",
                name=self.account_id,
                arn=f"arn:aws:iam::{self.account_id}:root",
                attrs={
                    "root_mfa_enabled": summary.get("AccountMFAEnabled") == 1,
                    "root_access_keys": summary.get("AccountAccessKeysPresent", root_keys),
                    "users": summary.get("Users"),
                },
            )
        )
        try:
            raw_policy = iam.get_account_password_policy()["PasswordPolicy"]
            policy_attrs = {PASSWORD_POLICY_KEYS[k]: v for k, v in raw_policy.items() if k in PASSWORD_POLICY_KEYS}
            policy_attrs["exists"] = True
        except ClientError as exc:
            if error_code(exc) != "NoSuchEntity":
                raise
            policy_attrs = {"exists": False}
        resources.append(
            Resource(
                type="aws_iam_account_password_policy",
                id=self.account_id,
                region="global",
                name="account password policy",
                attrs=policy_attrs,
            )
        )
        for page in iam.get_paginator("list_users").paginate():
            for user in page["Users"]:
                name = user["UserName"]
                attrs = {"name": name, "path": user.get("Path", "/"), "created": user["CreateDate"].isoformat()}
                attrs.update(report.get(name, {}))
                attrs["attached_policy_arns"] = [
                    p["PolicyArn"]
                    for page_ in iam.get_paginator("list_attached_user_policies").paginate(UserName=name)
                    for p in page_["AttachedPolicies"]
                ]
                attrs["inline_policies"] = [
                    {
                        "name": policy_name,
                        "policy": iam.get_user_policy(UserName=name, PolicyName=policy_name)["PolicyDocument"],
                    }
                    for page_ in iam.get_paginator("list_user_policies").paginate(UserName=name)
                    for policy_name in page_["PolicyNames"]
                ]
                resources.append(
                    Resource(type="aws_iam_user", id=name, region="global", name=name, arn=user["Arn"], attrs=attrs)
                )
        for page in iam.get_paginator("list_groups").paginate():
            for group in page["Groups"]:
                name = group["GroupName"]
                attrs = {
                    "name": name,
                    "attached_policy_arns": [
                        p["PolicyArn"]
                        for page_ in iam.get_paginator("list_attached_group_policies").paginate(GroupName=name)
                        for p in page_["AttachedPolicies"]
                    ],
                    "inline_policies": [
                        {
                            "name": policy_name,
                            "policy": iam.get_group_policy(GroupName=name, PolicyName=policy_name)["PolicyDocument"],
                        }
                        for page_ in iam.get_paginator("list_group_policies").paginate(GroupName=name)
                        for policy_name in page_["PolicyNames"]
                    ],
                }
                resources.append(
                    Resource(type="aws_iam_group", id=name, region="global", name=name, arn=group["Arn"], attrs=attrs)
                )
        for page in iam.get_paginator("list_roles").paginate():
            for role in page["Roles"]:
                if role.get("Path", "/").startswith("/aws-service-role/"):
                    continue
                name = role["RoleName"]
                attrs = {
                    "name": name,
                    "assume_role_policy": role.get("AssumeRolePolicyDocument"),
                    "attached_policy_arns": [
                        p["PolicyArn"]
                        for page_ in iam.get_paginator("list_attached_role_policies").paginate(RoleName=name)
                        for p in page_["AttachedPolicies"]
                    ],
                    "inline_policies": [
                        {
                            "name": policy_name,
                            "policy": iam.get_role_policy(RoleName=name, PolicyName=policy_name)["PolicyDocument"],
                        }
                        for page_ in iam.get_paginator("list_role_policies").paginate(RoleName=name)
                        for policy_name in page_["PolicyNames"]
                    ],
                }
                resources.append(
                    Resource(type="aws_iam_role", id=name, region="global", name=name, arn=role["Arn"], attrs=attrs)
                )
        for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
            for policy in page["Policies"]:
                version = iam.get_policy_version(PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"])
                attrs = {
                    "name": policy["PolicyName"],
                    "policy": version["PolicyVersion"]["Document"],
                    "attachment_count": policy.get("AttachmentCount", 0),
                }
                resources.append(
                    Resource(
                        type="aws_iam_policy",
                        id=policy["Arn"],
                        region="global",
                        name=policy["PolicyName"],
                        arn=policy["Arn"],
                        attrs=attrs,
                    )
                )
        return resources

    def collect_s3(self, region) -> list:
        s3 = self.client("s3")
        resources = []
        control = self.client("s3control", "us-east-1")
        try:
            block = control.get_public_access_block(AccountId=self.account_id)["PublicAccessBlockConfiguration"]
            attrs = {PUBLIC_ACCESS_BLOCK_KEYS[k]: v for k, v in block.items() if k in PUBLIC_ACCESS_BLOCK_KEYS}
            attrs["exists"] = True
        except ClientError as exc:
            if error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
                raise
            attrs = {"exists": False}
        resources.append(
            Resource(
                type="aws_s3_account_public_access_block",
                id=self.account_id,
                region="global",
                name="account public access block",
                attrs=attrs,
            )
        )
        names = []
        token = None
        while True:
            response = s3.list_buckets(ContinuationToken=token) if token else s3.list_buckets()
            names.extend(bucket["Name"] for bucket in response.get("Buckets", []))
            token = response.get("ContinuationToken")
            if not token:
                break
        with ThreadPoolExecutor(max_workers=min(self.workers, 8)) as pool:
            futures = {pool.submit(self.collect_bucket, name): name for name in names}
            for future in as_completed(futures):
                try:
                    resources.append(future.result())
                except (ClientError, BotoCoreError) as exc:
                    self.record_error("s3", futures[future], exc)
        return resources

    def bucket_call(self, name: str, call, missing_codes: tuple, default=None):
        try:
            return call()
        except ClientError as exc:
            code = error_code(exc)
            if code in missing_codes:
                return default
            self.record_error("s3", name, exc)
            return UNKNOWN

    def collect_bucket(self, name: str) -> Resource:
        s3 = self.client("s3")
        location = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
        if location == "EU":
            location = "eu-west-1"
        client = self.client("s3", location)
        block = self.bucket_call(
            name,
            lambda: client.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"],
            ("NoSuchPublicAccessBlockConfiguration",),
        )
        if isinstance(block, dict):
            block = {PUBLIC_ACCESS_BLOCK_KEYS[k]: v for k, v in block.items() if k in PUBLIC_ACCESS_BLOCK_KEYS}
        versioning = self.bucket_call(name, lambda: client.get_bucket_versioning(Bucket=name), (), {})
        if isinstance(versioning, dict):
            versioning = {
                "enabled": versioning.get("Status") == "Enabled",
                "mfa_delete": versioning.get("MFADelete") == "Enabled",
            }
        encryption = self.bucket_call(
            name,
            lambda: client.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"],
            ("ServerSideEncryptionConfigurationNotFoundError",),
        )
        if isinstance(encryption, dict):
            rules = encryption.get("Rules") or [{}]
            default = rules[0].get("ApplyServerSideEncryptionByDefault", {})
            encryption = {
                "sse_algorithm": default.get("SSEAlgorithm"),
                "kms_key_id": default.get("KMSMasterKeyID"),
                "bucket_key_enabled": rules[0].get("BucketKeyEnabled"),
            }
        logging = self.bucket_call(name, lambda: client.get_bucket_logging(Bucket=name).get("LoggingEnabled"), ())
        if isinstance(logging, dict):
            logging = {"target_bucket": logging.get("TargetBucket"), "target_prefix": logging.get("TargetPrefix")}
        policy = self.bucket_call(
            name, lambda: client.get_bucket_policy(Bucket=name)["Policy"], ("NoSuchBucketPolicy",)
        )
        grants = self.bucket_call(name, lambda: client.get_bucket_acl(Bucket=name).get("Grants", []), ())
        acl = UNKNOWN
        if isinstance(grants, list):
            acl = {
                "canned": None,
                "grants": [
                    {
                        "type": g.get("Grantee", {}).get("Type"),
                        "uri": g.get("Grantee", {}).get("URI"),
                        "permission": g.get("Permission"),
                    }
                    for g in grants
                ],
            }
        return Resource(
            type="aws_s3_bucket",
            id=name,
            region=location,
            name=name,
            arn=f"arn:aws:s3:::{name}",
            attrs={
                "bucket": name,
                "public_access_block": block,
                "versioning": versioning,
                "encryption": encryption,
                "logging": logging,
                "policy": policy,
                "acl": acl,
            },
        )

    def collect_ec2(self, region) -> list:
        ec2 = self.client("ec2", region)
        resources = []
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for group in page["SecurityGroups"]:
                is_default = group["GroupName"] == "default"
                resources.append(
                    Resource(
                        type="aws_default_security_group" if is_default else "aws_security_group",
                        id=group["GroupId"],
                        region=region,
                        name=group["GroupName"],
                        arn=f"arn:aws:ec2:{region}:{self.account_id}:security-group/{group['GroupId']}",
                        attrs={
                            "name": group["GroupName"],
                            "description": group.get("Description", ""),
                            "vpc_id": group.get("VpcId"),
                            "ingress": [normalize_permission(p) for p in group.get("IpPermissions", [])],
                            "egress": [normalize_permission(p) for p in group.get("IpPermissionsEgress", [])],
                        },
                    )
                )
        for page in ec2.get_paginator("describe_instances").paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    if instance.get("State", {}).get("Name") == "terminated":
                        continue
                    options = instance.get("MetadataOptions", {})
                    resources.append(
                        Resource(
                            type="aws_instance",
                            id=instance["InstanceId"],
                            region=region,
                            name=tag_name(instance.get("Tags")),
                            arn=f"arn:aws:ec2:{region}:{self.account_id}:instance/{instance['InstanceId']}",
                            attrs={
                                "instance_type": instance.get("InstanceType"),
                                "state": instance.get("State", {}).get("Name"),
                                "subnet_id": instance.get("SubnetId"),
                                "vpc_id": instance.get("VpcId"),
                                "associate_public_ip_address": "PublicIpAddress" in instance,
                                "metadata_options": {
                                    "http_tokens": options.get("HttpTokens"),
                                    "http_endpoint": options.get("HttpEndpoint"),
                                },
                                "iam_instance_profile": instance.get("IamInstanceProfile", {}).get("Arn"),
                            },
                        )
                    )
        for page in ec2.get_paginator("describe_volumes").paginate():
            for volume in page["Volumes"]:
                resources.append(
                    Resource(
                        type="aws_ebs_volume",
                        id=volume["VolumeId"],
                        region=region,
                        name=tag_name(volume.get("Tags")),
                        arn=f"arn:aws:ec2:{region}:{self.account_id}:volume/{volume['VolumeId']}",
                        attrs={
                            "encrypted": volume.get("Encrypted"),
                            "size": volume.get("Size"),
                            "availability_zone": volume.get("AvailabilityZone"),
                            "kms_key_id": volume.get("KmsKeyId"),
                            "attached_to": [a.get("InstanceId") for a in volume.get("Attachments", [])],
                        },
                    )
                )
        default_encryption = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
        resources.append(
            Resource(
                type="aws_ebs_encryption_by_default",
                id=region,
                region=region,
                name=f"ebs default encryption {region}",
                attrs={"enabled": default_encryption},
            )
        )
        flow_logs = {}
        for page in ec2.get_paginator("describe_flow_logs").paginate():
            for log in page["FlowLogs"]:
                flow_logs.setdefault(log.get("ResourceId"), []).append(
                    {"traffic_type": log.get("TrafficType"), "log_destination_type": log.get("LogDestinationType")}
                )
        for page in ec2.get_paginator("describe_vpcs").paginate():
            for vpc in page["Vpcs"]:
                resources.append(
                    Resource(
                        type="aws_vpc",
                        id=vpc["VpcId"],
                        region=region,
                        name=tag_name(vpc.get("Tags")),
                        arn=f"arn:aws:ec2:{region}:{self.account_id}:vpc/{vpc['VpcId']}",
                        attrs={
                            "cidr_block": vpc.get("CidrBlock"),
                            "is_default": vpc.get("IsDefault", False),
                            "flow_logs": flow_logs.get(vpc["VpcId"], []),
                        },
                    )
                )
        return resources

    def collect_rds(self, region) -> list:
        rds = self.client("rds", region)
        resources = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page["DBInstances"]:
                resources.append(
                    Resource(
                        type="aws_db_instance",
                        id=db["DBInstanceIdentifier"],
                        region=region,
                        name=db["DBInstanceIdentifier"],
                        arn=db.get("DBInstanceArn", ""),
                        attrs={
                            "identifier": db["DBInstanceIdentifier"],
                            "engine": db.get("Engine"),
                            "publicly_accessible": db.get("PubliclyAccessible"),
                            "storage_encrypted": db.get("StorageEncrypted"),
                            "backup_retention_period": db.get("BackupRetentionPeriod"),
                            "deletion_protection": db.get("DeletionProtection"),
                            "auto_minor_version_upgrade": db.get("AutoMinorVersionUpgrade"),
                            "multi_az": db.get("MultiAZ"),
                            "kms_key_id": db.get("KmsKeyId"),
                        },
                    )
                )
        return resources

    def collect_kms(self, region) -> list:
        kms = self.client("kms", region)
        aliases = {}
        for page in kms.get_paginator("list_aliases").paginate():
            for alias in page["Aliases"]:
                if "TargetKeyId" in alias:
                    aliases.setdefault(alias["TargetKeyId"], alias["AliasName"])
        resources = []
        for page in kms.get_paginator("list_keys").paginate():
            for key in page["Keys"]:
                alias = aliases.get(key["KeyId"], "")
                if alias.startswith("alias/aws/"):
                    continue
                metadata = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                if metadata.get("KeyManager") != "CUSTOMER" or metadata.get("KeyState") in (
                    "PendingDeletion",
                    "PendingReplicaDeletion",
                ):
                    continue
                spec = metadata.get("KeySpec") or metadata.get("CustomerMasterKeySpec") or "SYMMETRIC_DEFAULT"
                usage = metadata.get("KeyUsage") or "ENCRYPT_DECRYPT"
                rotation = None
                if spec == "SYMMETRIC_DEFAULT" and usage == "ENCRYPT_DECRYPT":
                    rotation = kms.get_key_rotation_status(KeyId=key["KeyId"])["KeyRotationEnabled"]
                resources.append(
                    Resource(
                        type="aws_kms_key",
                        id=key["KeyId"],
                        region=region,
                        name=alias or metadata.get("Description", ""),
                        arn=key.get("KeyArn", metadata.get("Arn", "")),
                        attrs={
                            "description": metadata.get("Description"),
                            "customer_master_key_spec": spec,
                            "key_usage": usage,
                            "enable_key_rotation": rotation,
                            "key_state": metadata.get("KeyState"),
                        },
                    )
                )
        return resources

    def collect_cloudtrail(self, region) -> list:
        cloudtrail = self.client("cloudtrail", region)
        resources = []
        for trail in cloudtrail.describe_trails(includeShadowTrails=False)["trailList"]:
            if trail.get("HomeRegion") and trail["HomeRegion"] != region:
                continue
            arn = trail["TrailARN"]
            status = cloudtrail.get_trail_status(Name=arn)
            selectors = cloudtrail.get_event_selectors(TrailName=arn)
            management = not selectors.get("EventSelectors") and not selectors.get("AdvancedEventSelectors")
            read_write = "All" if management else None
            for selector in selectors.get("EventSelectors", []):
                if selector.get("IncludeManagementEvents", True):
                    management = True
                    read_write = selector.get("ReadWriteType", "All")
            for selector in selectors.get("AdvancedEventSelectors", []):
                fields = {f.get("Field"): f for f in selector.get("FieldSelectors", [])}
                if "Management" in fields.get("eventCategory", {}).get("Equals", []):
                    management = True
                    read_only = fields.get("readOnly", {}).get("Equals")
                    read_write = (
                        {"true": "ReadOnly", "false": "WriteOnly"}.get(read_only[0], "All") if read_only else "All"
                    )
            resources.append(
                Resource(
                    type="aws_cloudtrail",
                    id=trail["Name"],
                    region=region,
                    name=trail["Name"],
                    arn=arn,
                    attrs={
                        "name": trail["Name"],
                        "s3_bucket_name": trail.get("S3BucketName"),
                        "is_multi_region_trail": trail.get("IsMultiRegionTrail", False),
                        "is_organization_trail": trail.get("IsOrganizationTrail", False),
                        "include_global_service_events": trail.get("IncludeGlobalServiceEvents", False),
                        "enable_log_file_validation": trail.get("LogFileValidationEnabled", False),
                        "kms_key_id": trail.get("KmsKeyId"),
                        "cloud_watch_logs_group_arn": trail.get("CloudWatchLogsLogGroupArn"),
                        "enable_logging": status.get("IsLogging", False),
                        "management_events": management,
                        "read_write_type": read_write,
                    },
                )
            )
        return resources

    def collect_lambda(self, region) -> list:
        client = self.client("lambda", region)
        resources = []
        for page in client.get_paginator("list_functions").paginate():
            for function in page["Functions"]:
                name = function["FunctionName"]
                try:
                    policy = client.get_policy(FunctionName=name)["Policy"]
                except ClientError as exc:
                    if error_code(exc) != "ResourceNotFoundException":
                        raise
                    policy = None
                resources.append(
                    Resource(
                        type="aws_lambda_function",
                        id=name,
                        region=region,
                        name=name,
                        arn=function["FunctionArn"],
                        attrs={
                            "function_name": name,
                            "runtime": function.get("Runtime"),
                            "role": function.get("Role"),
                            "package_type": function.get("PackageType", "Zip"),
                            "policy": policy,
                        },
                    )
                )
                for url in self.function_urls(client, name):
                    resources.append(
                        Resource(
                            type="aws_lambda_function_url",
                            id=f"{name}/url",
                            region=region,
                            name=name,
                            arn=f"{function['FunctionArn']}/url",
                            attrs={
                                "function_name": name,
                                "authorization_type": url.get("AuthType"),
                                "function_url": url.get("FunctionUrl"),
                            },
                        )
                    )
        return resources

    def function_urls(self, client, name: str) -> list:
        try:
            return client.list_function_url_configs(FunctionName=name).get("FunctionUrlConfigs", [])
        except ClientError as exc:
            if error_code(exc) == "ResourceNotFoundException":
                return []
        try:
            return [client.get_function_url_config(FunctionName=name)]
        except ClientError as exc:
            if error_code(exc) != "ResourceNotFoundException":
                raise
            return []

    def collect_config(self, region) -> list:
        config = self.client("config", region)
        recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
        statuses = {
            s["name"]: s
            for s in config.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        }
        if not recorders:
            attrs = {"exists": False, "recording": False}
        else:
            recorder = recorders[0]
            attrs = {
                "exists": True,
                "name": recorder.get("name"),
                "recording": statuses.get(recorder.get("name"), {}).get("recording", False),
                "all_supported": recorder.get("recordingGroup", {}).get("allSupported"),
                "include_global_resource_types": recorder.get("recordingGroup", {}).get("includeGlobalResourceTypes"),
            }
        return [
            Resource(
                type="aws_config_configuration_recorder",
                id=region,
                region=region,
                name=f"config recorder {region}",
                attrs=attrs,
            )
        ]
