from conftest import make_inventory, resource, verdict

from parapet.model import UNKNOWN
from parapet.rules import awsconfig, cloudtrail, kms, lambda_, rds


def trail(**attrs):
    base = {
        "name": "t",
        "is_multi_region_trail": True,
        "enable_log_file_validation": True,
        "kms_key_id": "arn:aws:kms:us-east-1:1:key/k",
        "cloud_watch_logs_group_arn": "arn:aws:logs:us-east-1:1:log-group:g:*",
        "enable_logging": True,
        "management_events": True,
        "read_write_type": "All",
    }
    base.update(attrs)
    return resource("aws_cloudtrail", "t", **base)


def test_multi_region_trail_rule_is_inventory_wide():
    account = resource("aws_account", "1")
    rule = cloudtrail.MultiRegionTrail()
    assert rule.evaluate(make_inventory("aws", account, trail()))[0].ok is True
    outcomes = rule.evaluate(make_inventory("aws", account, trail(is_multi_region_trail=False)))
    assert outcomes[0].ok is False and "none is multi-region" in outcomes[0].message
    assert "no CloudTrail trail" in rule.evaluate(make_inventory("aws", account))[0].message
    assert rule.evaluate(make_inventory("aws", trail())) == []
    assert rule.evaluate(make_inventory("aws", account, trail(read_write_type="WriteOnly")))[0].ok is False
    assert rule.evaluate(make_inventory("aws", account, trail(enable_logging=False)))[0].ok is False


def test_trail_resource_rules():
    assert verdict(cloudtrail.TrailLogFileValidation, trail())[0] is True
    assert verdict(cloudtrail.TrailLogFileValidation, trail(enable_log_file_validation=False))[0] is False
    assert verdict(cloudtrail.TrailKmsEncryption, trail(kms_key_id=None))[0] is False
    assert verdict(cloudtrail.TrailKmsEncryption, trail(kms_key_id=UNKNOWN))[0] is True
    assert verdict(cloudtrail.TrailCloudWatchLogs, trail(cloud_watch_logs_group_arn=None))[0] is False
    assert verdict(cloudtrail.TrailCloudWatchLogs, trail(cloud_watch_logs_group_arn=UNKNOWN))[0] is True
    assert verdict(cloudtrail.TrailLogging, trail(enable_logging=False), "aws")[0] is False
    assert verdict(cloudtrail.TrailLogging, trail(enable_logging=None), "aws") is None


def test_kms_rotation_rule():
    assert verdict(kms.KeyRotation, resource("aws_kms_key", "k", enable_key_rotation=False))[0] is False
    assert verdict(kms.KeyRotation, resource("aws_kms_key", "k", enable_key_rotation=True))[0] is True
    asymmetric = resource(
        "aws_kms_key", "k", enable_key_rotation=False, customer_master_key_spec="RSA_2048", key_usage="SIGN_VERIFY"
    )
    assert verdict(kms.KeyRotation, asymmetric) is None
    assert verdict(kms.KeyRotation, resource("aws_kms_key", "k", enable_key_rotation=UNKNOWN)) is None


def db(**attrs):
    base = {
        "publicly_accessible": False,
        "storage_encrypted": True,
        "backup_retention_period": 7,
        "deletion_protection": True,
        "auto_minor_version_upgrade": True,
    }
    base.update(attrs)
    return resource("aws_db_instance", "db", **base)


def test_rds_rules():
    assert verdict(rds.PubliclyAccessible, db())[0] is True
    assert verdict(rds.PubliclyAccessible, db(publicly_accessible=True))[0] is False
    assert verdict(rds.StorageEncrypted, db(storage_encrypted=False))[0] is False
    assert verdict(rds.StorageEncrypted, db(storage_encrypted=UNKNOWN)) is None
    assert "kept for 0 days" in verdict(rds.BackupRetention, db(backup_retention_period=0))[1]
    assert verdict(rds.BackupRetention, db(backup_retention_period=None))[0] is False
    assert (
        verdict(rds.BackupRetention, db(backup_retention_period=3), settings={"backup_retention_min_days": 3})[0]
        is True
    )
    assert verdict(rds.DeletionProtection, db(deletion_protection=False))[0] is False
    assert verdict(rds.AutoMinorVersionUpgrade, db(auto_minor_version_upgrade=False))[0] is False
    assert verdict(rds.AutoMinorVersionUpgrade, db(auto_minor_version_upgrade=None))[0] is True


def test_lambda_rules():
    public = {
        "Statement": [
            {"Sid": "pub", "Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction", "Resource": "*"}
        ]
    }
    assert "pub" in verdict(lambda_.PublicInvokePolicy, resource("aws_lambda_function", "f", policy=public))[1]
    scoped = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "lambda:InvokeFunction",
                "Resource": "*",
                "Condition": {"ArnLike": {"AWS:SourceArn": "arn:aws:s3:::b"}},
            }
        ]
    }
    assert verdict(lambda_.PublicInvokePolicy, resource("aws_lambda_function", "f", policy=scoped))[0] is True
    assert verdict(lambda_.PublicInvokePolicy, resource("aws_lambda_function", "f", policy=None))[0] is True
    assert (
        verdict(lambda_.FunctionUrlWithoutAuth, resource("aws_lambda_function_url", "u", authorization_type="NONE"))[0]
        is False
    )
    assert (
        verdict(lambda_.FunctionUrlWithoutAuth, resource("aws_lambda_function_url", "u", authorization_type="AWS_IAM"))[
            0
        ]
        is True
    )
    assert (
        "python3.8" in verdict(lambda_.DeprecatedRuntime, resource("aws_lambda_function", "f", runtime="python3.8"))[1]
    )
    assert verdict(lambda_.DeprecatedRuntime, resource("aws_lambda_function", "f", runtime="python3.12"))[0] is True
    assert verdict(lambda_.DeprecatedRuntime, resource("aws_lambda_function", "f", runtime=None)) is None
    custom = verdict(
        lambda_.DeprecatedRuntime,
        resource("aws_lambda_function", "f", runtime="python3.12"),
        settings={"deprecated_lambda_runtimes": ["python3.12"]},
    )
    assert custom[0] is False


def test_config_recorder_rule():
    assert (
        "no configuration recorder"
        in verdict(
            awsconfig.ConfigRecorder, resource("aws_config_configuration_recorder", "us-east-1", exists=False), "aws"
        )[1]
    )
    stopped = resource(
        "aws_config_configuration_recorder", "us-east-1", exists=True, recording=False, all_supported=True
    )
    assert "stopped" in verdict(awsconfig.ConfigRecorder, stopped, "aws")[1]
    partial = resource(
        "aws_config_configuration_recorder", "us-east-1", exists=True, recording=True, all_supported=False
    )
    assert "all supported" in verdict(awsconfig.ConfigRecorder, partial, "aws")[1]
    good = resource("aws_config_configuration_recorder", "us-east-1", exists=True, recording=True, all_supported=True)
    assert verdict(awsconfig.ConfigRecorder, good, "aws")[0] is True
