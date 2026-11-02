from datetime import date, datetime, timezone

from conftest import make_inventory, resource

from parapet.config import Config, Suppression
from parapet.engine import run_rules
from parapet.model import Severity
from parapet.rules import ALL_RULES, build_rules, rule_ids
from parapet.sources.terraform import load_plan

EXPECTED_INSECURE = {
    "S3-001",
    "S3-002",
    "S3-003",
    "S3-004",
    "S3-005",
    "S3-006",
    "S3-007",
    "S3-009",
    "IAM-003",
    "IAM-004",
    "IAM-009",
    "IAM-010",
    "IAM-011",
    "IAM-012",
    "EC2-001",
    "EC2-002",
    "EC2-003",
    "EC2-005",
    "EC2-006",
    "EC2-007",
    "EC2-008",
    "EC2-009",
    "EC2-010",
    "EC2-011",
    "CT-002",
    "CT-003",
    "CT-004",
    "KMS-001",
    "RDS-001",
    "RDS-002",
    "RDS-003",
    "RDS-004",
    "RDS-005",
    "LAMBDA-001",
    "LAMBDA-002",
    "LAMBDA-003",
}


def test_rule_ids_are_unique_and_complete():
    ids = rule_ids()
    assert len(ids) == len(set(ids)) == 47
    for rule in ALL_RULES:
        assert rule.title and rule.remediation and rule.resource_types
        assert set(rule.sources) <= {"aws", "terraform"}
    assert len(build_rules(disabled=["S3-001", "KMS-001"])) == 45


def test_insecure_plan_findings(insecure_plan):
    result = run_rules(load_plan(str(insecure_plan)), Config())
    assert {f.rule_id for f in result.active} == EXPECTED_INSECURE
    assert len(result.active) == 36
    assert result.passed == 7
    assert result.counts() == {"critical": 6, "high": 8, "medium": 13, "low": 9, "info": 0}
    assert result.score == 16.3
    assert result.worst() is Severity.CRITICAL
    assert result.source == "terraform"
    assert result.resource_count == 20
    assert result.rule_count == 47
    assert [f.severity for f in result.findings] == sorted((f.severity for f in result.findings), reverse=True)


def test_hardened_plan_is_clean(hardened_plan):
    result = run_rules(load_plan(str(hardened_plan)), Config())
    assert result.active == []
    assert result.passed == 65
    assert result.score == 100.0


def test_terraform_only_and_aws_only_rules_follow_the_source():
    account = resource("aws_account", "1", root_mfa_enabled=False, root_access_keys=1)
    instance = resource("aws_instance", "i", root_block_device=[{"encrypted": False}])
    from_plan = run_rules(make_inventory("terraform", account, instance), Config())
    assert {f.rule_id for f in from_plan.active} == {"EC2-011", "EC2-009"}
    from_account = run_rules(make_inventory("aws", account, instance), Config())
    assert {f.rule_id for f in from_account.active} == {"IAM-001", "IAM-002", "EC2-009", "CT-001"}


def test_suppressions_match_by_pattern_and_expire(insecure_plan):
    config = Config()
    config.suppressions = [
        Suppression("S3-*", "parapet-demo-*", "demo buckets", date(2030, 1, 1)),
        Suppression("EC2-002", "aws_security_group.web", "known", None),
        Suppression("RDS-001", "app-db", "expired one", date(2020, 1, 1)),
    ]
    result = run_rules(load_plan(str(insecure_plan)), config, now=datetime(2026, 11, 1, tzinfo=timezone.utc))
    suppressed = {f.rule_id for f in result.suppressed}
    assert suppressed == {"EC2-002"}
    assert "RDS-001" in {f.rule_id for f in result.active}
    assert len(result.warnings) == 1
    assert "expired on 2020-01-01" in result.warnings[0]
    assert result.suppressed[0].suppressed_by == "EC2-002 on aws_security_group.web: known"


def test_wildcard_rule_suppression_and_disabled_rules(insecure_plan):
    config = Config()
    config.suppressions = [Suppression("*", "parapet-demo-data", "demo bucket", None)]
    config.disabled_rules = ["EC2-001", "EC2-002", "EC2-003"]
    result = run_rules(load_plan(str(insecure_plan)), config)
    assert {f.rule_id for f in result.suppressed} == {
        "S3-001",
        "S3-002",
        "S3-003",
        "S3-004",
        "S3-005",
        "S3-006",
        "S3-007",
    }
    assert not {"EC2-001", "EC2-002", "EC2-003"} & {f.rule_id for f in result.findings}
    assert result.rule_count == 44
    assert result.passed == 4
    assert result.score == round(100 * result.passed / (result.passed + len(result.active)), 1)


def test_settings_change_verdicts(insecure_plan):
    config = Config()
    config.settings["password_min_length"] = 8
    config.settings["password_reuse_prevention"] = 3
    config.settings["backup_retention_min_days"] = 0
    config.settings["deprecated_lambda_runtimes"] = []
    result = run_rules(load_plan(str(insecure_plan)), config)
    ids = {f.rule_id for f in result.active}
    assert not {"IAM-003", "IAM-004", "RDS-003", "LAMBDA-003"} & ids
    assert len(result.active) == 32
