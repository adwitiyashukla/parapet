import json

import pytest

from parapet.model import is_unknown
from parapet.sources import SourceError
from parapet.sources.terraform import build_inventory, load_plan


def test_insecure_plan_inventory(insecure_plan):
    inventory = load_plan(str(insecure_plan))
    assert inventory.source == "terraform"
    assert inventory.regions == ["us-east-1"]
    assert len(inventory.resources) == 20
    types = {r.type for r in inventory.resources}
    assert "aws_s3_bucket_public_access_block" not in types
    assert "aws_vpc_security_group_ingress_rule" not in types
    assert "aws_lambda_permission" not in types
    assert "aws_iam_user_policy" not in types
    assert "aws_s3_bucket_ownership_controls" in types


def test_bucket_children_are_folded(insecure_plan):
    bucket = load_plan(str(insecure_plan)).find("aws_s3_bucket", "aws_s3_bucket.data")
    assert bucket.name == "parapet-demo-data"
    assert bucket.region == "us-east-1"
    assert bucket.attrs["public_access_block"] == {
        "block_public_acls": False,
        "block_public_policy": False,
        "ignore_public_acls": False,
        "restrict_public_buckets": False,
    }
    assert bucket.attrs["versioning"]["enabled"] is False
    assert is_unknown(bucket.attrs["versioning"]["mfa_delete"])
    assert bucket.attrs["acl"]["canned"] == "public-read"
    assert "PublicRead" in bucket.attrs["policy"]
    assert bucket.attrs["logging"] is None
    assert bucket.attrs["encryption"] is None


def test_security_group_rules_are_merged(insecure_plan):
    group = load_plan(str(insecure_plan)).find("aws_security_group", "aws_security_group.web")
    ports = sorted((r["from_port"], r["to_port"], r["protocol"]) for r in group.attrs["ingress"])
    assert ports == [(0, 0, "-1"), (22, 22, "tcp"), (3389, 3389, "tcp"), (5432, 5432, "tcp")]
    merged = [r for r in group.attrs["ingress"] if r["from_port"] == 5432][0]
    assert merged["cidr_blocks"] == ["0.0.0.0/0"]
    assert merged["security_groups"] == []


def test_iam_and_lambda_children_are_folded(insecure_plan):
    inventory = load_plan(str(insecure_plan))
    user = inventory.find("aws_iam_user", "aws_iam_user.deploy")
    assert [p["name"] for p in user.attrs["inline_policies"]] == ["deploy-admin"]
    assert user.attrs["attached_policy_arns"] == ["aws_iam_policy.ops"]
    assert user.region == "global"
    function = inventory.find("aws_lambda_function", "aws_lambda_function.api")
    statement = function.attrs["policy"]["Statement"][0]
    assert statement["Principal"] == "*"
    assert "Condition" not in statement


def test_hardened_plan_resolves_references(hardened_plan):
    inventory = load_plan(str(hardened_plan))
    assert len(inventory.resources) == 29
    vpc = inventory.find("aws_vpc", "aws_vpc.main")
    assert vpc.attrs["flow_logs"] == [{"traffic_type": "ALL", "log_destination_type": "cloud-watch-logs"}]
    data = inventory.find("aws_s3_bucket", "aws_s3_bucket.data")
    assert data.attrs["logging"] == {"target_bucket": "parapet-demo-logs", "target_prefix": "data/"}
    assert data.attrs["encryption"]["sse_algorithm"] == "aws:kms"
    assert is_unknown(data.attrs["encryption"]["kms_key_id"])
    role = inventory.find("aws_iam_role", "aws_iam_role.app")
    assert [p["name"] for p in role.attrs["inline_policies"]] == ["app-data"]
    db_group = inventory.find("aws_security_group", "aws_security_group.db")
    assert db_group.attrs["ingress"][0]["security_groups"] == ["referenced"]
    assert db_group.attrs["ingress"][0]["cidr_blocks"] == []
    default_group = inventory.find("aws_default_security_group", "aws_default_security_group.main")
    assert default_group.attrs["ingress"] == []
    function = inventory.find("aws_lambda_function", "aws_lambda_function.api")
    assert function.attrs["policy"]["Statement"][0]["Condition"]["ArnLike"]["AWS:SourceArn"].startswith(
        "arn:aws:execute-api"
    )
    trail = inventory.find("aws_cloudtrail", "aws_cloudtrail.main")
    assert is_unknown(trail.attrs["kms_key_id"])


def plan_with(resources, configuration_resources, module_calls=None, provider_region="eu-west-1"):
    return {
        "format_version": "1.2",
        "resource_changes": resources,
        "configuration": {
            "provider_config": {"aws": {"name": "aws", "expressions": {"region": {"constant_value": provider_region}}}},
            "root_module": {"resources": configuration_resources, "module_calls": module_calls or {}},
        },
    }


def change(address, rtype, after, unknown=None, actions=("create",), module_address=None):
    entry = {
        "address": address,
        "mode": "managed",
        "type": rtype,
        "name": address.split(".")[-1],
        "change": {"actions": list(actions), "after": after, "after_unknown": unknown or {}},
    }
    if module_address:
        entry["module_address"] = module_address
    return entry


def test_module_references_and_indexed_resources():
    resources = [
        change("module.store.aws_s3_bucket.logs[0]", "aws_s3_bucket", {"bucket": "logs-a"}, {"id": True}),
        change("module.store.aws_s3_bucket.logs[1]", "aws_s3_bucket", {"bucket": "logs-b"}, {"id": True}),
        change(
            "module.store.aws_s3_bucket_versioning.logs[0]",
            "aws_s3_bucket_versioning",
            {"versioning_configuration": [{"status": "Enabled"}]},
            {"bucket": True},
        ),
        change("aws_s3_bucket.old", "aws_s3_bucket", None, None, actions=("delete",)),
    ]
    module = {
        "store": {
            "module": {
                "resources": [
                    {"address": "aws_s3_bucket.logs", "mode": "managed", "expressions": {}},
                    {
                        "address": "aws_s3_bucket_versioning.logs",
                        "mode": "managed",
                        "expressions": {
                            "bucket": {
                                "references": [
                                    "aws_s3_bucket.logs[count.index].id",
                                    "aws_s3_bucket.logs",
                                    "count.index",
                                ]
                            }
                        },
                    },
                ]
            }
        }
    }
    inventory = build_inventory(plan_with(resources, [], module), "plan.json")
    assert [r.address for r in inventory.resources] == [
        "module.store.aws_s3_bucket.logs[0]",
        "module.store.aws_s3_bucket.logs[1]",
    ]
    assert all(r.attrs["versioning"]["enabled"] is True for r in inventory.resources)
    assert inventory.resources[0].region == "eu-west-1"


def test_unfolded_child_stays_in_inventory_and_provider_region_fallback():
    resources = [
        change("aws_s3_bucket_policy.orphan", "aws_s3_bucket_policy", {"policy": "{}"}, {"bucket": True}),
        change("aws_iam_user.bob", "aws_iam_user", {"name": "bob"}),
        change("aws_kms_key.k", "aws_kms_key", {"enable_key_rotation": True, "region": "ap-south-1"}),
    ]
    inventory = build_inventory(
        plan_with(
            resources,
            [{"address": "aws_s3_bucket_policy.orphan", "expressions": {"bucket": {"constant_value": "ghost"}}}],
        ),
        "p",
    )
    types = sorted(r.type for r in inventory.resources)
    assert types == ["aws_iam_user", "aws_kms_key", "aws_s3_bucket_policy"]
    assert inventory.find("aws_iam_user", "aws_iam_user.bob").region == "global"
    assert inventory.find("aws_kms_key", "aws_kms_key.k").region == "ap-south-1"
    assert inventory.find("aws_s3_bucket_policy", "aws_s3_bucket_policy.orphan").region == "eu-west-1"
    assert inventory.regions == ["ap-south-1", "eu-west-1"]


def test_legacy_inline_bucket_blocks_are_normalized():
    after = {
        "bucket": "legacy",
        "versioning": [{"enabled": True, "mfa_delete": False}],
        "logging": [{"target_bucket": "logs", "target_prefix": ""}],
        "server_side_encryption_configuration": [
            {
                "rule": [
                    {
                        "apply_server_side_encryption_by_default": [
                            {"sse_algorithm": "aws:kms", "kms_master_key_id": "k"}
                        ],
                        "bucket_key_enabled": False,
                    }
                ]
            }
        ],
        "acl": "private",
        "policy": None,
    }
    inventory = build_inventory(plan_with([change("aws_s3_bucket.legacy", "aws_s3_bucket", after)], []), "p")
    bucket = inventory.resources[0]
    assert bucket.attrs["versioning"] == {"enabled": True, "mfa_delete": False}
    assert bucket.attrs["logging"]["target_bucket"] == "logs"
    assert bucket.attrs["encryption"]["sse_algorithm"] == "aws:kms"
    assert bucket.attrs["acl"] == {"canned": "private", "grants": []}
    assert bucket.attrs["policy"] is None
    assert bucket.attrs["public_access_block"] is None


def test_errors_for_missing_or_invalid_plan(tmp_path):
    with pytest.raises(SourceError):
        load_plan(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    with pytest.raises(SourceError):
        load_plan(bad)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"values": {}}), encoding="utf-8")
    with pytest.raises(SourceError) as info:
        load_plan(state)
    assert "terraform show -json" in str(info.value)
