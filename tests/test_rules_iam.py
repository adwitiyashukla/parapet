import json
from datetime import datetime, timezone

from conftest import resource, verdict

from parapet.model import UNKNOWN
from parapet.rules import iam

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
SCOPED = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}],
}


def user(**attrs):
    base = {
        "name": "u",
        "password_enabled": True,
        "password_last_used": "2026-10-20T00:00:00+00:00",
        "mfa_active": True,
        "created": "2025-01-01T00:00:00+00:00",
        "access_keys": [
            {"active": True, "last_rotated": "2026-10-01T00:00:00+00:00", "last_used": "2026-10-30T00:00:00+00:00"}
        ],
        "inline_policies": [],
        "attached_policy_arns": [],
    }
    base.update(attrs)
    return resource("aws_iam_user", "u", **base)


def test_root_rules():
    account = resource("aws_account", "1", root_mfa_enabled=False, root_access_keys=2)
    assert "2 access key" in verdict(iam.RootAccessKeys, account, "aws")[1]
    assert verdict(iam.RootMfa, account, "aws")[0] is False
    good = resource("aws_account", "1", root_mfa_enabled=True, root_access_keys=0)
    assert verdict(iam.RootAccessKeys, good, "aws")[0] is True
    assert verdict(iam.RootMfa, good, "aws")[0] is True
    assert verdict(iam.RootMfa, resource("aws_account", "1"), "aws") is None


def test_password_policy_rules():
    weak = resource(
        "aws_iam_account_password_policy", "1", exists=True, minimum_password_length=8, password_reuse_prevention=3
    )
    assert "is 8" in verdict(iam.PasswordLength, weak)[1]
    assert "only 3" in verdict(iam.PasswordReuse, weak)[1]
    missing = resource("aws_iam_account_password_policy", "1", exists=False)
    assert "no custom password policy" in verdict(iam.PasswordLength, missing)[1]
    assert verdict(iam.PasswordReuse, missing)[0] is False
    strong = resource("aws_iam_account_password_policy", "1", minimum_password_length=14, password_reuse_prevention=24)
    assert verdict(iam.PasswordLength, strong)[0] is True
    assert verdict(iam.PasswordReuse, strong)[0] is True
    custom = verdict(iam.PasswordLength, strong, settings={"password_min_length": 16})
    assert custom[0] is False
    assert (
        verdict(iam.PasswordLength, resource("aws_iam_account_password_policy", "1", minimum_password_length=UNKNOWN))
        is None
    )


def test_console_mfa_rule():
    assert verdict(iam.ConsoleUserWithoutMfa, user(), "aws")[0] is True
    assert verdict(iam.ConsoleUserWithoutMfa, user(mfa_active=False), "aws")[0] is False
    assert verdict(iam.ConsoleUserWithoutMfa, user(password_enabled=False, mfa_active=False), "aws")[0] is True
    assert verdict(iam.ConsoleUserWithoutMfa, resource("aws_iam_user", "tf", name="tf"), "aws") is None


def test_key_rotation_rule():
    assert verdict(iam.AccessKeyRotation, user(), "aws", now=NOW)[0] is True
    old = user(
        access_keys=[
            {"active": True, "last_rotated": "2026-01-01T00:00:00+00:00", "last_used": "2026-10-30T00:00:00+00:00"}
        ]
    )
    ok, message = verdict(iam.AccessKeyRotation, old, "aws", now=NOW)
    assert ok is False and "304 days" in message
    inactive = user(access_keys=[{"active": False, "last_rotated": "2020-01-01T00:00:00+00:00", "last_used": "N/A"}])
    assert verdict(iam.AccessKeyRotation, inactive, "aws", now=NOW)[0] is True
    assert verdict(iam.AccessKeyRotation, resource("aws_iam_user", "tf", name="tf"), "aws") is None


def test_unused_credentials_rule():
    assert verdict(iam.UnusedCredentials, user(), "aws", now=NOW)[0] is True
    stale_password = user(password_last_used="2026-01-01T00:00:00+00:00")
    assert "password unused for 304 days" in verdict(iam.UnusedCredentials, stale_password, "aws", now=NOW)[1]
    never_used = user(password_last_used="no_information", created="2026-01-01T00:00:00+00:00")
    assert verdict(iam.UnusedCredentials, never_used, "aws", now=NOW)[0] is False
    stale_key = user(
        access_keys=[
            {"active": True, "last_rotated": "2026-10-01T00:00:00+00:00", "last_used": "2026-05-01T00:00:00+00:00"}
        ]
    )
    assert "access key unused for 184 days" in verdict(iam.UnusedCredentials, stale_key, "aws", now=NOW)[1]
    key_never_used = user(
        access_keys=[{"active": True, "last_rotated": "2026-01-01T00:00:00+00:00", "last_used": "N/A"}]
    )
    assert verdict(iam.UnusedCredentials, key_never_used, "aws", now=NOW)[0] is False


def test_multiple_keys_and_direct_policies():
    two = user(access_keys=[{"active": True, "last_rotated": "2026-10-01T00:00:00+00:00", "last_used": "N/A"}] * 2)
    assert "2 active access keys" in verdict(iam.MultipleAccessKeys, two, "aws")[1]
    assert verdict(iam.MultipleAccessKeys, user(), "aws")[0] is True
    assert verdict(iam.UserDirectPolicies, user())[0] is True
    direct = user(
        inline_policies=[{"name": "x", "policy": SCOPED}],
        attached_policy_arns=["arn:aws:iam::aws:policy/ReadOnlyAccess"],
    )
    assert "1 inline and 1 attached" in verdict(iam.UserDirectPolicies, direct)[1]


def test_full_admin_and_service_wildcards():
    managed = resource("aws_iam_policy", "p", name="p", policy=json.dumps(ADMIN))
    assert "Action * on Resource *" in verdict(iam.FullAdminPolicy, managed)[1]
    assert verdict(iam.FullAdminPolicy, resource("aws_iam_policy", "p", name="p", policy=json.dumps(SCOPED)))[0] is True
    inline_user = user(inline_policies=[{"name": "admin", "policy": ADMIN}])
    assert "admin (statement 1)" in verdict(iam.FullAdminPolicy, inline_user)[1]
    assert verdict(iam.FullAdminPolicy, user()) is None
    assert verdict(iam.FullAdminPolicy, resource("aws_iam_policy", "p", name="p", policy=UNKNOWN))[0] is True
    wild = {"Statement": [{"Effect": "Allow", "Action": ["s3:*", "ec2:*"], "Resource": "*"}]}
    assert (
        "ec2:*, s3:*" in verdict(iam.ServiceWildcardPolicy, resource("aws_iam_policy", "p", name="p", policy=wild))[1]
    )
    assert (
        verdict(iam.ServiceWildcardPolicy, resource("aws_iam_policy", "p", name="p", policy=json.dumps(SCOPED)))[0]
        is True
    )
    assert verdict(iam.ServiceWildcardPolicy, user()) is None


def test_role_trust_rule():
    open_trust = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
    role = resource("aws_iam_role", "r", name="r", assume_role_policy=json.dumps(open_trust))
    assert verdict(iam.RoleTrustsAnyPrincipal, role)[0] is False
    service = {
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    }
    assert (
        verdict(iam.RoleTrustsAnyPrincipal, resource("aws_iam_role", "r", name="r", assume_role_policy=service))[0]
        is True
    )
    assert (
        verdict(iam.RoleTrustsAnyPrincipal, resource("aws_iam_role", "r", name="r", assume_role_policy=UNKNOWN)) is None
    )


def test_time_helpers():
    assert iam.parse_time("N/A") is None
    assert iam.parse_time("2026-01-01T00:00:00Z").tzinfo is not None
    assert iam.parse_time("2026-01-01T00:00:00").tzinfo is not None
    assert iam.parse_time("yesterday") is None
    assert iam.age_days(NOW, "2026-10-31T00:00:00+00:00") == 1
