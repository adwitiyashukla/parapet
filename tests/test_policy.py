import json

from parapet.model import UNKNOWN, is_unknown
from parapet.rules import policy


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def test_load_policy_accepts_json_strings_dicts_and_unknown():
    assert policy.load_policy(json.dumps(doc())) == doc()
    assert policy.load_policy(doc()) == doc()
    assert policy.load_policy(None) is None
    assert policy.load_policy("{not json") is None
    assert policy.load_policy("[]") is None
    assert is_unknown(policy.load_policy(UNKNOWN))


def test_statements_normalize_scalars_and_single_statement_dict():
    document = {"Statement": {"Sid": "One", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}
    parsed = policy.statements(document)
    assert parsed[0]["label"] == "One"
    assert parsed[0]["action"] == ["s3:GetObject"]
    assert parsed[0]["resource"] == ["*"]
    unnamed = policy.statements(doc({"Effect": "Deny"}))
    assert unnamed[0]["label"] == "statement 1"


def test_full_admin_detection():
    assert policy.allows_full_admin(doc({"Effect": "Allow", "Action": "*", "Resource": "*"})) == ["statement 1"]
    assert policy.allows_full_admin(doc({"Sid": "A", "Effect": "Allow", "Action": ["*:*"], "Resource": ["*"]})) == ["A"]
    assert policy.allows_full_admin(doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})) == ["statement 1"]
    assert policy.allows_full_admin(doc({"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b/*"})) == []
    assert policy.allows_full_admin(doc({"Effect": "Deny", "Action": "*", "Resource": "*"})) == []
    conditional = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*",
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
    }
    assert policy.allows_full_admin(doc(conditional)) == []


def test_service_wildcards():
    document = doc({"Effect": "Allow", "Action": ["s3:*", "ec2:Describe*", "iam:PassRole", "*"], "Resource": "*"})
    assert policy.service_wildcards(document) == ["s3:*"]
    assert policy.service_wildcards(doc({"Effect": "Deny", "Action": "s3:*", "Resource": "*"})) == []


def test_public_statements_respect_restricting_conditions():
    public = {"Sid": "Open", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}
    aws_star = {"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": "s3:GetObject", "Resource": "*"}
    scoped = dict(public, Condition={"StringEquals": {"aws:PrincipalOrgID": "o-123"}})
    vpce = dict(public, Condition={"StringEquals": {"aws:SourceVpce": "vpce-1"}})
    weak = dict(public, Sid="Weak", Condition={"Bool": {"aws:SecureTransport": "true"}})
    service = {
        "Effect": "Allow",
        "Principal": {"Service": "cloudtrail.amazonaws.com"},
        "Action": "s3:PutObject",
        "Resource": "*",
    }
    assert policy.public_statements(doc(public, aws_star, scoped, vpce, weak, service)) == [
        "Open",
        "statement 2",
        "Weak",
    ]


def test_denies_insecure_transport_variants():
    deny = {
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": "*",
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }
    assert policy.denies_insecure_transport(doc(deny))
    as_bool = dict(deny, Condition={"Bool": {"aws:SecureTransport": False}})
    assert policy.denies_insecure_transport(doc(as_bool))
    as_list = dict(deny, Condition={"BoolIfExists": {"aws:securetransport": ["false"]}})
    assert policy.denies_insecure_transport(doc(as_list))
    wrong_value = dict(deny, Condition={"Bool": {"aws:SecureTransport": "true"}})
    assert not policy.denies_insecure_transport(doc(wrong_value))
    allow = dict(deny, Effect="Allow")
    assert not policy.denies_insecure_transport(doc(allow))


def test_trust_policy_checks():
    open_trust = {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}
    org_trust = dict(open_trust, Condition={"StringEquals": {"aws:PrincipalOrgID": "o-1"}})
    service_trust = {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
    assert policy.trust_allows_any_principal(doc(open_trust)) == ["statement 1"]
    assert policy.trust_allows_any_principal(doc(org_trust, service_trust)) == []
