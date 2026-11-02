import json

from conftest import resource, verdict

from parapet.model import UNKNOWN
from parapet.rules import s3

ALL_ON = {
    "block_public_acls": True,
    "block_public_policy": True,
    "ignore_public_acls": True,
    "restrict_public_buckets": True,
}


def bucket(**attrs):
    base = {
        "bucket": "b",
        "public_access_block": dict(ALL_ON),
        "versioning": {"enabled": True, "mfa_delete": True},
        "encryption": {"sse_algorithm": "aws:kms", "kms_key_id": "k"},
        "logging": {"target_bucket": "logs"},
        "policy": None,
        "acl": {"canned": None, "grants": []},
    }
    base.update(attrs)
    return resource("aws_s3_bucket", "b", **base)


def test_public_access_block_variants():
    assert verdict(s3.BucketPublicAccessBlock, bucket())[0] is True
    ok, message = verdict(s3.BucketPublicAccessBlock, bucket(public_access_block=None))
    assert ok is False and "no public access block" in message
    partial = dict(ALL_ON, restrict_public_buckets=False)
    assert "restrict_public_buckets" in verdict(s3.BucketPublicAccessBlock, bucket(public_access_block=partial))[1]
    assert verdict(s3.BucketPublicAccessBlock, bucket(public_access_block=UNKNOWN)) is None
    unknown_key = dict(ALL_ON, block_public_acls=UNKNOWN)
    assert verdict(s3.BucketPublicAccessBlock, bucket(public_access_block=unknown_key))[0] is True


def test_public_policy_rule():
    public = json.dumps(
        {"Statement": [{"Sid": "Pub", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]}
    )
    assert verdict(s3.BucketPolicyPublic, bucket(policy=public))[1] == "bucket policy allows any principal in Pub"
    assert verdict(s3.BucketPolicyPublic, bucket())[0] is True
    assert verdict(s3.BucketPolicyPublic, bucket(policy=UNKNOWN)) is None


def test_insecure_transport_rule():
    deny = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ]
        }
    )
    assert verdict(s3.BucketPolicyInsecureTransport, bucket(policy=deny))[0] is True
    assert "no policy" in verdict(s3.BucketPolicyInsecureTransport, bucket())[1]
    other = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::1:root"},
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ]
        }
    )
    assert "no deny statement" in verdict(s3.BucketPolicyInsecureTransport, bucket(policy=other))[1]


def test_versioning_and_mfa_delete():
    assert verdict(s3.BucketVersioning, bucket())[0] is True
    assert verdict(s3.BucketVersioning, bucket(versioning={"enabled": False, "mfa_delete": False}))[0] is False
    assert verdict(s3.BucketVersioning, bucket(versioning={"enabled": UNKNOWN, "mfa_delete": UNKNOWN})) is None
    assert verdict(s3.BucketMfaDelete, bucket())[0] is True
    assert verdict(s3.BucketMfaDelete, bucket(versioning={"enabled": True, "mfa_delete": False}))[0] is False
    assert verdict(s3.BucketMfaDelete, bucket(versioning={"enabled": True, "mfa_delete": UNKNOWN})) is None


def test_kms_encryption_skips_log_targets():
    assert verdict(s3.BucketKmsEncryption, bucket())[0] is True
    assert "SSE-S3" in verdict(s3.BucketKmsEncryption, bucket(encryption=None))[1]
    assert (
        "AES256"
        in verdict(s3.BucketKmsEncryption, bucket(encryption={"sse_algorithm": "AES256", "kms_key_id": None}))[1]
    )
    logs = resource("aws_s3_bucket", "logs", bucket="logs", encryption=None, logging=None)
    data = bucket()
    assert verdict(s3.BucketKmsEncryption, logs, extra=(data,)) is None
    assert verdict(s3.BucketAccessLogging, logs, extra=(data,)) is None
    assert verdict(s3.BucketAccessLogging, bucket(logging=None))[0] is False
    assert verdict(s3.BucketAccessLogging, bucket(logging={"target_bucket": UNKNOWN}))[0] is True


def test_acl_rule():
    assert verdict(s3.BucketAclPublic, bucket())[0] is True
    assert "public-read" in verdict(s3.BucketAclPublic, bucket(acl={"canned": "public-read", "grants": []}))[1]
    grants = [{"type": "Group", "uri": "http://acs.amazonaws.com/groups/global/AllUsers", "permission": "READ"}]
    assert "AllUsers" in verdict(s3.BucketAclPublic, bucket(acl={"canned": None, "grants": grants}))[1]
    owner = [{"type": "CanonicalUser", "uri": None, "permission": "FULL_CONTROL"}]
    assert verdict(s3.BucketAclPublic, bucket(acl={"canned": None, "grants": owner}))[0] is True
    assert verdict(s3.BucketAclPublic, bucket(acl=UNKNOWN)) is None


def test_account_public_access_block():
    assert (
        verdict(s3.AccountPublicAccessBlock, resource("aws_s3_account_public_access_block", "acct", **ALL_ON))[0]
        is True
    )
    assert (
        "no account level"
        in verdict(s3.AccountPublicAccessBlock, resource("aws_s3_account_public_access_block", "acct", exists=False))[1]
    )
    partial = dict(ALL_ON, ignore_public_acls=False)
    assert (
        "ignore_public_acls"
        in verdict(s3.AccountPublicAccessBlock, resource("aws_s3_account_public_access_block", "acct", **partial))[1]
    )
