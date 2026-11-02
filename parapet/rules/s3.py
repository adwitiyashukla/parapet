from parapet.model import Severity, is_unknown
from parapet.rules import policy
from parapet.rules.base import PASS, Rule, fail

BLOCK_KEYS = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
PUBLIC_CANNED_ACLS = ("public-read", "public-read-write", "authenticated-read")
PUBLIC_GRANTEE_URIS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def logging_targets(inventory) -> set:
    targets = set()
    for bucket in inventory.of_type("aws_s3_bucket"):
        logging = bucket.attrs.get("logging")
        if isinstance(logging, dict) and isinstance(logging.get("target_bucket"), str):
            targets.add(logging["target_bucket"])
    return targets


def bucket_name(resource) -> str:
    name = resource.attrs.get("bucket")
    return name if isinstance(name, str) else resource.address or resource.id


def missing_block_settings(block: dict) -> list:
    return [key for key in BLOCK_KEYS if block.get(key) is not True and not is_unknown(block.get(key))]


class BucketPublicAccessBlock(Rule):
    id = "S3-001"
    title = "S3 bucket does not block all public access"
    severity = Severity.HIGH
    resource_types = ("aws_s3_bucket",)
    cis = ("2.1.4",)
    fsbp = ("S3.8",)
    remediation = "Turn on all four bucket public access block settings: block_public_acls, block_public_policy, ignore_public_acls and restrict_public_buckets."

    def check(self, resource, inventory):
        block = resource.attrs.get("public_access_block")
        if is_unknown(block):
            return None
        if not isinstance(block, dict):
            return fail("bucket has no public access block configuration")
        missing = missing_block_settings(block)
        if missing:
            return fail("public access block leaves " + ", ".join(missing) + " off")
        return PASS


class BucketPolicyPublic(Rule):
    id = "S3-002"
    title = "S3 bucket policy grants access to everyone"
    severity = Severity.CRITICAL
    resource_types = ("aws_s3_bucket",)
    fsbp = ("S3.2", "S3.3")
    remediation = "Remove statements with Principal * from the bucket policy, or restrict them with a condition such as aws:SourceVpce or aws:PrincipalOrgID."

    def check(self, resource, inventory):
        document = policy.load_policy(resource.attrs.get("policy"))
        if is_unknown(document):
            return None
        if document is None:
            return PASS
        hits = policy.public_statements(document)
        if hits:
            return fail("bucket policy allows any principal in " + ", ".join(hits))
        return PASS


class BucketPolicyInsecureTransport(Rule):
    id = "S3-003"
    title = "S3 bucket policy does not deny plain HTTP requests"
    severity = Severity.MEDIUM
    resource_types = ("aws_s3_bucket",)
    cis = ("2.1.1",)
    fsbp = ("S3.5",)
    remediation = (
        "Add a Deny statement for all principals and s3:* actions with the condition Bool aws:SecureTransport = false."
    )

    def check(self, resource, inventory):
        document = policy.load_policy(resource.attrs.get("policy"))
        if is_unknown(document):
            return None
        if document is None:
            return fail("bucket has no policy, so requests over HTTP are accepted")
        if not policy.denies_insecure_transport(document):
            return fail("bucket policy has no deny statement for aws:SecureTransport = false")
        return PASS


class BucketVersioning(Rule):
    id = "S3-004"
    title = "S3 bucket versioning is not enabled"
    severity = Severity.LOW
    resource_types = ("aws_s3_bucket",)
    fsbp = ("S3.14",)
    remediation = "Enable versioning on the bucket so overwritten and deleted objects can be recovered."

    def check(self, resource, inventory):
        enabled = resource.get("versioning.enabled")
        if is_unknown(enabled):
            return None
        if enabled is not True:
            return fail("versioning is suspended or was never enabled")
        return PASS


class BucketKmsEncryption(Rule):
    id = "S3-005"
    title = "S3 bucket is not encrypted with a KMS key"
    severity = Severity.LOW
    resource_types = ("aws_s3_bucket",)
    fsbp = ("S3.17",)
    remediation = "Set the default encryption of the bucket to aws:kms with a customer managed key. Server access log targets are skipped because log delivery only supports SSE-S3."

    def check(self, resource, inventory):
        if bucket_name(resource) in logging_targets(inventory):
            return None
        encryption = resource.attrs.get("encryption")
        if is_unknown(encryption):
            return None
        algorithm = encryption.get("sse_algorithm") if isinstance(encryption, dict) else None
        if is_unknown(algorithm):
            return None
        if algorithm not in ("aws:kms", "aws:kms:dsse"):
            return fail("default encryption uses " + (algorithm or "SSE-S3") + " instead of a KMS key")
        return PASS


class BucketAccessLogging(Rule):
    id = "S3-006"
    title = "S3 bucket has no server access logging"
    severity = Severity.LOW
    resource_types = ("aws_s3_bucket",)
    fsbp = ("S3.9",)
    remediation = "Enable server access logging with a separate target bucket. Buckets that are themselves a logging target are skipped."

    def check(self, resource, inventory):
        if bucket_name(resource) in logging_targets(inventory):
            return None
        logging = resource.attrs.get("logging")
        if is_unknown(logging):
            return None
        if not isinstance(logging, dict) or logging.get("target_bucket") is None:
            return fail("server access logging is not configured")
        return PASS


class BucketAclPublic(Rule):
    id = "S3-007"
    title = "S3 bucket ACL grants access to everyone"
    severity = Severity.CRITICAL
    resource_types = ("aws_s3_bucket",)
    fsbp = ("S3.2", "S3.3")
    remediation = "Set the bucket ACL to private and remove grants for AllUsers and AuthenticatedUsers. Prefer bucket owner enforced ownership so ACLs are disabled."

    def check(self, resource, inventory):
        acl = resource.attrs.get("acl")
        if is_unknown(acl):
            return None
        if not isinstance(acl, dict):
            return PASS
        canned = acl.get("canned")
        if is_unknown(canned):
            return None
        if canned in PUBLIC_CANNED_ACLS:
            return fail(f"bucket uses the canned ACL {canned}")
        public = [g for g in acl.get("grants") or [] if g.get("uri") in PUBLIC_GRANTEE_URIS]
        if public:
            groups = sorted({str(g["uri"]).rsplit("/", 1)[-1] for g in public})
            return fail("ACL grants " + ", ".join(groups) + " access to the bucket")
        return PASS


class BucketMfaDelete(Rule):
    id = "S3-008"
    title = "S3 bucket versioning has MFA delete disabled"
    severity = Severity.LOW
    resource_types = ("aws_s3_bucket",)
    cis = ("2.1.2",)
    remediation = (
        "Enable MFA delete on the versioning configuration using the root account credentials and an MFA device."
    )

    def check(self, resource, inventory):
        enabled = resource.get("versioning.enabled")
        mfa = resource.get("versioning.mfa_delete")
        if is_unknown(enabled) or is_unknown(mfa):
            return None
        if mfa is not True:
            return fail("MFA delete is not enabled on the bucket")
        return PASS


class AccountPublicAccessBlock(Rule):
    id = "S3-009"
    title = "Account level S3 public access block is not fully enabled"
    severity = Severity.HIGH
    resource_types = ("aws_s3_account_public_access_block",)
    fsbp = ("S3.1",)
    remediation = (
        "Enable all four account level public access block settings so no bucket in the account can be made public."
    )

    def check(self, resource, inventory):
        if resource.attrs.get("exists") is False:
            return fail("no account level public access block configuration")
        missing = missing_block_settings(resource.attrs)
        if missing:
            return fail("account public access block leaves " + ", ".join(missing) + " off")
        return PASS


RULES = [
    BucketPublicAccessBlock,
    BucketPolicyPublic,
    BucketPolicyInsecureTransport,
    BucketVersioning,
    BucketKmsEncryption,
    BucketAccessLogging,
    BucketAclPublic,
    BucketMfaDelete,
    AccountPublicAccessBlock,
]
