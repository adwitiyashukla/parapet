from datetime import datetime, timezone

from parapet.model import Severity, is_unknown
from parapet.rules import policy
from parapet.rules.base import PASS, Rule, fail

PRINCIPAL_TYPES = ("aws_iam_user", "aws_iam_role", "aws_iam_group")


def parse_time(text):
    if not isinstance(text, str) or not text or text in ("N/A", "no_information", "not_supported"):
        return None
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def age_days(now, text):
    value = parse_time(text)
    if value is None:
        return None
    return (now - value).days


def policy_documents(resource) -> list:
    documents = []
    if resource.type == "aws_iam_policy":
        documents.append((resource.label, resource.attrs.get("policy")))
    else:
        for inline in resource.attrs.get("inline_policies") or []:
            if isinstance(inline, dict):
                documents.append((str(inline.get("name") or "inline policy"), inline.get("policy")))
    return documents


class RootAccessKeys(Rule):
    id = "IAM-001"
    title = "Root account has active access keys"
    severity = Severity.CRITICAL
    resource_types = ("aws_account",)
    sources = ("aws",)
    cis = ("1.4",)
    fsbp = ("IAM.4",)
    remediation = "Delete the access keys of the root user and use IAM roles for programmatic access."

    def check(self, resource, inventory):
        keys = resource.attrs.get("root_access_keys")
        if keys is None:
            return None
        if keys:
            return fail(f"root user has {keys} access key(s)")
        return PASS


class RootMfa(Rule):
    id = "IAM-002"
    title = "Root account has no MFA device"
    severity = Severity.CRITICAL
    resource_types = ("aws_account",)
    sources = ("aws",)
    cis = ("1.5",)
    fsbp = ("IAM.9",)
    remediation = "Register a hardware or virtual MFA device for the root user."

    def check(self, resource, inventory):
        enabled = resource.attrs.get("root_mfa_enabled")
        if enabled is None:
            return None
        if not enabled:
            return fail("root user signs in without MFA")
        return PASS


class PasswordLength(Rule):
    id = "IAM-003"
    title = "IAM password policy allows short passwords"
    severity = Severity.MEDIUM
    resource_types = ("aws_iam_account_password_policy",)
    cis = ("1.8",)
    fsbp = ("IAM.7",)
    remediation = "Set the account password policy minimum length to 14 characters or more."

    def check(self, resource, inventory):
        minimum = self.settings["password_min_length"]
        if resource.attrs.get("exists") is False:
            return fail("the account has no custom password policy, so the default 8 character minimum applies")
        length = resource.attrs.get("minimum_password_length")
        if is_unknown(length):
            return None
        if length is None or length < minimum:
            return fail(f"minimum password length is {length if length is not None else 6}, policy requires {minimum}")
        return PASS


class PasswordReuse(Rule):
    id = "IAM-004"
    title = "IAM password policy allows password reuse"
    severity = Severity.LOW
    resource_types = ("aws_iam_account_password_policy",)
    cis = ("1.9",)
    fsbp = ("IAM.7",)
    remediation = "Set password reuse prevention to remember the last 24 passwords."

    def check(self, resource, inventory):
        minimum = self.settings["password_reuse_prevention"]
        if resource.attrs.get("exists") is False:
            return fail("the account has no custom password policy, so previous passwords can be reused")
        remembered = resource.attrs.get("password_reuse_prevention")
        if is_unknown(remembered):
            return None
        if remembered is None or remembered < minimum:
            return fail(f"only {remembered or 0} previous password(s) are remembered, policy requires {minimum}")
        return PASS


class ConsoleUserWithoutMfa(Rule):
    id = "IAM-005"
    title = "IAM user with console access has no MFA"
    severity = Severity.HIGH
    resource_types = ("aws_iam_user",)
    sources = ("aws",)
    cis = ("1.10",)
    fsbp = ("IAM.5",)
    remediation = "Require an MFA device for every user with a console password, or remove the password."

    def check(self, resource, inventory):
        if "password_enabled" not in resource.attrs:
            return None
        if resource.attrs["password_enabled"] and not resource.attrs.get("mfa_active"):
            return fail("user has a console password but no MFA device")
        return PASS


class AccessKeyRotation(Rule):
    id = "IAM-006"
    title = "IAM access key has not been rotated"
    severity = Severity.MEDIUM
    resource_types = ("aws_iam_user",)
    sources = ("aws",)
    cis = ("1.14",)
    fsbp = ("IAM.3",)
    remediation = "Rotate access keys at least every 90 days and delete the old key after the new one is in use."

    def check(self, resource, inventory):
        keys = resource.attrs.get("access_keys")
        if keys is None:
            return None
        limit = self.settings["access_key_max_age_days"]
        old = []
        for key in keys:
            if not key.get("active"):
                continue
            age = age_days(self.now, key.get("last_rotated"))
            if age is not None and age > limit:
                old.append(f"{age} days")
        if old:
            return fail("active access key age " + ", ".join(old) + f" exceeds {limit} days")
        return PASS


class UnusedCredentials(Rule):
    id = "IAM-007"
    title = "IAM credentials unused for too long are still active"
    severity = Severity.MEDIUM
    resource_types = ("aws_iam_user",)
    sources = ("aws",)
    cis = ("1.12",)
    fsbp = ("IAM.8",)
    remediation = "Disable or delete passwords and access keys that have not been used within the allowed window."

    def check(self, resource, inventory):
        if "password_enabled" not in resource.attrs:
            return None
        limit = self.settings["unused_credential_days"]
        stale = []
        if resource.attrs.get("password_enabled"):
            last = age_days(self.now, resource.attrs.get("password_last_used"))
            if last is None:
                last = age_days(self.now, resource.attrs.get("created"))
            if last is not None and last > limit:
                stale.append(f"password unused for {last} days")
        for key in resource.attrs.get("access_keys") or []:
            if not key.get("active"):
                continue
            last = age_days(self.now, key.get("last_used"))
            if last is None:
                last = age_days(self.now, key.get("last_rotated"))
            if last is not None and last > limit:
                stale.append(f"access key unused for {last} days")
        if stale:
            return fail(", ".join(stale) + f" (limit {limit} days)")
        return PASS


class MultipleAccessKeys(Rule):
    id = "IAM-008"
    title = "IAM user has more than one active access key"
    severity = Severity.LOW
    resource_types = ("aws_iam_user",)
    sources = ("aws",)
    cis = ("1.13",)
    remediation = "Keep one active access key per user; a second key should only exist briefly during rotation."

    def check(self, resource, inventory):
        keys = resource.attrs.get("access_keys")
        if keys is None:
            return None
        active = sum(1 for key in keys if key.get("active"))
        if active > 1:
            return fail(f"user has {active} active access keys")
        return PASS


class UserDirectPolicies(Rule):
    id = "IAM-009"
    title = "IAM user has policies attached directly"
    severity = Severity.LOW
    resource_types = ("aws_iam_user",)
    cis = ("1.15",)
    fsbp = ("IAM.2",)
    remediation = "Attach policies to groups and add users to groups instead of attaching policies to users."

    def check(self, resource, inventory):
        inline = len(resource.attrs.get("inline_policies") or [])
        attached = len(resource.attrs.get("attached_policy_arns") or [])
        if inline or attached:
            return fail(f"user has {inline} inline and {attached} attached policies")
        return PASS


class FullAdminPolicy(Rule):
    id = "IAM-010"
    title = "IAM policy grants full administrative access"
    severity = Severity.HIGH
    resource_types = ("aws_iam_policy", *PRINCIPAL_TYPES)
    cis = ("1.16",)
    fsbp = ("IAM.1",)
    remediation = "Replace Action * on Resource * with the specific actions and resources the principal needs."

    def check(self, resource, inventory):
        documents = policy_documents(resource)
        if not documents:
            return None
        hits = []
        for name, raw in documents:
            document = policy.load_policy(raw)
            if is_unknown(document) or document is None:
                continue
            for label in policy.allows_full_admin(document):
                hits.append(f"{name} ({label})")
        if hits:
            return fail("Action * on Resource * in " + ", ".join(hits))
        return PASS


class ServiceWildcardPolicy(Rule):
    id = "IAM-011"
    title = "IAM policy grants wildcard actions for a whole service"
    severity = Severity.MEDIUM
    resource_types = ("aws_iam_policy", *PRINCIPAL_TYPES)
    fsbp = ("IAM.21",)
    remediation = "List the individual actions that are needed instead of service:* wildcards."

    def check(self, resource, inventory):
        documents = policy_documents(resource)
        if not documents:
            return None
        hits = []
        for name, raw in documents:
            document = policy.load_policy(raw)
            if is_unknown(document) or document is None:
                continue
            wildcards = policy.service_wildcards(document)
            if wildcards:
                hits.append(f"{name}: " + ", ".join(wildcards))
        if hits:
            return fail("; ".join(hits))
        return PASS


class RoleTrustsAnyPrincipal(Rule):
    id = "IAM-012"
    title = "IAM role can be assumed by any AWS principal"
    severity = Severity.CRITICAL
    resource_types = ("aws_iam_role",)
    remediation = "Restrict the trust policy to specific accounts, roles or services, or add a condition such as aws:PrincipalOrgID."

    def check(self, resource, inventory):
        document = policy.load_policy(resource.attrs.get("assume_role_policy"))
        if is_unknown(document):
            return None
        if document is None:
            return None
        hits = policy.trust_allows_any_principal(document)
        if hits:
            return fail("trust policy allows sts:AssumeRole from any principal in " + ", ".join(hits))
        return PASS


RULES = [
    RootAccessKeys,
    RootMfa,
    PasswordLength,
    PasswordReuse,
    ConsoleUserWithoutMfa,
    AccessKeyRotation,
    UnusedCredentials,
    MultipleAccessKeys,
    UserDirectPolicies,
    FullAdminPolicy,
    ServiceWildcardPolicy,
    RoleTrustsAnyPrincipal,
]
