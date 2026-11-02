from parapet.model import Severity, is_unknown
from parapet.rules.base import PASS, Rule, fail


class KeyRotation(Rule):
    id = "KMS-001"
    title = "Customer managed KMS key has rotation disabled"
    severity = Severity.MEDIUM
    resource_types = ("aws_kms_key",)
    cis = ("3.6",)
    security_hub = ("KMS.4",)
    remediation = "Enable automatic key rotation on symmetric customer managed keys."

    def check(self, resource, inventory):
        spec = resource.attrs.get("customer_master_key_spec")
        usage = resource.attrs.get("key_usage")
        if isinstance(spec, str) and spec != "SYMMETRIC_DEFAULT":
            return None
        if isinstance(usage, str) and usage != "ENCRYPT_DECRYPT":
            return None
        rotation = resource.attrs.get("enable_key_rotation")
        if is_unknown(rotation):
            return None
        if rotation is not True:
            return fail("automatic key rotation is disabled")
        return PASS


RULES = [KeyRotation]
