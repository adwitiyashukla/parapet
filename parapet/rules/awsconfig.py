from parapet.model import Severity
from parapet.rules.base import PASS, Rule, fail


class ConfigRecorder(Rule):
    id = "CONFIG-001"
    title = "AWS Config is not recording in the region"
    severity = Severity.MEDIUM
    resource_types = ("aws_config_configuration_recorder",)
    sources = ("aws",)
    cis = ("3.3",)
    fsbp = ("Config.1",)
    remediation = "Create a configuration recorder with a delivery channel in every region in use and start it."

    def check(self, resource, inventory):
        if resource.attrs.get("exists") is False:
            return fail("no configuration recorder in this region")
        if resource.attrs.get("recording") is not True:
            return fail("configuration recorder exists but is stopped")
        if resource.attrs.get("all_supported") is False:
            return fail("configuration recorder does not record all supported resource types")
        return PASS


RULES = [ConfigRecorder]
