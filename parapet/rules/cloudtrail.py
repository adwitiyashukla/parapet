from parapet.model import Severity, is_unknown
from parapet.rules.base import PASS, Outcome, Rule, fail


def covers_management_events(trail) -> bool:
    management = trail.attrs.get("management_events")
    if management is False:
        return False
    read_write = trail.attrs.get("read_write_type")
    if isinstance(read_write, str) and read_write != "All":
        return False
    return True


class MultiRegionTrail(Rule):
    id = "CT-001"
    title = "No multi-region CloudTrail trail records management events"
    severity = Severity.HIGH
    resource_types = ("aws_account",)
    sources = ("aws",)
    cis = ("3.1",)
    fsbp = ("CloudTrail.1",)
    remediation = "Create one multi-region trail that is logging, includes global service events and records read and write management events."

    def evaluate(self, inventory):
        accounts = inventory.of_type("aws_account")
        if not accounts:
            return []
        trails = inventory.of_type("aws_cloudtrail")
        good = [
            t
            for t in trails
            if t.attrs.get("is_multi_region_trail") is True
            and t.attrs.get("enable_logging") is not False
            and covers_management_events(t)
        ]
        if good:
            return [Outcome(self, accounts[0], True, "")]
        if trails:
            message = (
                f"{len(trails)} trail(s) exist but none is multi-region, logging and recording all management events"
            )
        else:
            message = "the account has no CloudTrail trail"
        return [Outcome(self, accounts[0], False, message)]


class TrailLogFileValidation(Rule):
    id = "CT-002"
    title = "CloudTrail log file validation is disabled"
    severity = Severity.MEDIUM
    resource_types = ("aws_cloudtrail",)
    cis = ("3.2",)
    fsbp = ("CloudTrail.4",)
    remediation = "Enable log file validation so digest files prove the delivered logs were not changed."

    def check(self, resource, inventory):
        enabled = resource.attrs.get("enable_log_file_validation")
        if is_unknown(enabled):
            return None
        if enabled is not True:
            return fail("log file validation is off for this trail")
        return PASS


class TrailKmsEncryption(Rule):
    id = "CT-003"
    title = "CloudTrail logs are not encrypted with a KMS key"
    severity = Severity.MEDIUM
    resource_types = ("aws_cloudtrail",)
    cis = ("3.5",)
    fsbp = ("CloudTrail.2",)
    remediation = "Set a customer managed KMS key on the trail so log files are encrypted with SSE-KMS."

    def check(self, resource, inventory):
        key = resource.attrs.get("kms_key_id")
        if is_unknown(key):
            return PASS
        if not key:
            return fail("trail delivers logs without a KMS key")
        return PASS


class TrailCloudWatchLogs(Rule):
    id = "CT-004"
    title = "CloudTrail trail is not sending logs to CloudWatch Logs"
    severity = Severity.LOW
    resource_types = ("aws_cloudtrail",)
    fsbp = ("CloudTrail.5",)
    remediation = "Connect the trail to a CloudWatch Logs group so metric filters and alarms can watch the events."

    def check(self, resource, inventory):
        group = resource.attrs.get("cloud_watch_logs_group_arn")
        if is_unknown(group):
            return PASS
        if not group:
            return fail("trail has no CloudWatch Logs group")
        return PASS


class TrailLogging(Rule):
    id = "CT-005"
    title = "CloudTrail trail has logging turned off"
    severity = Severity.HIGH
    resource_types = ("aws_cloudtrail",)
    sources = ("aws",)
    remediation = "Start logging on the trail; a stopped trail records nothing while it exists."

    def check(self, resource, inventory):
        logging = resource.attrs.get("enable_logging")
        if logging is None or is_unknown(logging):
            return None
        if not logging:
            return fail("trail exists but is not logging")
        return PASS


RULES = [MultiRegionTrail, TrailLogFileValidation, TrailKmsEncryption, TrailCloudWatchLogs, TrailLogging]
