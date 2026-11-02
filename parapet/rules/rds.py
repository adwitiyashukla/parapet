from parapet.model import Severity, is_unknown
from parapet.rules.base import PASS, Rule, fail


class PubliclyAccessible(Rule):
    id = "RDS-001"
    title = "RDS instance is publicly accessible"
    severity = Severity.CRITICAL
    resource_types = ("aws_db_instance",)
    cis = ("2.2.3",)
    fsbp = ("RDS.2",)
    remediation = "Set publicly_accessible to false and place the instance in private subnets reachable only from the application tier."

    def check(self, resource, inventory):
        public = resource.attrs.get("publicly_accessible")
        if is_unknown(public):
            return None
        if public is True:
            return fail("instance has a public endpoint")
        return PASS


class StorageEncrypted(Rule):
    id = "RDS-002"
    title = "RDS instance storage is not encrypted"
    severity = Severity.HIGH
    resource_types = ("aws_db_instance",)
    cis = ("2.2.1",)
    fsbp = ("RDS.3",)
    remediation = (
        "Enable storage encryption at creation; an existing instance needs an encrypted snapshot copy and a restore."
    )

    def check(self, resource, inventory):
        encrypted = resource.attrs.get("storage_encrypted")
        if is_unknown(encrypted):
            return None
        if encrypted is not True:
            return fail("storage is not encrypted at rest")
        return PASS


class BackupRetention(Rule):
    id = "RDS-003"
    title = "RDS instance keeps backups for too few days"
    severity = Severity.MEDIUM
    resource_types = ("aws_db_instance",)
    fsbp = ("RDS.11",)
    remediation = "Set backup_retention_period to at least 7 days so point in time recovery is possible."

    def check(self, resource, inventory):
        minimum = self.settings["backup_retention_min_days"]
        days = resource.attrs.get("backup_retention_period")
        if is_unknown(days):
            return None
        days = 0 if days is None else int(days)
        if days < minimum:
            return fail(f"automated backups are kept for {days} days, policy requires {minimum}")
        return PASS


class DeletionProtection(Rule):
    id = "RDS-004"
    title = "RDS instance has deletion protection disabled"
    severity = Severity.LOW
    resource_types = ("aws_db_instance",)
    fsbp = ("RDS.8",)
    remediation = "Enable deletion protection so the instance cannot be deleted by a single API call."

    def check(self, resource, inventory):
        protected = resource.attrs.get("deletion_protection")
        if is_unknown(protected):
            return None
        if protected is not True:
            return fail("deletion protection is off")
        return PASS


class AutoMinorVersionUpgrade(Rule):
    id = "RDS-005"
    title = "RDS instance does not apply minor engine upgrades automatically"
    severity = Severity.LOW
    resource_types = ("aws_db_instance",)
    cis = ("2.2.2",)
    fsbp = ("RDS.13",)
    remediation = "Enable auto_minor_version_upgrade so security patches in minor engine versions are applied in the maintenance window."

    def check(self, resource, inventory):
        auto = resource.attrs.get("auto_minor_version_upgrade")
        if is_unknown(auto):
            return None
        if auto is False:
            return fail("auto minor version upgrade is disabled")
        return PASS


RULES = [PubliclyAccessible, StorageEncrypted, BackupRetention, DeletionProtection, AutoMinorVersionUpgrade]
