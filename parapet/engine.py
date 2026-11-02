import time
from datetime import datetime, timezone
from fnmatch import fnmatchcase

from parapet import __version__
from parapet.config import Config
from parapet.model import Finding, Inventory, ScanResult
from parapet.rules import build_rules


def match_suppression(finding: Finding, resource, suppressions: list):
    candidates = {resource.id, resource.arn, resource.name, resource.address}
    candidates.discard("")
    for suppression in suppressions:
        if suppression.rule not in ("*", finding.rule_id):
            continue
        if any(fnmatchcase(candidate, suppression.resource) for candidate in candidates):
            return suppression
    return None


def run_rules(inventory: Inventory, config: Config, now: datetime | None = None) -> ScanResult:
    now = now or datetime.now(timezone.utc)
    clock = time.perf_counter()
    rules = build_rules(config.settings, config.disabled_rules, now)
    active_suppressions = []
    warnings = []
    for suppression in config.suppressions:
        if suppression.expired(now.date()):
            warnings.append(f"suppression expired on {suppression.expires.isoformat()}: {suppression.label}")
        else:
            active_suppressions.append(suppression)
    findings = []
    passed = 0
    for rule in rules:
        if inventory.source not in rule.sources:
            continue
        for outcome in rule.evaluate(inventory):
            if outcome.ok:
                passed += 1
                continue
            resource = outcome.resource
            finding = Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                resource_type=resource.type,
                resource_id=resource.id,
                resource_name=resource.name,
                region=resource.region,
                message=outcome.message,
                remediation=rule.remediation,
                cis=list(rule.cis),
                security_hub=list(rule.security_hub),
                address=resource.address or resource.arn,
            )
            suppression = match_suppression(finding, resource, active_suppressions)
            if suppression is not None:
                finding.status = "suppressed"
                finding.suppressed_by = suppression.label
            findings.append(finding)
    findings.sort(key=lambda f: (-int(f.severity), f.rule_id, f.region, f.resource_id))
    return ScanResult(
        source=inventory.source,
        origin=inventory.origin,
        account_id=inventory.account_id,
        regions=list(inventory.regions),
        started_at=now.isoformat(timespec="seconds"),
        duration_seconds=round(time.perf_counter() - clock, 3),
        resource_count=len(inventory.resources),
        rule_count=len(rules),
        passed=passed,
        findings=findings,
        errors=list(inventory.errors),
        warnings=warnings,
        version=__version__,
    )
