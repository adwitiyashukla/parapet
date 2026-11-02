import json
from pathlib import Path

from parapet.model import ScanResult, Severity
from parapet.rules import ALL_RULES

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}
LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def artifact_uri(result: ScanResult) -> str:
    if result.source != "terraform" or not result.origin:
        return "aws-account.json"
    path = Path(result.origin)
    if path.is_absolute():
        try:
            path = path.relative_to(Path.cwd())
        except ValueError:
            path = Path(path.name)
    text = path.as_posix()
    while text.startswith("./"):
        text = text[2:]
    return text or "plan.json"


def rule_descriptor(rule) -> dict:
    tags = ["security", "service/" + rule.id.split("-")[0].lower()]
    tags.extend(f"cis/{item}" for item in rule.cis)
    tags.extend(f"securityhub/{item}" for item in rule.security_hub)
    frameworks = []
    if rule.cis:
        frameworks.append("CIS AWS Foundations Benchmark v3.0 " + ", ".join(rule.cis))
    if rule.security_hub:
        frameworks.append("AWS Security Hub controls " + ", ".join(rule.security_hub))
    return {
        "id": rule.id,
        "name": rule.__name__,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.title + (". " + "; ".join(frameworks) if frameworks else "")},
        "help": {"text": rule.remediation, "markdown": rule.remediation},
        "defaultConfiguration": {"level": LEVELS[rule.severity]},
        "properties": {"security-severity": SECURITY_SEVERITY[rule.severity], "tags": tags},
    }


def render_sarif(result: ScanResult) -> str:
    rules = [rule_descriptor(rule) for rule in ALL_RULES]
    index = {descriptor["id"]: position for position, descriptor in enumerate(rules)}
    uri = artifact_uri(result)
    results = []
    for finding in result.active:
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": index[finding.rule_id],
                "level": LEVELS[finding.severity],
                "message": {
                    "text": f"{finding.resource_type} {finding.resource_name or finding.resource_id}: {finding.message}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": 1, "startColumn": 1},
                        },
                        "logicalLocations": [
                            {
                                "name": finding.resource_name or finding.resource_id,
                                "fullyQualifiedName": finding.address or finding.resource_id,
                                "kind": "resource",
                            }
                        ],
                    }
                ],
                "partialFingerprints": {
                    "parapet/v1": f"{finding.rule_id}:{finding.resource_type}:{finding.resource_id}:{finding.region}"
                },
                "properties": {
                    "severity": finding.severity.label,
                    "resourceType": finding.resource_type,
                    "resourceId": finding.resource_id,
                    "region": finding.region,
                    "remediation": finding.remediation,
                },
            }
        )
    notifications = [
        {
            "level": "warning",
            "message": {"text": f"{error['service']} {error['region']}: {error['error']}"},
        }
        for error in result.errors
    ]
    document = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "parapet",
                        "version": result.version,
                        "informationUri": "https://github.com/adwitiyashukla/parapet",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": result.started_at.replace("+00:00", "Z"),
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "results": results,
                "properties": {
                    "source": result.source,
                    "origin": result.origin,
                    "accountId": result.account_id,
                    "score": result.score,
                },
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"
