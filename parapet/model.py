from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, text: str) -> "Severity":
        try:
            return cls[text.strip().upper()]
        except KeyError:
            names = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity '{text}', expected one of {names}") from None


class Unknown:
    def __repr__(self) -> str:
        return "unknown"

    def __bool__(self) -> bool:
        return False


UNKNOWN = Unknown()


def is_unknown(value) -> bool:
    return value is UNKNOWN


@dataclass
class Resource:
    type: str
    id: str
    region: str = "global"
    name: str = ""
    arn: str = ""
    address: str = ""
    attrs: dict = field(default_factory=dict)

    def get(self, path: str, default=None):
        value = self.attrs
        for part in path.split("."):
            if is_unknown(value):
                return UNKNOWN
            if isinstance(value, dict):
                if part not in value:
                    return default
                value = value[part]
            elif isinstance(value, list):
                if not part.isdigit() or int(part) >= len(value):
                    return default
                value = value[int(part)]
            else:
                return default
        return value

    @property
    def label(self) -> str:
        return self.name or self.id


@dataclass
class Inventory:
    source: str
    origin: str = ""
    account_id: str = ""
    regions: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def add(self, resource: Resource) -> None:
        self.resources.append(resource)

    def of_type(self, *types: str) -> list:
        return [r for r in self.resources if r.type in types]

    def find(self, type_name: str, resource_id: str):
        for resource in self.resources:
            if resource.type == type_name and resource.id == resource_id:
                return resource
        return None


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    resource_type: str
    resource_id: str
    resource_name: str
    region: str
    message: str
    remediation: str
    cis: list
    security_hub: list
    address: str = ""
    status: str = "fail"
    suppressed_by: str = ""

    @property
    def key(self) -> tuple:
        return (self.rule_id, self.resource_type, self.resource_id, self.region)

    @property
    def service(self) -> str:
        return self.rule_id.split("-")[0].lower()

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        fields = dict(data)
        fields["severity"] = Severity.parse(fields["severity"])
        return cls(**fields)


@dataclass
class ScanResult:
    source: str
    origin: str
    account_id: str
    regions: list
    started_at: str
    duration_seconds: float
    resource_count: int
    rule_count: int
    passed: int
    findings: list
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    version: str = ""

    @property
    def active(self) -> list:
        return [f for f in self.findings if f.status == "fail"]

    @property
    def suppressed(self) -> list:
        return [f for f in self.findings if f.status == "suppressed"]

    def counts(self) -> dict:
        counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for finding in self.active:
            counts[finding.severity.label] += 1
        return counts

    @property
    def score(self) -> float:
        total = self.passed + len(self.active)
        if total == 0:
            return 100.0
        return round(100.0 * self.passed / total, 1)

    def worst(self):
        active = self.active
        if not active:
            return None
        return max(f.severity for f in active)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "source": self.source,
            "origin": self.origin,
            "account_id": self.account_id,
            "regions": list(self.regions),
            "started_at": self.started_at,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "resources": self.resource_count,
                "rules": self.rule_count,
                "passed": self.passed,
                "failed": len(self.active),
                "suppressed": len(self.suppressed),
                "score": self.score,
                "by_severity": self.counts(),
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScanResult":
        summary = data.get("summary", {})
        return cls(
            source=data.get("source", ""),
            origin=data.get("origin", ""),
            account_id=data.get("account_id", ""),
            regions=list(data.get("regions", [])),
            started_at=data.get("started_at", ""),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            resource_count=int(summary.get("resources", 0)),
            rule_count=int(summary.get("rules", 0)),
            passed=int(summary.get("passed", 0)),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            errors=list(data.get("errors", [])),
            warnings=list(data.get("warnings", [])),
            version=data.get("version", ""),
        )
