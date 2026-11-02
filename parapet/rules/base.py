import copy
from dataclasses import dataclass
from datetime import datetime, timezone

from parapet.config import DEFAULT_SETTINGS
from parapet.model import Inventory, Resource, Severity

PASS = (True, "")


def fail(message: str) -> tuple:
    return (False, message)


@dataclass
class Outcome:
    rule: "Rule"
    resource: Resource
    ok: bool
    message: str


class Rule:
    id = ""
    title = ""
    severity = Severity.MEDIUM
    resource_types: tuple = ()
    sources: tuple = ("aws", "terraform")
    cis: tuple = ()
    security_hub: tuple = ()
    remediation = ""

    def __init__(self, settings: dict | None = None, now: datetime | None = None):
        self.settings = copy.deepcopy(DEFAULT_SETTINGS) if settings is None else settings
        self.now = now or datetime.now(timezone.utc)

    @property
    def service(self) -> str:
        return self.id.split("-")[0].lower()

    def evaluate(self, inventory: Inventory) -> list:
        outcomes = []
        for resource in inventory.of_type(*self.resource_types):
            verdict = self.check(resource, inventory)
            if verdict is None:
                continue
            ok, message = verdict
            outcomes.append(Outcome(self, resource, ok, message))
        return outcomes

    def check(self, resource: Resource, inventory: Inventory):
        raise NotImplementedError

    def describe(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.label,
            "resource_types": list(self.resource_types),
            "sources": list(self.sources),
            "cis": list(self.cis),
            "security_hub": list(self.security_hub),
            "remediation": self.remediation,
        }
