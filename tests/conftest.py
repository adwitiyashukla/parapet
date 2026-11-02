from pathlib import Path

import pytest

from parapet.model import Inventory, Resource

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def insecure_plan() -> Path:
    return ROOT / "examples" / "insecure" / "plan.json"


@pytest.fixture(scope="session")
def hardened_plan() -> Path:
    return ROOT / "examples" / "hardened" / "plan.json"


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def make_inventory(source: str, *resources: Resource) -> Inventory:
    inventory = Inventory(source=source, origin="test")
    for resource in resources:
        inventory.add(resource)
    return inventory


def resource(type_name: str, resource_id: str = "r1", **attrs) -> Resource:
    return Resource(type=type_name, id=resource_id, region="us-east-1", name=resource_id, attrs=attrs)


def verdict(rule_class, res: Resource, source: str = "terraform", settings=None, now=None, extra=()):
    rule = rule_class(settings, now)
    inventory = make_inventory(source, res, *extra)
    return rule.check(res, inventory)
