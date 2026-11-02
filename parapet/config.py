import copy
import tomllib
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

from parapet.model import Severity


class ConfigError(Exception):
    pass


DEFAULT_SETTINGS = {
    "access_key_max_age_days": 90,
    "unused_credential_days": 45,
    "password_min_length": 14,
    "password_reuse_prevention": 24,
    "backup_retention_min_days": 7,
    "admin_ports": [22, 3389],
    "database_ports": [1433, 1521, 3306, 5432, 6379, 9200, 27017],
    "public_ports_allowed": [80, 443],
    "deprecated_lambda_runtimes": [
        "python3.8",
        "python3.9",
        "nodejs16.x",
        "nodejs18.x",
        "go1.x",
        "dotnet6",
        "dotnetcore3.1",
        "java8",
        "ruby2.7",
        "ruby3.2",
        "provided",
    ],
}

INT_SETTINGS = (
    "access_key_max_age_days",
    "unused_credential_days",
    "password_min_length",
    "password_reuse_prevention",
    "backup_retention_min_days",
)
PORT_LIST_SETTINGS = ("admin_ports", "database_ports", "public_ports_allowed")
STRING_LIST_SETTINGS = ("deprecated_lambda_runtimes",)


@dataclass
class Suppression:
    rule: str
    resource: str
    reason: str
    expires: date | None = None

    def expired(self, today: date) -> bool:
        return self.expires is not None and self.expires < today

    @property
    def label(self) -> str:
        return f"{self.rule} on {self.resource}: {self.reason}"


@dataclass
class Config:
    regions: list = field(default_factory=lambda: ["us-east-1"])
    workers: int = 8
    fail_on: Severity | None = Severity.HIGH
    profile: str = ""
    disabled_rules: list = field(default_factory=list)
    settings: dict = field(default_factory=lambda: copy.deepcopy(DEFAULT_SETTINGS))
    width: int = 0
    suppressions: list = field(default_factory=list)
    path: str = ""


def load_config(path) -> Config:
    if path is None:
        candidate = Path("config.toml")
        if not candidate.is_file():
            return Config()
        path = candidate
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from None
    config = parse_config(data, str(path))
    config.path = str(path)
    return config


def parse_config(data: dict, where: str = "config") -> Config:
    if not isinstance(data, dict):
        raise ConfigError(f"{where}: top level must be a table")
    allowed = {"scan", "rules", "report", "suppressions"}
    _check_keys(data, allowed, where)
    config = Config()
    scan = _table(data, "scan", where)
    _check_keys(scan, {"regions", "workers", "fail_on", "profile"}, f"{where} [scan]")
    if "regions" in scan:
        config.regions = _string_list(scan["regions"], f"{where} [scan] regions")
        if not config.regions:
            raise ConfigError(f"{where} [scan] regions must not be empty")
    if "workers" in scan:
        config.workers = _positive_int(scan["workers"], f"{where} [scan] workers", 64)
    if "fail_on" in scan:
        config.fail_on = parse_fail_on(scan["fail_on"], f"{where} [scan] fail_on")
    if "profile" in scan:
        if not isinstance(scan["profile"], str):
            raise ConfigError(f"{where} [scan] profile must be a string")
        config.profile = scan["profile"]
    rules = _table(data, "rules", where)
    _check_keys(rules, {"disabled", *DEFAULT_SETTINGS}, f"{where} [rules]")
    if "disabled" in rules:
        config.disabled_rules = _string_list(rules["disabled"], f"{where} [rules] disabled")
    for key in INT_SETTINGS:
        if key in rules:
            config.settings[key] = _positive_int(rules[key], f"{where} [rules] {key}", 100000)
    for key in PORT_LIST_SETTINGS:
        if key in rules:
            config.settings[key] = _port_list(rules[key], f"{where} [rules] {key}")
    for key in STRING_LIST_SETTINGS:
        if key in rules:
            config.settings[key] = _string_list(rules[key], f"{where} [rules] {key}")
    report = _table(data, "report", where)
    _check_keys(report, {"width"}, f"{where} [report]")
    if "width" in report:
        width = report["width"]
        if not isinstance(width, int) or isinstance(width, bool) or width < 0:
            raise ConfigError(f"{where} [report] width must be an integer of 0 or more")
        config.width = width
    raw_suppressions = data.get("suppressions", [])
    if not isinstance(raw_suppressions, list):
        raise ConfigError(f"{where}: suppressions must be an array of tables")
    for index, entry in enumerate(raw_suppressions, start=1):
        config.suppressions.append(_suppression(entry, f"{where} [[suppressions]] #{index}"))
    return config


def parse_fail_on(value, where: str):
    if not isinstance(value, str):
        raise ConfigError(f"{where} must be a string")
    if value.strip().lower() == "none":
        return None
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from None


def _table(data: dict, name: str, where: str) -> dict:
    table = data.get(name, {})
    if not isinstance(table, dict):
        raise ConfigError(f"{where}: [{name}] must be a table")
    return table


def _check_keys(table: dict, allowed: set, where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        names = ", ".join(sorted(allowed))
        raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)}; allowed: {names}")


def _string_list(value, where: str) -> list:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where} must be a list of strings")
    return list(value)


def _positive_int(value, where: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > maximum:
        raise ConfigError(f"{where} must be an integer between 1 and {maximum}")
    return value


def _port_list(value, where: str) -> list:
    if not isinstance(value, list):
        raise ConfigError(f"{where} must be a list of ports")
    for port in value:
        if not isinstance(port, int) or isinstance(port, bool) or port < 0 or port > 65535:
            raise ConfigError(f"{where} must only contain ports between 0 and 65535")
    return list(value)


def _suppression(entry, where: str) -> Suppression:
    if not isinstance(entry, dict):
        raise ConfigError(f"{where} must be a table")
    _check_keys(entry, {"rule", "resource", "reason", "expires"}, where)
    for key in ("rule", "resource", "reason"):
        if key not in entry or not isinstance(entry[key], str) or not entry[key].strip():
            raise ConfigError(f"{where} needs a non-empty string '{key}'")
    expires = entry.get("expires")
    if isinstance(expires, datetime):
        expires = expires.date()
    if expires is not None and not isinstance(expires, date):
        raise ConfigError(f"{where} expires must be a date like 2027-01-31")
    return Suppression(entry["rule"], entry["resource"], entry["reason"], expires)
