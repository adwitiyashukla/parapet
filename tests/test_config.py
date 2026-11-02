from datetime import date

import pytest

from parapet.config import (
    DEFAULT_SETTINGS,
    Config,
    ConfigError,
    load_config,
    parse_config,
    parse_fail_on,
)
from parapet.model import Severity


def test_defaults_without_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = load_config(None)
    assert config.regions == ["us-east-1"]
    assert config.fail_on is Severity.HIGH
    assert config.settings == DEFAULT_SETTINGS
    assert config.suppressions == []


def test_missing_explicit_file(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.toml")


def test_full_config_parses(tmp_path):
    text = """
[scan]
regions = ["us-east-1", "eu-west-1"]
workers = 4
fail_on = "medium"
profile = "audit"

[rules]
disabled = ["S3-008"]
access_key_max_age_days = 60
database_ports = [3306]
deprecated_lambda_runtimes = ["python3.7"]

[report]
width = 100

[[suppressions]]
rule = "S3-006"
resource = "parapet-demo-*"
reason = "log buckets"
expires = 2030-01-01
"""
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    config = load_config(path)
    assert config.regions == ["us-east-1", "eu-west-1"]
    assert config.workers == 4
    assert config.fail_on is Severity.MEDIUM
    assert config.profile == "audit"
    assert config.disabled_rules == ["S3-008"]
    assert config.settings["access_key_max_age_days"] == 60
    assert config.settings["database_ports"] == [3306]
    assert config.settings["password_min_length"] == 14
    assert config.width == 100
    assert len(config.suppressions) == 1
    assert config.suppressions[0].expires == date(2030, 1, 1)
    assert not config.suppressions[0].expired(date(2029, 12, 31))
    assert config.suppressions[0].expired(date(2030, 1, 2))
    assert config.path == str(path)


@pytest.mark.parametrize(
    "data",
    [
        {"scan": {"region": ["us-east-1"]}},
        {"scan": {"regions": "us-east-1"}},
        {"scan": {"regions": []}},
        {"scan": {"workers": 0}},
        {"scan": {"fail_on": "severe"}},
        {"scan": {"profile": 3}},
        {"rules": {"disabled": "S3-001"}},
        {"rules": {"password_min_length": -1}},
        {"rules": {"database_ports": [70000]}},
        {"rules": {"deprecated_lambda_runtimes": [1]}},
        {"report": {"width": -5}},
        {"suppressions": {"rule": "S3-001"}},
        {"suppressions": [{"rule": "S3-001", "resource": "x"}]},
        {"suppressions": [{"rule": "S3-001", "resource": "x", "reason": " "}]},
        {"suppressions": [{"rule": "S3-001", "resource": "x", "reason": "ok", "expires": "soon"}]},
        {"extra": {}},
    ],
)
def test_invalid_configs_are_rejected(data):
    with pytest.raises(ConfigError):
        parse_config(data)


def test_fail_on_none_disables_threshold():
    assert parse_fail_on("none", "x") is None
    assert parse_fail_on("LOW", "x") is Severity.LOW
    with pytest.raises(ConfigError):
        parse_fail_on(5, "x")


def test_bad_toml_reports_path(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("[scan\nregions = 1", encoding="utf-8")
    with pytest.raises(ConfigError) as info:
        load_config(path)
    assert "config.toml" in str(info.value)


def test_config_settings_do_not_share_default_lists():
    first = Config()
    first.settings["admin_ports"].append(2222)
    assert DEFAULT_SETTINGS["admin_ports"] == [22, 3389]
    assert Config().settings["admin_ports"] == [22, 3389]
