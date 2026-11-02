import json
from html.parser import HTMLParser

from conftest import make_inventory, resource

from parapet.config import Config, Suppression
from parapet.engine import run_rules
from parapet.model import ScanResult
from parapet.report import render_html, render_json, render_sarif, render_table
from parapet.rules import rule_ids
from parapet.sources.terraform import load_plan


def scan(path, config=None):
    return run_rules(load_plan(str(path)), config or Config())


def test_json_report_roundtrips(insecure_plan):
    result = scan(insecure_plan)
    data = json.loads(render_json(result))
    assert data["summary"]["failed"] == 36
    assert data["summary"]["by_severity"]["critical"] == 6
    assert data["findings"][0]["severity"] == "critical"
    restored = ScanResult.from_dict(data)
    assert restored.findings == result.findings
    assert restored.score == result.score


def test_sarif_structure(insecure_plan, monkeypatch):
    monkeypatch.chdir(insecure_plan.parent.parent.parent)
    result = scan(insecure_plan)
    sarif = json.loads(render_sarif(result))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == rule_ids()
    assert all(r["properties"]["security-severity"] for r in rules)
    assert all(r["help"]["text"] for r in rules)
    results = run["results"]
    assert len(results) == 36
    for item in results:
        assert rules[item["ruleIndex"]]["id"] == item["ruleId"]
        assert item["level"] in ("error", "warning", "note")
        location = item["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "examples/insecure/plan.json"
        assert location["physicalLocation"]["region"]["startLine"] == 1
        assert location["logicalLocations"][0]["fullyQualifiedName"].startswith("aws_")
        assert item["partialFingerprints"]["parapet/v1"]
    critical = [r for r in results if r["properties"]["severity"] == "critical"]
    assert all(r["level"] == "error" for r in critical)
    assert run["invocations"][0]["startTimeUtc"].endswith("Z")
    assert run["properties"]["score"] == 16.3


def test_sarif_uri_for_paths_outside_the_working_directory(insecure_plan, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sarif = json.loads(render_sarif(scan(insecure_plan)))
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "plan.json"
    monkeypatch.chdir(insecure_plan.parent)
    result = run_rules(load_plan("./plan.json"), Config())
    uri = json.loads(render_sarif(result))["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "plan.json"


def test_sarif_for_live_scans_and_errors():
    inventory = make_inventory("aws", resource("aws_account", "1", root_mfa_enabled=False))
    inventory.account_id = "1"
    inventory.errors.append({"service": "rds", "region": "us-east-1", "error": "AccessDenied"})
    sarif = json.loads(render_sarif(run_rules(inventory, Config())))
    run = sarif["runs"][0]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "aws-account.json"
    assert run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"] == "rds us-east-1: AccessDenied"


class Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = 0
        self.open_tags = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag == "tr" and ("data-sev", "critical") in attrs:
            self.rows += 1
        if tag not in ("meta", "input", "br"):
            self.open_tags.append(tag)

    def handle_endtag(self, tag):
        if self.open_tags and self.open_tags[-1] == tag:
            self.open_tags.pop()
        else:
            self.errors.append(tag)


def test_html_report_is_well_formed_and_escaped(insecure_plan):
    config = Config()
    config.suppressions = [Suppression("S3-004", "parapet-demo-data", "<demo> & co", None)]
    page = render_html(scan(insecure_plan, config))
    parser = Collector()
    parser.feed(page)
    assert parser.errors == []
    assert parser.open_tags == []
    assert parser.rows == 6
    assert "&lt;demo&gt; &amp; co" in page
    assert "<demo>" not in page
    assert "Suppressed findings (1)" in page
    assert page.isascii()


def test_html_report_without_findings(hardened_plan):
    page = render_html(scan(hardened_plan))
    assert "no findings" in page
    assert ">100.0<" in page


def test_table_layout(insecure_plan):
    config = Config()
    config.suppressions = [Suppression("S3-004", "parapet-demo-data", "demo", None)]
    config.disabled_rules = ["S3-008"]
    result = scan(insecure_plan, config)
    text = render_table(result, width=100)
    lines = text.splitlines()
    assert lines[0].startswith("parapet 0.1.0  source: terraform")
    assert "failed 35  suppressed 1" in lines[1]
    assert lines[2] == "critical 6  high 8  medium 13  low 8"
    table = lines[lines.index("") + 1 :]
    assert table[0].startswith("SEVERITY  RULE")
    assert max(len(line) for line in table) <= 100
    assert "suppressed (1):" in text
    assert "S3-004 parapet-demo-data: S3-004 on parapet-demo-data: demo" in text
    wide = render_table(result, width=400).splitlines()
    assert len(wide) < len(lines)


def test_table_with_errors_and_warnings_and_no_findings(hardened_plan):
    result = scan(hardened_plan)
    result.errors.append({"service": "ec2", "region": "eu-west-1", "error": "AccessDenied"})
    result.warnings.append("suppression expired on 2020-01-01: S3-001 on x: y")
    text = render_table(result, width=120)
    assert "no findings" in text
    assert "collector errors (1)" in text
    assert "ec2 eu-west-1: AccessDenied" in text
    assert "warnings:" in text
