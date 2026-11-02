import json
import subprocess
import sys

import pytest

from parapet.cli import main


def test_plan_scan_writes_every_format(insecure_plan, tmp_path, capsys):
    code = main(
        [
            "scan",
            "plan",
            str(insecure_plan),
            "--json",
            str(tmp_path / "out" / "r.json"),
            "--sarif",
            str(tmp_path / "r.sarif"),
            "--html",
            str(tmp_path / "r.html"),
        ]
    )
    assert code == 1
    captured = capsys.readouterr()
    assert "failed 36" in captured.out
    assert "wrote" in captured.err
    assert json.loads((tmp_path / "out" / "r.json").read_text(encoding="utf-8"))["summary"]["failed"] == 36
    assert json.loads((tmp_path / "r.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert "<title>parapet report</title>" in (tmp_path / "r.html").read_text(encoding="utf-8")


def test_fail_on_controls_exit_code(insecure_plan, hardened_plan, capsys):
    assert main(["scan", "plan", str(insecure_plan), "--fail-on", "none", "--quiet"]) == 0
    assert capsys.readouterr().out == ""
    assert main(["scan", "plan", str(insecure_plan), "--fail-on", "critical", "--quiet"]) == 1
    assert main(["scan", "plan", str(hardened_plan), "--fail-on", "low"]) == 0
    assert "no findings" in capsys.readouterr().out
    assert main(["scan", "plan", str(insecure_plan), "--fail-on", "urgent"]) == 2
    assert "unknown severity" in capsys.readouterr().err


def test_config_file_and_suppressions(insecure_plan, tmp_path, capsys):
    config = tmp_path / "config.toml"
    config.write_text(
        '[scan]\nfail_on = "critical"\n\n[rules]\ndisabled = ["S3-007"]\n\n'
        '[[suppressions]]\nrule = "*"\nresource = "parapet-demo-data"\nreason = "demo bucket"\n',
        encoding="utf-8",
    )
    assert main(["scan", "plan", str(insecure_plan), "--config", str(config)]) == 1
    out = capsys.readouterr().out
    assert "suppressed 6" in out
    assert "rules 46" in out
    assert main(["scan", "plan", str(insecure_plan), "--config", str(config), "--no-suppress", "--quiet"]) == 1
    assert main(["scan", "plan", str(insecure_plan), "--config", str(tmp_path / "missing.toml")]) == 2
    assert "config file not found" in capsys.readouterr().err


def test_default_config_is_picked_up_from_cwd(insecure_plan, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.toml").write_text('[scan]\nfail_on = "none"\n', encoding="utf-8")
    assert main(["scan", "plan", str(insecure_plan), "--quiet"]) == 0
    (tmp_path / "config.toml").write_text("[scan]\nworkers = 'many'\n", encoding="utf-8")
    assert main(["scan", "plan", str(insecure_plan), "--quiet"]) == 2
    assert "workers" in capsys.readouterr().err


def test_missing_plan_is_a_usage_error(tmp_path, capsys):
    assert main(["scan", "plan", str(tmp_path / "nope.json")]) == 2
    assert "plan file not found" in capsys.readouterr().err


def test_diff_command(insecure_plan, hardened_plan, tmp_path, capsys):
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    assert main(["scan", "plan", str(hardened_plan), "--json", str(before), "--quiet"]) == 0
    assert main(["scan", "plan", str(insecure_plan), "--json", str(after), "--quiet", "--fail-on", "none"]) == 0
    capsys.readouterr()
    assert main(["diff", str(before), str(after), "--json", str(tmp_path / "diff.json")]) == 1
    out = capsys.readouterr().out
    assert "new 36  resolved 0  unchanged 0" in out
    assert json.loads((tmp_path / "diff.json").read_text(encoding="utf-8"))["unchanged"] == 0
    assert main(["diff", str(after), str(before)]) == 0
    assert "resolved 36" in capsys.readouterr().out
    assert main(["diff", str(before), str(after), "--fail-on", "none"]) == 0
    assert main(["diff", str(before), str(tmp_path / "missing.json")]) == 2


def test_rules_listing(capsys, tmp_path):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "47 rules" in out
    assert "S3-001" in out and "CONFIG-001" in out
    config = tmp_path / "config.toml"
    config.write_text('[rules]\ndisabled = ["S3-001"]\n', encoding="utf-8")
    assert main(["rules", "--config", str(config), "--json"]) == 0
    listing = json.loads(capsys.readouterr().out)
    assert len(listing) == 46
    assert listing[0]["id"] == "S3-002"
    assert listing[0]["fsbp"] == ["S3.2", "S3.3"]


def test_aws_scan_without_credentials_fails_cleanly(monkeypatch, capsys):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "")
    monkeypatch.delenv("AWS_SESSION_TOKEN")
    monkeypatch.delenv("AWS_SECURITY_TOKEN")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/credentials")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/config")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    assert main(["scan", "aws", "--regions", "us-east-1", "--workers", "1"]) == 2
    captured = capsys.readouterr()
    assert "scanning account via default credentials in us-east-1" in captured.err
    assert "could not connect to AWS" in captured.err


def test_module_entry_point(insecure_plan):
    completed = subprocess.run(
        [sys.executable, "-m", "parapet", "scan", "plan", str(insecure_plan), "--quiet", "--fail-on", "none"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    version = subprocess.run(
        [sys.executable, "-m", "parapet", "--version"], capture_output=True, text=True, check=False
    )
    assert version.stdout.strip() == "parapet 0.1.0"


def test_argument_errors_exit_with_usage_code():
    with pytest.raises(SystemExit) as info:
        main(["scan"])
    assert info.value.code == 2
