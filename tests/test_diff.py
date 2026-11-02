import json

import pytest

from parapet.config import Config
from parapet.diff import diff_results, load_result, render_diff
from parapet.engine import run_rules
from parapet.model import Severity
from parapet.report import render_json
from parapet.sources import SourceError
from parapet.sources.terraform import load_plan


def test_diff_between_plans(insecure_plan, hardened_plan, tmp_path):
    before = run_rules(load_plan(str(insecure_plan)), Config())
    after = run_rules(load_plan(str(hardened_plan)), Config())
    (tmp_path / "before.json").write_text(render_json(before), encoding="utf-8")
    (tmp_path / "after.json").write_text(render_json(after), encoding="utf-8")
    diff = diff_results(load_result(tmp_path / "before.json"), load_result(tmp_path / "after.json"))
    assert diff.new == []
    assert len(diff.resolved) == 36
    assert diff.unchanged == 0
    assert diff.worst_new() is None
    reverse = diff_results(after, before)
    assert len(reverse.new) == 36
    assert reverse.worst_new() is Severity.CRITICAL
    assert reverse.new[0].severity is Severity.CRITICAL
    text = render_diff(reverse)
    assert "new 36  resolved 0  unchanged 0" in text
    assert "new findings:" in text
    assert "resolved findings:" not in text
    data = reverse.to_dict()
    assert data["baseline"] == str(hardened_plan)
    assert len(data["new"]) == 36


def test_diff_counts_unchanged(insecure_plan):
    result = run_rules(load_plan(str(insecure_plan)), Config())
    diff = diff_results(result, result)
    assert diff.unchanged == 36 and diff.new == [] and diff.resolved == []


def test_load_result_errors(tmp_path):
    with pytest.raises(SourceError):
        load_result(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("nope", encoding="utf-8")
    with pytest.raises(SourceError):
        load_result(bad)
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"runs": []}), encoding="utf-8")
    with pytest.raises(SourceError):
        load_result(other)
