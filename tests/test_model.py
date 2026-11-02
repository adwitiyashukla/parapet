import pytest

from parapet.model import UNKNOWN, Finding, Resource, ScanResult, Severity, is_unknown


def test_severity_parse_and_order():
    assert Severity.parse("High") is Severity.HIGH
    assert Severity.CRITICAL > Severity.LOW
    assert Severity.MEDIUM.label == "medium"
    with pytest.raises(ValueError):
        Severity.parse("urgent")


def test_resource_get_walks_nested_paths():
    res = Resource(
        type="aws_instance", id="i-1", attrs={"metadata_options": [{"http_tokens": "required"}], "deep": UNKNOWN}
    )
    assert res.get("metadata_options.0.http_tokens") == "required"
    assert res.get("metadata_options.5.http_tokens", "none") == "none"
    assert res.get("missing", 7) == 7
    assert is_unknown(res.get("deep.anything"))
    assert res.label == "i-1"


def make_finding(rule_id="S3-001", severity=Severity.HIGH, status="fail"):
    return Finding(
        rule_id=rule_id,
        title="t",
        severity=severity,
        resource_type="aws_s3_bucket",
        resource_id="b",
        resource_name="b",
        region="us-east-1",
        message="m",
        remediation="r",
        cis=["2.1.4"],
        fsbp=["S3.8"],
        status=status,
    )


def test_finding_roundtrip():
    finding = make_finding()
    data = finding.to_dict()
    assert data["severity"] == "high"
    assert Finding.from_dict(data) == finding
    assert finding.key == ("S3-001", "aws_s3_bucket", "b", "us-east-1")
    assert finding.service == "s3"


def test_scan_result_summary_and_roundtrip():
    findings = [
        make_finding(),
        make_finding("S3-004", Severity.LOW),
        make_finding("S3-006", Severity.LOW, "suppressed"),
    ]
    result = ScanResult(
        "terraform", "plan.json", "", ["us-east-1"], "2026-01-01T00:00:00+00:00", 0.5, 10, 47, 6, findings
    )
    assert len(result.active) == 2
    assert len(result.suppressed) == 1
    assert result.counts()["high"] == 1
    assert result.counts()["low"] == 1
    assert result.score == 75.0
    assert result.worst() is Severity.HIGH
    restored = ScanResult.from_dict(result.to_dict())
    assert restored.findings == findings
    assert restored.passed == 6
    assert restored.score == 75.0


def test_empty_result_scores_full_marks():
    result = ScanResult("aws", "x", "1", [], "", 0.0, 0, 47, 0, [])
    assert result.score == 100.0
    assert result.worst() is None
