import json
from dataclasses import dataclass, field
from pathlib import Path

from parapet.model import ScanResult
from parapet.sources import SourceError


@dataclass
class Diff:
    baseline_origin: str
    current_origin: str
    new: list = field(default_factory=list)
    resolved: list = field(default_factory=list)
    unchanged: int = 0

    def worst_new(self):
        if not self.new:
            return None
        return max(f.severity for f in self.new)

    def to_dict(self) -> dict:
        return {
            "baseline": self.baseline_origin,
            "current": self.current_origin,
            "new": [f.to_dict() for f in self.new],
            "resolved": [f.to_dict() for f in self.resolved],
            "unchanged": self.unchanged,
        }


def load_result(path) -> ScanResult:
    path = Path(path)
    if not path.is_file():
        raise SourceError(f"result file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SourceError(f"{path}: could not read json result ({exc})") from None
    if not isinstance(data, dict) or "findings" not in data:
        raise SourceError(f"{path}: not a parapet json result")
    return ScanResult.from_dict(data)


def diff_results(baseline: ScanResult, current: ScanResult) -> Diff:
    before = {f.key: f for f in baseline.active}
    after = {f.key: f for f in current.active}

    def order(finding):
        return (-int(finding.severity), finding.rule_id, finding.region, finding.resource_id)

    return Diff(
        baseline_origin=baseline.origin,
        current_origin=current.origin,
        new=sorted((after[key] for key in after.keys() - before.keys()), key=order),
        resolved=sorted((before[key] for key in before.keys() - after.keys()), key=order),
        unchanged=len(before.keys() & after.keys()),
    )


def render_diff(diff: Diff) -> str:
    lines = [
        f"baseline: {diff.baseline_origin}",
        f"current:  {diff.current_origin}",
        f"new {len(diff.new)}  resolved {len(diff.resolved)}  unchanged {diff.unchanged}",
    ]
    for label, findings in (("new findings", diff.new), ("resolved findings", diff.resolved)):
        if not findings:
            continue
        lines.append("")
        lines.append(f"{label}:")
        for finding in findings:
            lines.append(
                f"  {finding.severity.label:9} {finding.rule_id:11} {finding.resource_type.removeprefix('aws_')} "
                f"{finding.resource_name or finding.resource_id} ({finding.region}): {finding.message}"
            )
    return "\n".join(lines) + "\n"
