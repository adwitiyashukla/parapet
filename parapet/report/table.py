import shutil
import textwrap

from parapet.model import ScanResult

COLUMNS = ("SEVERITY", "RULE", "TYPE", "RESOURCE", "REGION", "MESSAGE")
MAX_WIDTHS = {"TYPE": 30, "RESOURCE": 36, "REGION": 14}
MIN_MESSAGE_WIDTH = 36


def clip(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def summary_lines(result: ScanResult) -> list:
    counts = result.counts()
    header = f"parapet {result.version}  source: {result.source}  origin: {result.origin}"
    if result.account_id:
        header += f"  account: {result.account_id}"
    if result.regions:
        header += f"  regions: {', '.join(result.regions)}"
    return [
        header,
        f"resources {result.resource_count}  rules {result.rule_count}  checks {result.passed + len(result.active)}"
        f"  passed {result.passed}  failed {len(result.active)}  suppressed {len(result.suppressed)}  score {result.score}",
        "  ".join(f"{label} {counts[label]}" for label in ("critical", "high", "medium", "low")),
    ]


def column_widths(rows: list, width: int) -> list:
    widths = []
    for index, column in enumerate(COLUMNS[:-1]):
        longest = max(len(column), *(len(row[index]) for row in rows))
        widths.append(min(longest, MAX_WIDTHS.get(column, longest)))
    gaps = 2 * (len(COLUMNS) - 1)
    available = width - gaps - MIN_MESSAGE_WIDTH
    for index, minimum in ((2, 16), (3, 16), (2, 10), (3, 12)):
        excess = sum(widths) - available
        if excess <= 0:
            break
        widths[index] -= min(excess, max(widths[index] - minimum, 0))
    widths.append(max(MIN_MESSAGE_WIDTH, width - sum(widths) - gaps))
    return widths


def format_row(row: tuple, widths: list) -> list:
    cells = [clip(cell, widths[i]).ljust(widths[i]) for i, cell in enumerate(row[:-1])]
    prefix = "  ".join(cells) + "  "
    message_lines = textwrap.wrap(row[-1], widths[-1], break_on_hyphens=False) or [""]
    lines = [(prefix + message_lines[0]).rstrip()]
    indent = " " * len(prefix)
    lines.extend((indent + line).rstrip() for line in message_lines[1:])
    return lines


def render_table(result: ScanResult, width: int = 0) -> str:
    if width <= 0:
        width = shutil.get_terminal_size((140, 40)).columns
    lines = summary_lines(result)
    rows = [
        (
            f.severity.label,
            f.rule_id,
            f.resource_type.removeprefix("aws_"),
            f.resource_name or f.resource_id,
            f.region,
            f.message,
        )
        for f in result.active
    ]
    lines.append("")
    if rows:
        widths = column_widths(rows, width)
        lines.extend(format_row(COLUMNS, widths))
        for row in rows:
            lines.extend(format_row(row, widths))
    else:
        lines.append("no findings")
    if result.suppressed:
        lines.append("")
        lines.append(f"suppressed ({len(result.suppressed)}):")
        for finding in result.suppressed:
            lines.append(f"  {finding.rule_id} {finding.resource_name or finding.resource_id}: {finding.suppressed_by}")
    if result.warnings:
        lines.append("")
        lines.append("warnings:")
        lines.extend(f"  {warning}" for warning in result.warnings)
    if result.errors:
        lines.append("")
        lines.append(f"collector errors ({len(result.errors)}), affected checks were skipped:")
        lines.extend(f"  {e['service']} {e['region']}: {e['error']}" for e in result.errors)
    return "\n".join(lines) + "\n"
