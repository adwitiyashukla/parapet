from html import escape

from parapet.model import ScanResult

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>parapet report</title>
<style>
:root { --bg: #f6f7f9; --card: #ffffff; --text: #1d2430; --muted: #5d6675; --line: #dde2ea;
  --critical: #a4262c; --high: #d9541e; --medium: #c48a00; --low: #3b7dd8; --pass: #2e8b57; }
* { box-sizing: border-box; }
body { margin: 0; font-family: Segoe UI, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); }
header { padding: 24px 32px 8px; }
h1 { margin: 0 0 4px; font-size: 24px; }
.meta { color: var(--muted); font-size: 14px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; padding: 16px 32px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px 18px; min-width: 120px; }
.card .num { font-size: 26px; font-weight: 600; }
.card .lbl { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }
.card.critical .num { color: var(--critical); } .card.high .num { color: var(--high); }
.card.medium .num { color: var(--medium); } .card.low .num { color: var(--low); } .card.score .num { color: var(--pass); }
.controls { display: flex; flex-wrap: wrap; gap: 8px; padding: 0 32px 12px; align-items: center; }
.controls button { border: 1px solid var(--line); background: var(--card); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 13px; }
.controls button.on { background: var(--text); color: #fff; border-color: var(--text); }
.controls input { padding: 6px 10px; border: 1px solid var(--line); border-radius: 6px; font-size: 13px; min-width: 260px; }
main { padding: 0 32px 32px; }
table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line); border-radius: 8px; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: #eef1f5; font-weight: 600; cursor: pointer; user-select: none; }
td:nth-child(4) { white-space: nowrap; }
tr.hidden { display: none; }
.sev { display: inline-block; padding: 2px 8px; border-radius: 10px; color: #fff; font-size: 11px; text-transform: uppercase; }
.sev.critical { background: var(--critical); } .sev.high { background: var(--high); }
.sev.medium { background: var(--medium); } .sev.low { background: var(--low); } .sev.info { background: var(--muted); }
.fix { color: var(--muted); font-size: 12px; margin-top: 4px; }
.frameworks { color: var(--muted); font-size: 11px; }
.section { margin-top: 24px; }
.section h2 { font-size: 16px; margin: 0 0 8px; }
.section ul { margin: 0; padding-left: 18px; font-size: 13px; color: var(--muted); }
code { font-family: Consolas, Menlo, monospace; font-size: 12px; }
</style>
</head>
<body>
<header>
<h1>parapet scan report</h1>
<div class="meta">__META__</div>
</header>
<div class="cards">__CARDS__</div>
<div class="controls">
<button class="on" data-sev="all">all</button>
<button data-sev="critical">critical</button>
<button data-sev="high">high</button>
<button data-sev="medium">medium</button>
<button data-sev="low">low</button>
<input id="search" type="search" placeholder="filter by rule, resource, region or text">
<span class="meta" id="count"></span>
</div>
<main>
<table id="findings">
<thead><tr><th data-col="0">Severity</th><th data-col="1">Rule</th><th data-col="2">Resource</th><th data-col="3">Region</th><th data-col="4">Finding</th></tr></thead>
<tbody>
__ROWS__
</tbody>
</table>
__EXTRA__
</main>
<script>
(function () {
  var rows = Array.prototype.slice.call(document.querySelectorAll('#findings tbody tr'));
  var buttons = Array.prototype.slice.call(document.querySelectorAll('.controls button'));
  var search = document.getElementById('search');
  var count = document.getElementById('count');
  var severity = 'all';
  function apply() {
    var needle = search.value.toLowerCase();
    var shown = 0;
    rows.forEach(function (row) {
      var okSeverity = severity === 'all' || row.getAttribute('data-sev') === severity;
      var okText = !needle || row.textContent.toLowerCase().indexOf(needle) !== -1;
      var visible = okSeverity && okText;
      row.className = visible ? '' : 'hidden';
      if (visible) { shown += 1; }
    });
    count.textContent = shown + ' of ' + rows.length + ' findings shown';
  }
  buttons.forEach(function (button) {
    button.addEventListener('click', function () {
      severity = button.getAttribute('data-sev');
      buttons.forEach(function (b) { b.className = b === button ? 'on' : ''; });
      apply();
    });
  });
  search.addEventListener('input', apply);
  var order = {critical: 0, high: 1, medium: 2, low: 3, info: 4};
  Array.prototype.slice.call(document.querySelectorAll('#findings th')).forEach(function (th) {
    var asc = true;
    th.addEventListener('click', function () {
      var col = parseInt(th.getAttribute('data-col'), 10);
      var body = document.querySelector('#findings tbody');
      rows.sort(function (a, b) {
        var x = a.children[col].textContent.trim().toLowerCase();
        var y = b.children[col].textContent.trim().toLowerCase();
        if (col === 0) { x = order[x]; y = order[y]; }
        if (x < y) { return asc ? -1 : 1; }
        if (x > y) { return asc ? 1 : -1; }
        return 0;
      });
      asc = !asc;
      rows.forEach(function (row) { body.appendChild(row); });
    });
  });
  apply();
})();
</script>
</body>
</html>
"""


def card(label: str, value, css: str = "") -> str:
    return f'<div class="card {css}"><div class="num">{escape(str(value))}</div><div class="lbl">{escape(label)}</div></div>'


def render_html(result: ScanResult) -> str:
    counts = result.counts()
    meta = [
        f"source {escape(result.source)}",
        f"origin {escape(result.origin)}",
    ]
    if result.account_id:
        meta.append(f"account {escape(result.account_id)}")
    if result.regions:
        meta.append("regions " + escape(", ".join(result.regions)))
    meta.append(f"started {escape(result.started_at)}")
    meta.append(f"parapet {escape(result.version)}")
    cards = [
        card("score", result.score, "score"),
        card("resources", result.resource_count),
        card("checks passed", result.passed),
        card("findings", len(result.active)),
        card("critical", counts["critical"], "critical"),
        card("high", counts["high"], "high"),
        card("medium", counts["medium"], "medium"),
        card("low", counts["low"], "low"),
        card("suppressed", len(result.suppressed)),
    ]
    rows = []
    for finding in result.active:
        frameworks = []
        if finding.cis:
            frameworks.append("CIS " + ", ".join(finding.cis))
        if finding.fsbp:
            frameworks.append("FSBP " + ", ".join(finding.fsbp))
        rows.append(
            f'<tr data-sev="{finding.severity.label}">'
            f'<td><span class="sev {finding.severity.label}">{finding.severity.label}</span></td>'
            f'<td><code>{escape(finding.rule_id)}</code><div class="frameworks">{escape(" / ".join(frameworks))}</div></td>'
            f'<td>{escape(finding.resource_name or finding.resource_id)}<div class="frameworks">{escape(finding.resource_type)}</div></td>'
            f"<td>{escape(finding.region)}</td>"
            f"<td><strong>{escape(finding.title)}</strong><div>{escape(finding.message)}</div>"
            f'<div class="fix">fix: {escape(finding.remediation)}</div></td>'
            "</tr>"
        )
    if not rows:
        rows.append('<tr data-sev="info"><td colspan="5">no findings</td></tr>')
    extra = []
    if result.suppressed:
        items = "".join(
            f"<li><code>{escape(f.rule_id)}</code> {escape(f.resource_name or f.resource_id)}: {escape(f.suppressed_by)}</li>"
            for f in result.suppressed
        )
        extra.append(
            f'<div class="section"><h2>Suppressed findings ({len(result.suppressed)})</h2><ul>{items}</ul></div>'
        )
    if result.warnings:
        items = "".join(f"<li>{escape(w)}</li>" for w in result.warnings)
        extra.append(f'<div class="section"><h2>Warnings</h2><ul>{items}</ul></div>')
    if result.errors:
        items = "".join(
            f"<li>{escape(e['service'])} {escape(e['region'])}: {escape(e['error'])}</li>" for e in result.errors
        )
        extra.append(f'<div class="section"><h2>Collector errors ({len(result.errors)})</h2><ul>{items}</ul></div>')
    return (
        PAGE.replace("__META__", " | ".join(meta))
        .replace("__CARDS__", "".join(cards))
        .replace("__ROWS__", "\n".join(rows))
        .replace("__EXTRA__", "\n".join(extra))
    )
