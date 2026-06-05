"""Render a self-contained HTML dashboard from the audit summary + findings."""
from __future__ import annotations

import html
import json


_CAT_LABELS = {
    "security": "Security",
    "redundancy": "Redundancy",
    "tests": "Tests &amp; Correctness",
    "dependencies": "Dependencies",
}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {
    "critical": "#b3001b", "high": "#e8590c", "medium": "#f08c00",
    "low": "#2b8a3e", "info": "#868e96",
}


def _grade_color(v: int) -> str:
    if v >= 85:
        return "#2b8a3e"
    if v >= 70:
        return "#f08c00"
    if v >= 50:
        return "#e8590c"
    return "#b3001b"


def _gauge(value: int, label: str) -> str:
    color = _grade_color(value)
    return f"""
    <div class="gauge">
      <svg viewBox="0 0 120 120">
        <circle cx="60" cy="60" r="52" fill="none" stroke="#2a2a33" stroke-width="12"/>
        <circle cx="60" cy="60" r="52" fill="none" stroke="{color}" stroke-width="12"
          stroke-linecap="round" stroke-dasharray="{value/100*326.7:.1f} 326.7"
          transform="rotate(-90 60 60)"/>
        <text x="60" y="66" text-anchor="middle" font-size="30" fill="#f1f1f4" font-weight="700">{value}</text>
      </svg>
      <div class="gauge-label">{label}</div>
    </div>"""


def render_html(project: str, summary: dict, findings: list[dict]) -> str:
    cats = summary["categories"]
    counts = summary["counts"]
    tool_status = summary.get("tool_status", {})
    stats = summary.get("stats", {})

    gauges = "".join(
        _gauge(cats[c], _CAT_LABELS[c]) for c in ["security", "redundancy", "tests", "dependencies"]
    )

    # severity-sorted findings
    order = {s: i for i, s in enumerate(_SEV_ORDER)}
    findings_sorted = sorted(findings, key=lambda f: order.get(f["severity"], 9))
    rows = ""
    for f in findings_sorted:
        loc = html.escape(f.get("file") or "—")
        if f.get("line"):
            loc += f":{f['line']}"
        rows += f"""
        <tr data-cat="{f['category']}" data-sev="{f['severity']}">
          <td><span class="pill" style="background:{_SEV_COLOR[f['severity']]}">{f['severity']}</span></td>
          <td>{html.escape(_CAT_LABELS.get(f['category'], f['category']))}</td>
          <td class="title">{html.escape(f['title'])}</td>
          <td class="loc">{loc}</td>
          <td class="detail">{html.escape((f.get('detail') or '')[:300])}
            {f"<div class='remed'>Fix: {html.escape(f['remediation'])}</div>" if f.get('remediation') else ''}</td>
          <td class="tool">{html.escape(f.get('tool') or '')}</td>
        </tr>"""

    tools_html = "".join(
        f"<span class='tool-chip {('ok' if v=='ok' else 'off')}'>{html.escape(t)}: {html.escape(v)}</span>"
        for t, v in sorted(tool_status.items())
    )

    stat_chips = "".join(
        f"<span class='stat'>{html.escape(str(k).replace('_',' '))}: <b>{html.escape(str(v))}</b></span>"
        for k, v in stats.items()
    )

    verdict_color = _grade_color(summary["overall"])

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Code Audit — {html.escape(project)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background:#16161a; color:#e9e9ee; padding:32px; }}
  .wrap {{ max-width:1100px; margin:0 auto; }}
  header h1 {{ margin:0 0 4px; font-size:24px; }}
  header .sub {{ color:#9a9aa5; font-size:14px; }}
  .hero {{ display:flex; align-items:center; gap:28px; background:#1e1e26; border:1px solid #2a2a33;
    border-radius:16px; padding:24px; margin:24px 0; }}
  .overall {{ text-align:center; }}
  .overall .num {{ font-size:56px; font-weight:800; color:{verdict_color}; line-height:1; }}
  .overall .of {{ color:#9a9aa5; font-size:14px; }}
  .verdict {{ font-size:20px; font-weight:700; color:{verdict_color}; }}
  .verdict-sub {{ color:#9a9aa5; font-size:13px; margin-top:6px; max-width:480px; }}
  .gauges {{ display:flex; gap:16px; flex-wrap:wrap; margin:0 0 24px; }}
  .gauge {{ background:#1e1e26; border:1px solid #2a2a33; border-radius:14px; padding:14px;
    text-align:center; flex:1; min-width:150px; }}
  .gauge svg {{ width:96px; height:96px; }}
  .gauge-label {{ font-size:13px; color:#c5c5cf; margin-top:4px; }}
  .meta {{ display:flex; flex-wrap:wrap; gap:8px; margin-bottom:20px; }}
  .tool-chip, .stat {{ font-size:12px; padding:4px 10px; border-radius:20px; background:#23232c; border:1px solid #2f2f3a; }}
  .tool-chip.ok {{ border-color:#2b8a3e55; }} .tool-chip.off {{ opacity:.6; }}
  .controls {{ margin:16px 0; display:flex; gap:8px; flex-wrap:wrap; }}
  .controls button {{ background:#23232c; color:#e9e9ee; border:1px solid #2f2f3a;
    padding:6px 14px; border-radius:8px; cursor:pointer; font-size:13px; }}
  .controls button.active {{ background:#3b3b8f; border-color:#5050c0; }}
  table {{ width:100%; border-collapse:collapse; background:#1e1e26; border-radius:12px; overflow:hidden; }}
  th, td {{ text-align:left; padding:10px 12px; font-size:13px; border-bottom:1px solid #2a2a33; vertical-align:top; }}
  th {{ background:#23232c; color:#b9b9c4; font-weight:600; position:sticky; top:0; }}
  .pill {{ color:#fff; padding:2px 9px; border-radius:20px; font-size:11px; text-transform:uppercase; font-weight:700; }}
  .title {{ font-weight:600; }} .loc {{ color:#9a9aa5; font-family:monospace; font-size:12px; }}
  .detail {{ color:#c5c5cf; max-width:380px; }} .remed {{ color:#7fc98f; margin-top:4px; font-size:12px; }}
  .tool {{ color:#868e96; font-size:12px; }}
  .empty {{ text-align:center; padding:40px; color:#7fc98f; }}
</style></head><body><div class="wrap">
<header>
  <h1>Code Audit Report</h1>
  <div class="sub">{html.escape(project)} · generated by codeaudit</div>
</header>

<div class="hero">
  <div class="overall"><div class="num">{summary['overall']}</div><div class="of">/ 100</div></div>
  <div>
    <div class="verdict">{html.escape(summary['verdict'])}</div>
    <div class="verdict-sub">Weighted across security, redundancy, tests, and dependencies.
      A single critical issue (e.g. an exposed secret or active CVE) caps the verdict regardless of other scores.</div>
  </div>
</div>

<div class="gauges">{gauges}</div>

<div class="meta">{tools_html}{stat_chips}</div>

<div class="controls" id="filters">
  <button data-f="all" class="active">All ({len(findings)})</button>
  <button data-f="critical">Critical ({sum(1 for f in findings if f['severity']=='critical')})</button>
  <button data-f="high">High ({sum(1 for f in findings if f['severity']=='high')})</button>
  <button data-f="security">Security</button>
  <button data-f="redundancy">Redundancy</button>
  <button data-f="tests">Tests</button>
  <button data-f="dependencies">Dependencies</button>
</div>

{"<div class='empty'>No findings. Either the codebase is clean or scanners are not installed — check the tool chips above.</div>" if not findings else f'''
<table id="tbl"><thead><tr>
  <th>Severity</th><th>Category</th><th>Issue</th><th>Location</th><th>Detail</th><th>Tool</th>
</tr></thead><tbody>{rows}</tbody></table>'''}

<script>
const btns = document.querySelectorAll('#filters button');
btns.forEach(b => b.onclick = () => {{
  btns.forEach(x => x.classList.remove('active')); b.classList.add('active');
  const f = b.dataset.f;
  document.querySelectorAll('#tbl tbody tr').forEach(tr => {{
    const show = f==='all' || tr.dataset.sev===f || tr.dataset.cat===f;
    tr.style.display = show ? '' : 'none';
  }});
}});
</script>
</div></body></html>"""
