#!/usr/bin/env python3
"""Generate an executive remediation report from a scored APT pipeline run.

This is the business-facing companion to `score_run.py`. Where the scorer
produces the technical scoresheet (detection/exploitation/precision by OWASP
category and difficulty), this tool turns a completed run into a report an
executive or sponsor can read: current security posture, the risk the findings
represent in business terms, what was *proven* exploitable versus merely
*potential*, and a prioritized remediation roadmap with references.

It never re-derives the metrics by hand. It calls `score_run.score()` so every
number here is the same number the technical scoresheet reports; this tool only
*reframes* that result for a non-technical reader and adds a severity/risk model
on top of the answer key.

Outputs, written into the run directory:

  <run>/exec-report.md     the executive remediation report (Markdown)
  <run>/exec-report.html   the same report as a styled, standalone HTML page
                           (self-contained; open in a browser or hand to a sponsor)

Inputs it reads from the run directory (optional, except that the scorer needs
at least one of the vulnerability-assessment or exploitation findings files):

  vuln_assessment/findings.json   what the agent reported   (scorer input)
  exploitation/findings.json      what the agent confirmed  (scorer input)
  mitigation/findings.json        the agent's remediation playbook, if the
                                  mitigation phase ran (its recommendations are
                                  merged into the roadmap)
  run.json                        the run manifest (cost, tokens, model), if present

Usage:
  python3 vuln-list/exec_report.py vuln-list/examples/sample-run --mode black-box
  python3 vuln-list/exec_report.py Tooling/runs/<run-id> --mode white-box \
      --client "Acme Corp" --engagement "Q4 2026 AI Pentest"

Requires PyYAML (same dependency as score_run.py).
"""
from __future__ import annotations

import argparse
import html
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Reuse the technical scorer so the executive numbers can never drift from it.
import score_run

_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low")
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(_SEVERITY_ORDER)}
_SEV_COLOR = {
    "Critical": "#b4232a",
    "High": "#d1621a",
    "Medium": "#b8900a",
    "Low": "#5a7d3a",
}

# Higher values represent more business damage if the category is abused.
_OWASP_IMPACT = {
    "A01": 4,  # Broken Access Control — direct data/authz compromise
    "A02": 4,  # Cryptographic Failures — exposure of protected data
    "A03": 5,  # Injection — often full data/system compromise
    "A04": 3,  # Insecure Design
    "A05": 3,  # Security Misconfiguration
    "A06": 3,  # Vulnerable Components
    "A07": 4,  # Identification & Auth Failures — account takeover
    "A08": 4,  # Software & Data Integrity Failures
    "A09": 2,  # Logging & Monitoring Failures — enabler, not direct loss
    "A10": 4,  # SSRF
}


# --- severity and business-risk model ------------------------------------
#
# Juice Shop's `difficulty` (1-6) measures how hard a vulnerability is to
# exploit, not how much damage it can cause. Severity combines OWASP-based
# impact with whether the exploit was proven by the oracle.

def _owasp_code(entry: Mapping[str, Any]) -> str | None:
    owasp = entry.get("owasp_top10")
    if not owasp:
        return None
    return owasp.split(":", 1)[0].strip().upper()


def impact_tier(entry: Mapping[str, Any]) -> int:
    """Return the 1-5 business-impact tier for an answer-key entry."""
    return _OWASP_IMPACT.get(_owasp_code(entry) or "", 3)


def severity_of(entry: Mapping[str, Any], proven: bool) -> str:
    """Map impact and exploit proof to Critical, High, Medium, or Low."""
    tier = impact_tier(entry)
    if proven:
        if tier >= 5:
            return "Critical"
        if tier >= 3:
            return "High"
        return "Medium"

    if tier >= 4:
        return "High"
    if tier >= 3:
        return "Medium"
    return "Low"


# --- input loading --------------------------------------------------------


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def load_mitigations(run_dir: Path) -> dict[str, dict[str, Any]]:
    """Agent's remediation playbook keyed by vuln_id, if the mitigation phase ran."""
    data = _load_json(run_dir / "mitigation" / "findings.json")
    if not data:
        return {}
    items = (data.get("payload") or {}).get("items") or []
    return {it["vuln_id"]: it for it in items if it.get("vuln_id")}


def load_manifest(run_dir: Path) -> dict[str, Any]:
    """Cost/token/model info from the run manifest, best-effort."""
    data = _load_json(run_dir / "run.json") or {}
    manifest = {}
    for k in ("model", "mode", "target", "total_cost_usd", "total_tokens", "cost_usd", "cost"):
        if k in data:
            manifest[k] = data[k]
    if "total_cost_usd" not in manifest:
        for alt in ("cost_usd", "cost"):
            if alt in manifest:
                manifest["total_cost_usd"] = manifest[alt]
                break
    return manifest


# --- build the ranked finding set -----------------------------------------


def build_findings(run_dir: Path, result: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Produce the ranked list of answer-key-backed findings for the report.

    Each item: key, name, category, owasp, difficulty, severity, proven(bool),
    impact tier, remediation reference, and the agent's playbook recommendation
    if it produced one for the matching vuln."""
    answer_key = result["answer_key"]
    detected = result["detected"]
    exploited = result["exploited"]

    mitigations = load_mitigations(run_dir)

    # Connect attempted vuln IDs to challenge keys for matching playbook advice.
    exploit_phase = _load_json(run_dir / "exploitation" / "findings.json")
    key_for_vuln: dict[str, str] = {}
    rec_for_key: dict[str, dict] = {}
    if exploit_phase:
        for a in (exploit_phase.get("payload") or {}).get("attempts", []):
            if a.get("challenge_key") and a.get("vuln_id"):
                key_for_vuln[a["vuln_id"]] = a["challenge_key"]
    for vuln_id, key in key_for_vuln.items():
        if vuln_id in mitigations:
            rec_for_key[key] = mitigations[vuln_id]

    findings = []
    for key in sorted(detected | exploited):
        entry = answer_key.get(key)
        if not entry:
            continue
        proven = key in exploited
        sev = severity_of(entry, proven)
        ref = entry.get("mitigation_url")
        if not ref:
            rf = entry.get("reference_fix")
            if isinstance(rf, dict):
                ref = rf.get("explanation")
        findings.append({
            "key": key,
            "name": entry.get("name", key),
            "category": entry.get("category", ""),
            "owasp": entry.get("owasp_top10") or "",
            "difficulty": entry.get("difficulty"),
            "severity": sev,
            "proven": proven,
            "impact": impact_tier(entry),
            "reference": ref,
            "agent_recommendation": (rec_for_key.get(key) or {}).get("recommendation"),
        })

    # Rank: severity band, then proven before potential, then impact tier.
    findings.sort(
        key=lambda finding: (
            _SEVERITY_RANK[finding["severity"]],
            not finding["proven"],
            -finding["impact"],
            finding["name"],
        )
    )
    return findings


def posture(
    result: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
) -> tuple[str, str]:
    """A one-word posture label and a one-paragraph plain-language verdict."""
    graded = result["graded"]
    exploited = result["exploited"] & graded
    proven_critical = sum(1 for f in findings if f["severity"] == "Critical" and f["proven"])
    proven_high = sum(1 for f in findings if f["severity"] == "High" and f["proven"])

    if proven_critical:
        label = "Critical exposure"
    elif proven_high:
        label = "High exposure"
    elif exploited:
        label = "Moderate exposure"
    else:
        label = "Limited exposure"

    n_exploited = len(exploited)
    n_graded = len(graded)
    verdict = (
        f"The automated engagement confirmed {n_exploited} exploitable "
        f"{'issue' if n_exploited == 1 else 'issues'} against the target, out of "
        f"{n_graded} assessed. "
    )
    if proven_critical or proven_high:
        verdict += (
            "Several carry high business impact and were proven end to end, meaning "
            "an attacker following the same steps would succeed today. These should be "
            "scheduled for remediation ahead of lower-severity items below."
        )
    elif n_exploited:
        verdict += (
            "The confirmed issues are of moderate impact; none reached the critical "
            "tier in this run. Remediating them closes the paths the engagement proved."
        )
    else:
        verdict += (
            "No issue was proven exploitable end to end in this run. The potential "
            "findings below still warrant review, as coverage is not exhaustive."
        )
    return label, verdict


# --- render: Markdown ------------------------------------------------------


def _sev_counts(findings: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in _SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1
    return counts


def _missed_keys(result: Mapping[str, Any]) -> list[str]:
    """Return undetected graded keys, ordered by business impact."""
    answer_key = result["answer_key"]
    return sorted(
        result["graded"] - result["detected"],
        key=lambda key: (-impact_tier(answer_key[key]), answer_key[key]["name"]),
    )


def render_markdown(
    result: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
    meta: Mapping[str, Any],
) -> str:
    graded = result["graded"]
    detected = result["detected"] & graded
    exploited = result["exploited"] & graded
    label, verdict = posture(result, findings)
    counts = _sev_counts(findings)
    manifest = meta["manifest"]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    det_pct = f"{100 * len(detected) / len(graded):.0f}%" if graded else "n/a"
    exp_pct = f"{100 * len(exploited) / len(graded):.0f}%" if graded else "n/a"

    lines = ["# Executive Remediation Report", ""]
    if meta.get("client"):
        lines.append(f"**Client:** {meta['client']}  ")
    if meta.get("engagement"):
        lines.append(f"**Engagement:** {meta['engagement']}  ")
    lines.extend([
        f"**Target:** {manifest.get('target', 'authorized web application')}  ",
        f"**Assessment mode:** {meta['mode']}  ",
        "**Method:** Autonomous AI-driven penetration test (APT pipeline)  ",
        f"**Date:** {today}",
        "",
        "---",
        "",
    ])

    # Executive summary
    lines.extend([
        "## Executive summary",
        "",
        f"**Overall security posture: {label}.**",
        "",
        verdict,
        "",
        "This assessment was carried out by an autonomous AI agent working through "
        "the standard penetration-test phases. Every exploited issue listed here was "
        "independently confirmed by the application's own records — it reflects what "
        "the agent actually achieved, not what it merely suspected.",
        "",
    ])

    # Risk at a glance
    lines.extend([
        "## Risk at a glance",
        "",
        "| Severity | Findings | Of which proven exploitable |",
        "|---|---|---|",
    ])
    for severity in _SEVERITY_ORDER:
        proven = sum(
            1
            for finding in findings
            if finding["severity"] == severity and finding["proven"]
        )
        lines.append(f"| {severity} | {counts[severity]} | {proven} |")
    lines.extend([
        "",
        "| Coverage metric | Result | What it means |",
        "|---|---|---|",
        f"| Issues confirmed exploitable | {len(exploited)} of {len(graded)} ({exp_pct}) | "
        "Proven end to end against the live target |",
        f"| Issues identified | {len(detected)} of {len(graded)} ({det_pct}) | "
        "Flagged by the agent as likely vulnerable |",
    ])
    if manifest.get("total_cost_usd") is not None:
        lines.append(
            f"| Cost of this assessment | ${float(manifest['total_cost_usd']):.2f} | "
            "Compute cost of the full automated run |"
        )
    lines.append("")

    # Priority remediation roadmap
    lines.extend([
        "## Priority remediation roadmap",
        "",
        "Findings are ordered by business risk — highest first. *Proven* means the "
        "engagement exploited the issue end to end; *potential* means it was identified "
        "but not confirmed in this run. Address proven, higher-severity items first.",
        "",
    ])
    if not findings:
        lines.extend(["_No answer-key-backed findings were produced for this run._", ""])
    else:
        for index, finding in enumerate(findings, 1):
            status = "Proven exploitable" if finding["proven"] else "Potential"
            lines.extend([
                f"### {index}. {finding['name']} — {finding['severity']}",
                "",
                f"- **Status:** {status}",
            ])
            if finding["owasp"]:
                lines.append(
                    f"- **Category:** {finding['owasp']} ({finding['category']})"
                )
            else:
                lines.append(f"- **Category:** {finding['category']}")
            lines.append(
                f"- **Exploitation difficulty:** {finding['difficulty']}/6"
            )
            recommendation = finding.get("agent_recommendation")
            if recommendation:
                lines.append(f"- **Recommended remediation:** {recommendation}")
            elif finding.get("reference"):
                lines.append(
                    f"- **Recommended remediation:** {finding['reference']}"
                )
            else:
                lines.append(
                    "- **Recommended remediation:** See the technical report for "
                    "detailed guidance."
                )
            lines.append("")

    # What a human would add
    missed = _missed_keys(result)
    lines.extend([
        "## Residual risk — what this assessment did not cover",
        "",
    ])
    if missed:
        lines.extend([
            f"The engagement did not identify {len(missed)} known issue"
            f"{'s' if len(missed) != 1 else ''} in the assessed set. A traditional "
            "pentester, or a follow-up run, would additionally examine these. The "
            "highest-impact examples:",
            "",
        ])
        for key in missed[:8]:
            entry = result["answer_key"][key]
            lines.append(
                f"- **{entry['name']}** — "
                f"{entry.get('owasp_top10') or entry['category']}"
            )
        if len(missed) > 8:
            lines.append(
                f"- …and {len(missed) - 8} more (see the technical scoresheet)."
            )
    else:
        lines.append("The engagement identified every issue in the assessed set.")
    lines.append("")

    lines.extend([
        "---",
        "",
        "*This executive report is generated from the same scored results as the "
        "technical scoresheet (`score.csv` / `score-report.md`); the figures are "
        "identical. Severity reflects business impact (OWASP category) combined with "
        "whether the issue was proven exploitable, and is distinct from Juice Shop's "
        "exploitation-difficulty rating.*",
        "",
    ])
    return "\n".join(lines)


# --- render: HTML ----------------------------------------------------------


def render_html(
    run_dir: Path,
    result: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
    meta: Mapping[str, Any],
) -> str:
    graded = result["graded"]
    detected = result["detected"] & graded
    exploited = result["exploited"] & graded
    label, verdict = posture(result, findings)
    counts = _sev_counts(findings)
    manifest = meta["manifest"]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    det_pct = f"{100 * len(detected) / len(graded):.0f}%" if graded else "n/a"
    exp_pct = f"{100 * len(exploited) / len(graded):.0f}%" if graded else "n/a"

    def esc(value: Any) -> str:
        return html.escape(str(value))

    # Severity bar segments (only non-empty bands).
    total = sum(counts.values()) or 1
    bar = "".join(
        f'<span class="seg" style="width:{100*counts[s]/total:.1f}%;background:{_SEV_COLOR[s]}" '
        f'title="{s}: {counts[s]}"></span>'
        for s in _SEVERITY_ORDER if counts[s]
    )

    cards = []
    for s in _SEVERITY_ORDER:
        proven = sum(1 for f in findings if f["severity"] == s and f["proven"])
        cards.append(
            f'<div class="stat"><div class="stat-n" style="color:{_SEV_COLOR[s]}">{counts[s]}</div>'
            f'<div class="stat-l">{s}</div><div class="stat-sub">{proven} proven</div></div>'
        )

    rows = []
    for i, f in enumerate(findings, 1):
        status = "Proven exploitable" if f["proven"] else "Potential"
        status_cls = "proven" if f["proven"] else "potential"
        rec = f.get("agent_recommendation") or f.get("reference") or \
            "See the technical report for detailed guidance."
        rows.append(f"""
      <div class="finding">
        <div class="finding-head">
          <span class="rank">{i}</span>
          <span class="fname">{esc(f['name'])}</span>
          <span class="badge" style="background:{_SEV_COLOR[f['severity']]}">{f['severity']}</span>
          <span class="status {status_cls}">{status}</span>
        </div>
        <div class="finding-meta">{esc(f['owasp'] or f['category'])} &middot; exploitation difficulty {esc(f['difficulty'])}/6</div>
        <div class="finding-rec"><strong>Remediation:</strong> {esc(rec)}</div>
      </div>""")

    missed = _missed_keys(result)
    missed_items = "".join(
        f"<li><strong>{esc(result['answer_key'][k]['name'])}</strong> — "
        f"{esc(result['answer_key'][k].get('owasp_top10') or result['answer_key'][k]['category'])}</li>"
        for k in missed[:8]
    )
    if len(missed) > 8:
        missed_items += f"<li>…and {len(missed) - 8} more (see the technical scoresheet).</li>"
    if not missed:
        missed_items = "<li>The engagement identified every issue in the assessed set.</li>"

    cost_row = ""
    if manifest.get("total_cost_usd") is not None:
        cost_row = (f'<tr><td>Cost of this assessment</td><td>${float(manifest["total_cost_usd"]):.2f}</td>'
                    f'<td>Compute cost of the full automated run</td></tr>')

    client_line = f'<div class="sub">{esc(meta["client"])}</div>' if meta.get("client") else ""
    eng_line = f'<div class="sub">{esc(meta["engagement"])}</div>' if meta.get("engagement") else ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Executive Remediation Report — {esc(run_dir.name)}</title>
<style>
  :root {{
    --ink:#1a1d21; --muted:#5b636b; --line:#e4e7ea; --bg:#f6f7f9;
    --card:#ffffff; --accent:#1f3a5f;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:860px; margin:0 auto; padding:40px 24px 80px; }}
  header {{ border-bottom:3px solid var(--accent); padding-bottom:20px; margin-bottom:28px; }}
  h1 {{ font-size:28px; margin:0 0 6px; letter-spacing:-0.01em; }}
  .sub {{ color:var(--muted); font-size:14px; }}
  .meta-grid {{ display:flex; flex-wrap:wrap; gap:6px 22px; margin-top:14px; font-size:13.5px; color:var(--muted); }}
  .meta-grid b {{ color:var(--ink); font-weight:600; }}
  h2 {{ font-size:19px; margin:34px 0 14px; padding-bottom:6px; border-bottom:1px solid var(--line); }}
  .posture {{ font-size:17px; font-weight:700; margin-bottom:8px; }}
  .verdict {{ background:var(--card); border:1px solid var(--line); border-left:4px solid var(--accent);
    border-radius:8px; padding:16px 18px; margin:10px 0; }}
  .bar {{ display:flex; height:16px; border-radius:8px; overflow:hidden; margin:6px 0 18px; border:1px solid var(--line); }}
  .bar .seg {{ display:block; height:100%; }}
  .stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:8px 0 20px; }}
  .stat {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px; text-align:center; }}
  .stat-n {{ font-size:30px; font-weight:800; line-height:1; }}
  .stat-l {{ font-size:13px; font-weight:600; margin-top:4px; }}
  .stat-sub {{ font-size:11.5px; color:var(--muted); margin-top:2px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card);
    border:1px solid var(--line); border-radius:10px; overflow:hidden; font-size:14px; }}
  th,td {{ text-align:left; padding:10px 14px; border-bottom:1px solid var(--line); }}
  th {{ background:#eef1f4; font-size:12.5px; text-transform:uppercase; letter-spacing:0.03em; color:var(--muted); }}
  tr:last-child td {{ border-bottom:none; }}
  .finding {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
    padding:14px 16px; margin-bottom:12px; }}
  .finding-head {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .rank {{ width:24px; height:24px; border-radius:50%; background:var(--accent); color:#fff;
    font-size:13px; font-weight:700; display:flex; align-items:center; justify-content:center; flex:none; }}
  .fname {{ font-weight:700; font-size:16px; }}
  .badge {{ color:#fff; font-size:11.5px; font-weight:700; padding:2px 9px; border-radius:20px; }}
  .status {{ font-size:12px; font-weight:600; padding:2px 8px; border-radius:4px; }}
  .status.proven {{ background:#fdecec; color:#b4232a; }}
  .status.potential {{ background:#eef1f4; color:var(--muted); }}
  .finding-meta {{ color:var(--muted); font-size:13px; margin:6px 0 8px 34px; }}
  .finding-rec {{ font-size:14px; margin-left:34px; }}
  ul.residual {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
    padding:14px 14px 14px 32px; margin:0; }}
  ul.residual li {{ margin:4px 0; }}
  footer {{ margin-top:30px; padding-top:16px; border-top:1px solid var(--line);
    color:var(--muted); font-size:12.5px; }}
  @media (max-width:560px) {{ .stats {{ grid-template-columns:repeat(2,1fr); }} }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Executive Remediation Report</h1>
    {client_line}
    {eng_line}
    <div class="meta-grid">
      <span><b>Target:</b> {esc(manifest.get('target', 'authorized web application'))}</span>
      <span><b>Mode:</b> {esc(meta['mode'])}</span>
      <span><b>Method:</b> Autonomous AI penetration test</span>
      <span><b>Date:</b> {today}</span>
    </div>
  </header>

  <h2>Executive summary</h2>
  <div class="posture">Overall security posture: <span style="color:{_SEV_COLOR['Critical'] if 'Critical' in label else _SEV_COLOR['High'] if 'High' in label else 'var(--accent)'}">{esc(label)}</span></div>
  <div class="verdict">{esc(verdict)}</div>
  <p>Every exploited issue listed here was independently confirmed by the application's
     own records — it reflects what the agent actually achieved, not what it merely suspected.</p>

  <h2>Risk at a glance</h2>
  <div class="bar">{bar}</div>
  <div class="stats">{''.join(cards)}</div>
  <table>
    <tr><th>Coverage metric</th><th>Result</th><th>What it means</th></tr>
    <tr><td>Issues confirmed exploitable</td><td>{len(exploited)} of {len(graded)} ({exp_pct})</td><td>Proven end to end against the live target</td></tr>
    <tr><td>Issues identified</td><td>{len(detected)} of {len(graded)} ({det_pct})</td><td>Flagged by the agent as likely vulnerable</td></tr>
    {cost_row}
  </table>

  <h2>Priority remediation roadmap</h2>
  <p>Ordered by business risk — highest first. Address proven, higher-severity items
     before lower ones.</p>
  {''.join(rows) if rows else '<p><em>No answer-key-backed findings were produced for this run.</em></p>'}

  <h2>Residual risk — what this assessment did not cover</h2>
  <ul class="residual">{missed_items}</ul>

  <footer>
    Generated from the same scored results as the technical scoresheet
    (<code>score.csv</code> / <code>score-report.md</code>); the figures are identical.
    Severity reflects business impact (OWASP category) combined with whether the issue
    was proven exploitable, and is distinct from Juice Shop's exploitation-difficulty rating.
  </footer>
</div>
</body>
</html>
"""


# --- command line ----------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_dir", type=Path, help="run directory, e.g. Tooling/runs/<run-id>")
    parser.add_argument("--mode", default="unspecified",
                        help="assessment mode label: black-box or white-box")
    parser.add_argument("--client", default=None, help="client/organization name for the header")
    parser.add_argument("--engagement", default=None, help="engagement name/label for the header")
    parser.add_argument("--no-html", action="store_true", help="write only the Markdown report")
    args = parser.parse_args()

    result = score_run.score(args.run_dir)

    meta = {
        "mode": args.mode,
        "client": args.client,
        "engagement": args.engagement,
        "manifest": load_manifest(args.run_dir),
    }
    # Fall back to the manifest's mode if the user didn't pass one.
    if args.mode == "unspecified" and meta["manifest"].get("mode"):
        meta["mode"] = meta["manifest"]["mode"]

    findings = build_findings(args.run_dir, result)

    md = render_markdown(result, findings, meta)
    md_path = args.run_dir / "exec-report.md"
    md_path.write_text(md, encoding="utf-8")
    print(f"Wrote {md_path}")

    if not args.no_html:
        html_doc = render_html(args.run_dir, result, findings, meta)
        html_path = args.run_dir / "exec-report.html"
        html_path.write_text(html_doc, encoding="utf-8")
        print(f"Wrote {html_path}")

    graded = result["graded"]
    crit = sum(1 for f in findings if f["severity"] == "Critical")
    high = sum(1 for f in findings if f["severity"] == "High")
    print(f"Posture: {posture(result, findings)[0]} | "
          f"Critical {crit} | High {high} | "
          f"exploitable {len(result['exploited'] & graded)}/{len(graded)}")


if __name__ == "__main__":
    main()
