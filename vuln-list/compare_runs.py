#!/usr/bin/env python3
"""Compare scored runs side by side: AI agent vs. deterministic tooling.

Each run must already have a score.json (written by score_run.py). This script
groups the runs by (kind, mode) -- e.g. "ai/black-box" vs "baseline/black-box" --
averages each metric across the trials in a group (mean +/- std, so model
nondeterminism is visible), and computes the vulnerability overlap between the
AI and the tools: what only the AI found, what only the tools found, and what
both found. It writes:

  <out>/comparison.json   machine-readable (the GUI can also compute this live)
  <out>/comparison.md     the table for the written report

Usage:
  python3 vuln-list/compare_runs.py Tooling/runs/<ai-run> Tooling/runs/<baseline-run> ...
  python3 vuln-list/compare_runs.py Tooling/runs/* --out comparisons/blackbox

Pure standard library: the GUI reuses the same aggregation without PyYAML.
"""
from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path

# Metrics we average across trials, in display order, with friendly labels.
METRIC_LABELS = [
    ("detection_rate", "Detection rate"),
    ("exploitation_rate", "Exploitation rate"),
    ("precision", "Precision"),
    ("f1", "F1"),
    ("false_positives", "False positives"),
]


def load_score(run_dir: Path) -> dict | None:
    path = run_dir / "score.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _mean_std(values: list[float]) -> dict:
    """Mean and population std of the non-None values (keeps undefined metrics
    from being counted as zero)."""
    nums = [v for v in values if v is not None]
    if not nums:
        return {"mean": None, "std": None, "n": 0}
    mean = sum(nums) / len(nums)
    std = math.sqrt(sum((v - mean) ** 2 for v in nums) / len(nums)) if len(nums) > 1 else 0.0
    return {"mean": round(mean, 4), "std": round(std, 4), "n": len(nums)}


def group_key(score: dict) -> str:
    return f"{score.get('kind', 'ai')}/{score.get('mode') or 'unspecified'}"


def aggregate(scores: list[dict]) -> dict:
    """Group scored runs by kind/mode and average each metric across trials."""
    groups: dict[str, list[dict]] = {}
    for s in scores:
        groups.setdefault(group_key(s), []).append(s)

    out: dict[str, dict] = {}
    for gkey, members in groups.items():
        metrics: dict[str, dict] = {}
        for metric, _label in METRIC_LABELS:
            metrics[metric] = _mean_std([m["metrics"].get(metric) for m in members])
        # Cost and time, averaged where present.
        costs = [(m.get("usage_total") or {}).get("cost_usd") for m in members]
        metrics["cost_usd"] = _mean_std(costs)
        metrics["duration_s"] = _mean_std([m.get("duration_s") for m in members])
        # Union of everything any trial in the group detected/exploited.
        detected: set[str] = set()
        exploited: set[str] = set()
        for m in members:
            detected |= set(m.get("detected_keys") or [])
            exploited |= set(m.get("exploited_keys") or [])
        out[gkey] = {
            "kind": members[0].get("kind"),
            "mode": members[0].get("mode"),
            "trials": len(members),
            "run_ids": [m["run_id"] for m in members],
            "tools": members[0].get("tools"),
            "metrics": metrics,
            "detected_union": sorted(detected),
            "exploited_union": sorted(exploited),
        }
    return out


def overlap(groups: dict) -> dict | None:
    """AI-only / tool-only / both, for detection and exploitation. Only defined
    when exactly one AI group and one baseline group are present."""
    ai = [g for g in groups.values() if g["kind"] == "ai"]
    base = [g for g in groups.values() if g["kind"] == "baseline"]
    if len(ai) != 1 or len(base) != 1:
        return None

    def split(field: str) -> dict:
        a, b = set(ai[0][field]), set(base[0][field])
        return {"ai_only": sorted(a - b), "both": sorted(a & b),
                "baseline_only": sorted(b - a)}

    return {"detection": split("detected_union"),
            "exploitation": split("exploited_union")}


def build_comparison(scores: list[dict]) -> dict:
    groups = aggregate(scores)
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "groups": groups,
        "overlap": overlap(groups),
    }


def _fmt(cell: dict, metric: str) -> str:
    m = cell.get("mean")
    if m is None:
        return "n/a"
    if metric in ("false_positives", "duration_s"):
        body = f"{m:.1f}" if metric == "duration_s" else f"{m:.1f}"
    elif metric == "cost_usd":
        body = f"${m:.2f}"
    else:
        body = f"{100 * m:.0f}%"
    if cell.get("n", 0) > 1 and cell.get("std"):
        suffix = f"{100 * cell['std']:.0f}%" if metric not in ("false_positives", "duration_s", "cost_usd") else f"{cell['std']:.1f}"
        body += f" ±{suffix}"
    return body


def write_markdown(out_dir: Path, comparison: dict) -> Path:
    groups = comparison["groups"]
    gkeys = sorted(groups)
    lines = [
        "# Run comparison: AI agent vs. deterministic tooling",
        "",
        f"Generated {comparison['created_at']}.",
        "",
        "Each column is one group of runs (kind/mode); values are the mean across "
        "that group's trials, with ± population std where there is more than one "
        "trial (deterministic tooling should vary little; the AI will).",
        "",
        "## Headline metrics",
        "",
        "| Metric | " + " | ".join(gkeys) + " |",
        "|---|" + "---|" * len(gkeys),
    ]
    for metric, label in METRIC_LABELS + [("cost_usd", "Cost (USD)"), ("duration_s", "Time (s)")]:
        row = [label]
        for gk in gkeys:
            row.append(_fmt(groups[gk]["metrics"][metric], metric))
        lines.append("| " + " | ".join(row) + " |")
    lines += ["", f"Trials per group: " + ", ".join(f"{gk} = {groups[gk]['trials']}" for gk in gkeys), ""]

    ov = comparison.get("overlap")
    if ov:
        lines += ["## Vulnerability overlap (detection)", "",
                  f"- Both found: **{len(ov['detection']['both'])}** — {', '.join(ov['detection']['both']) or '(none)'}",
                  f"- AI only: **{len(ov['detection']['ai_only'])}** — {', '.join(ov['detection']['ai_only']) or '(none)'}",
                  f"- Tools only: **{len(ov['detection']['baseline_only'])}** — {', '.join(ov['detection']['baseline_only']) or '(none)'}",
                  "",
                  "## Vulnerability overlap (exploitation, oracle-confirmed)", "",
                  f"- Both: **{len(ov['exploitation']['both'])}** — {', '.join(ov['exploitation']['both']) or '(none)'}",
                  f"- AI only: **{len(ov['exploitation']['ai_only'])}** — {', '.join(ov['exploitation']['ai_only']) or '(none)'}",
                  f"- Tools only: **{len(ov['exploitation']['baseline_only'])}** — {', '.join(ov['exploitation']['baseline_only']) or '(none)'}",
                  ""]

    out = out_dir / "comparison.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("runs", nargs="+", type=Path, help="run directories, each with a score.json")
    parser.add_argument("--out", type=Path, default=None,
                        help="output directory (default: comparisons/<timestamp>)")
    args = parser.parse_args()

    scores = []
    for run_dir in args.runs:
        s = load_score(run_dir)
        if s is None:
            print(f"[skip] no score.json in {run_dir} (run score_run.py first)")
            continue
        scores.append(s)
    if not scores:
        raise SystemExit("No scored runs given. Run vuln-list/score_run.py on each run first.")

    comparison = build_comparison(scores)
    out_dir = args.out or (Path("comparisons") / datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "comparison.json").write_text(json.dumps(comparison, indent=2), encoding="utf-8")
    md_path = write_markdown(out_dir, comparison)
    print(f"Compared {len(scores)} run(s) in {len(comparison['groups'])} group(s).")
    print(f"Wrote {out_dir / 'comparison.json'}")
    print(f"Wrote {md_path}")


if __name__ == "__main__":
    main()
