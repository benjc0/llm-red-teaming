"""AI agent vs. free tools: the data behind the GUI's Compare view.

Read-only, like runstore.py. Three sources feed it:

  <run>/score.json          written by vuln-list/score_run.py (answer-key metrics)
  <run>/run.json            the manifest (kind, per-phase duration, cost, tools)
  <run>/<phase>/findings.json  per-phase attack-surface counts (no answer key needed)

Grouping, mean ± std and the AI-only / both / tools-only overlap come from
vuln-list/compare_runs.py, loaded by path. It is stdlib-only and written to be
reused here, so the GUI and the CLI table can never disagree.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Optional

from .runstore import PHASE_ORDER, PHASE_TITLES

VULN_LIST_DIR = Path(__file__).resolve().parents[2] / "vuln-list"

# What each phase is measured by, beyond the answer-key score: (payload field,
# label). "confirmed" and "report" are computed rather than plain list lengths.
PHASE_METRICS: dict[str, list[tuple[str, str]]] = {
    "recon": [("services", "Services"), ("tech_stack", "Tech stack items"),
              ("endpoints", "Endpoints")],
    "enumeration": [("routes", "Routes"), ("params", "Parameters"),
                    ("hidden_paths", "Hidden paths"), ("api_surface", "API endpoints")],
    "vuln_assessment": [("vulnerabilities", "Findings reported")],
    "exploitation": [("attempts", "Exploit attempts"), ("confirmed", "Oracle-confirmed")],
    "post_exploitation": [("footholds", "Footholds"), ("reachable_data", "Reachable data"),
                          ("escalations", "Escalations")],
    "reporting": [("report", "Report written")],
    "mitigation": [("items", "Mitigation items")],
}

# Phases with no real free-tool equivalent: the baseline derives them from
# earlier output. The GUI labels them so nobody reads too much into them.
DERIVED_PHASES = {"post_exploitation", "reporting", "mitigation"}

# The free-tool lineup per phase, with a one-line purpose for the GUI. Mirrors
# baseline/tools.py:REGISTRY. tools_by_phase() prefers the live registry and
# falls back to this table if baseline (pydantic) isn't importable.
TOOL_INFO: dict[str, str] = {
    "nmap": "Port and service/version scan",
    "whatweb": "Tech-stack fingerprinting",
    "katana": "JavaScript-aware crawler",
    "ffuf": "Content discovery (wordlist fuzzing)",
    "arjun": "Hidden parameter discovery",
    "zap": "DAST passive baseline scan",
    "nuclei": "Template-based vulnerability scanner",
    "nikto": "Web-server misconfiguration scanner",
    "retirejs": "Outdated JavaScript library detection",
    "semgrep": "SAST over the source tree",
    "sqlmap": "SQL injection exploitation",
    "zap_active": "DAST active attack scan",
}
_FALLBACK_REGISTRY = {
    "recon": [("nmap", False), ("whatweb", False)],
    "enumeration": [("katana", False), ("ffuf", False), ("arjun", False)],
    "vuln_assessment": [("zap", False), ("nuclei", False), ("nikto", False),
                        ("retirejs", False), ("semgrep", True)],
    "exploitation": [("sqlmap", False), ("zap_active", False)],
}
_DERIVED_NOTE = {
    "post_exploitation": "Derived from oracle-confirmed exploits",
    "reporting": "Rendered from accumulated findings",
    "mitigation": "Tool remediation text, else CWE → OWASP Cheat Sheet",
}


def tools_by_phase() -> dict:
    """{phase: {"tools": [{name, purpose, white_box_only}], "derived": note|None}}."""
    try:
        from baseline.tools import REGISTRY  # type: ignore
        reg = {p.value: [(s.name, s.white_box_only) for s in specs] for p, specs in REGISTRY.items()}
    except Exception:  # noqa: BLE001 - pydantic missing, etc.
        reg = _FALLBACK_REGISTRY
    out = {}
    for phase in PHASE_ORDER:
        out[phase] = {
            "title": PHASE_TITLES.get(phase, phase),
            "tools": [{"name": n, "purpose": TOOL_INFO.get(n, ""), "white_box_only": wb}
                      for n, wb in reg.get(phase, [])],
            "derived": _DERIVED_NOTE.get(phase),
        }
    return out


# -- loading shared code / data ------------------------------------------------

@lru_cache(maxsize=1)
def _compare_runs():
    path = VULN_LIST_DIR / "compare_runs.py"
    spec = importlib.util.spec_from_file_location("apt_compare_runs", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@lru_cache(maxsize=1)
def challenge_names() -> dict:
    """{key: {name, owasp, difficulty, category}} from the answer key, if PyYAML
    is installed. Without it the GUI just shows challenge keys."""
    try:
        import yaml  # type: ignore
        data = yaml.safe_load((VULN_LIST_DIR / "master-vuln-list.yml").read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    return {e["key"]: {"name": e.get("name") or e["key"], "owasp": e.get("owasp_top10"),
                       "difficulty": e.get("difficulty"), "category": e.get("category")}
            for e in data.get("vulnerabilities", [])}


def _read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def load_score(run_dir: Path) -> Optional[dict]:
    return _read_json(run_dir / "score.json")


def run_kind(run_dir: Path, manifest: Optional[dict] = None) -> str:
    manifest = manifest if manifest is not None else (_read_json(run_dir / "run.json") or {})
    if manifest.get("kind"):
        return manifest["kind"]
    return "baseline" if run_dir.name.startswith("base-") else "ai"


# -- per-phase stats -------------------------------------------------------------

# Programs worth reporting as "a tool the agent used". An allowlist, because
# multi-line Bash bodies (heredocs, scripts) otherwise yield junk like file names.
_KNOWN_PROGRAMS = {
    "curl", "wget", "http", "httpie", "nmap", "masscan", "nc", "ncat", "netcat", "openssl",
    "python", "python3", "node", "npx", "npm", "jq", "grep", "rg", "sed", "awk", "find",
    "base64", "xxd", "sqlmap", "ffuf", "gobuster", "dirb", "dirsearch", "feroxbuster",
    "nikto", "nuclei", "whatweb", "wfuzz", "hydra", "john", "hashcat", "jwt_tool", "zap",
    "katana", "arjun", "retire", "semgrep", "docker", "git", "sqlite3", "dig", "host",
    "whois", "ssh", "ps", "strings", "file", "unzip", "tar", "perl", "ruby", "php",
}
_WRAPPERS = {"sudo", "env", "time", "timeout", "nohup", "exec", "command", "xargs"}


def _log_scan(log_path: Path) -> tuple[Optional[float], Counter]:
    """From a Claude stream-json log: phase wall time (result.duration_ms) and
    which shell programs the agent actually reached for (first word of each
    pipeline segment in Bash calls). That second list is the AI-side answer to
    "which tools did it use in this phase"."""
    duration = None
    cmds: Counter = Counter()
    try:
        fh = log_path.open("r", encoding="utf-8", errors="replace")
    except OSError:
        return None, cmds
    with fh:
        for line in fh:
            if '"result"' not in line and '"Bash"' not in line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("type") == "result" and e.get("duration_ms") is not None:
                duration = round(e["duration_ms"] / 1000, 2)
            for b in (e.get("message") or {}).get("content") or []:
                if b.get("type") == "tool_use" and b.get("name") == "Bash":
                    for prog in _programs((b.get("input") or {}).get("command", "")):
                        cmds[prog] += 1
    return duration, cmds


def _programs(command: str) -> list[str]:
    out = []
    for seg in re.split(r"\|\||&&|[|;\n]|\$\(", command or ""):
        for w in seg.strip().split():
            if "=" in w.split("/")[0] or w.isdigit():
                continue  # VAR=value prefix, or a timeout's seconds argument
            prog = w.rsplit("/", 1)[-1].strip("()'\"`")
            if prog in _WRAPPERS:
                continue
            if prog in _KNOWN_PROGRAMS:
                out.append("python3" if prog == "python" else prog)
            break
    return out


def phase_stats(run_dir: Path) -> dict:
    """{phase: {ran, counts{field: n}, duration_s, cost_usd, tools[]}}."""
    manifest = _read_json(run_dir / "run.json") or {}
    kind = run_kind(run_dir, manifest)
    mphases = {p.get("phase"): p for p in manifest.get("phases", []) or []}
    out: dict[str, dict] = {}
    for phase in PHASE_ORDER:
        findings = _read_json(run_dir / phase / "findings.json")
        mp = mphases.get(phase) or {}
        payload = (findings or {}).get("payload") or {}
        counts: dict[str, int] = {}
        for field, _label in PHASE_METRICS.get(phase, []):
            if field == "confirmed":
                counts[field] = sum(1 for a in payload.get("attempts") or [] if a.get("oracle_confirmed"))
            elif field == "report":
                counts[field] = int((run_dir / phase / "report.md").is_file()
                                    or bool(payload.get("report_path")))
            else:
                counts[field] = len(payload.get(field) or [])
        duration = mp.get("duration_s")
        tools: list[str] = list(mp.get("tools") or [])
        if kind != "baseline":
            log_dur, cmds = _log_scan(run_dir / "logs" / f"{phase}.jsonl")
            duration = duration if duration is not None else log_dur
            tools = [p for p, _ in cmds.most_common(6)]
        out[phase] = {
            "ran": findings is not None,
            "counts": counts if findings is not None else {},
            "duration_s": duration,
            "cost_usd": (mp.get("usage") or {}).get("cost_usd") if kind != "baseline" else 0.0,
            "tools": tools,
        }
    return out


# -- the comparison ----------------------------------------------------------------

def _mean(vals: list) -> Optional[float]:
    nums = [v for v in vals if v is not None]
    return round(sum(nums) / len(nums), 4) if nums else None


def _merge_phase_stats(stats: list[dict]) -> dict:
    """Average per-phase counts / time / cost across a group's trials."""
    out = {}
    for phase in PHASE_ORDER:
        ran = [s[phase] for s in stats if s.get(phase, {}).get("ran")]
        fields = [f for f, _ in PHASE_METRICS.get(phase, [])]
        tools: list[str] = []
        for s in stats:
            for t in s.get(phase, {}).get("tools") or []:
                if t not in tools:
                    tools.append(t)
        out[phase] = {
            "ran": len(ran),
            "counts": {f: _mean([r["counts"].get(f) for r in ran]) for f in fields} if ran else {},
            "duration_s": _mean([s[phase]["duration_s"] for s in stats if phase in s]),
            "cost_usd": _mean([s[phase]["cost_usd"] for s in stats if s.get(phase, {}).get("ran")]),
            "tools": tools[:8],
        }
    return out


def _sum_buckets(members: list[dict], field: str) -> dict:
    """Pool hit/total over trials per bucket (so the rate is the mean rate)."""
    out: dict[str, dict] = {}
    for m in members:
        for bucket, v in (m.get(field) or {}).items():
            b = out.setdefault(bucket, {"hit": 0, "total": 0})
            b["hit"] += v.get("hit", 0)
            b["total"] += v.get("total", 0)
    n = max(len(members), 1)
    return {k: {"hit": round(v["hit"] / n, 2), "total": round(v["total"] / n, 2),
                "rate": round(v["hit"] / v["total"], 4) if v["total"] else None}
            for k, v in sorted(out.items())}


def _side(members: list[dict], group: dict, stats: list[dict]) -> dict:
    cr = _compare_runs()
    g = dict(group)
    metrics = dict(g["metrics"])
    for k in ("exploited", "detected", "needs_review", "matched_findings"):
        metrics[k] = cr._mean_std([m["metrics"].get(k) for m in members])
    metrics["reported"] = cr._mean_std([m.get("reported_count") for m in members])
    if metrics["duration_s"]["mean"] is None:
        # Older score.json files predate duration_s; sum the per-phase timings.
        totals = []
        for st in stats:
            durs = [v["duration_s"] for v in st.values() if v.get("duration_s") is not None]
            totals.append(round(sum(durs), 2) if durs else None)
        metrics["duration_s"] = cr._mean_std(totals)
    cost, time_s = metrics["cost_usd"]["mean"], metrics["duration_s"]["mean"]
    expl = metrics["exploited"]["mean"]
    metrics["cost_per_exploit"] = {"mean": round(cost / expl, 4) if cost is not None and expl else None,
                                   "std": None, "n": len(members)}
    metrics["time_per_exploit"] = {"mean": round(time_s / expl, 2) if time_s is not None and expl else None,
                                   "std": None, "n": len(members)}
    g["metrics"] = metrics
    g["modes"] = sorted({m.get("mode") or "unspecified" for m in members})
    g["models"] = sorted({m.get("model") for m in members if m.get("model")})
    g["graded_total"] = members[0].get("graded_total")
    g["by_owasp"] = _sum_buckets(members, "by_owasp")
    g["detection_by_owasp"] = _sum_buckets(members, "detection_by_owasp")
    g["by_difficulty"] = _sum_buckets(members, "by_difficulty")
    g["detection_by_difficulty"] = _sum_buckets(members, "detection_by_difficulty") \
        if any(m.get("detection_by_difficulty") for m in members) else None
    g["phases"] = _merge_phase_stats(stats)
    missed: Optional[set] = None
    for m in members:
        ks = set(m.get("missed_keys") or [])
        missed = ks if missed is None else missed & ks
    g["missed_all"] = sorted(missed or [])
    return g


def default_selection(runs_root: Path) -> list[str]:
    """Latest scored AI run + latest scored baseline run (same mode if possible)."""
    scored = []
    for d in sorted((p for p in Path(runs_root).iterdir() if p.is_dir()),
                    key=lambda p: (_read_json(p / "score.json") or {}).get("scored_at") or "",
                    reverse=True) if Path(runs_root).is_dir() else []:
        s = load_score(d)
        if s:
            scored.append((d.name, s.get("kind") or run_kind(d), s.get("mode")))
    ai = next((r for r in scored if r[1] == "ai"), None)
    base = None
    if ai:
        base = next((r for r in scored if r[1] == "baseline" and r[2] == ai[2]), None)
    base = base or next((r for r in scored if r[1] == "baseline"), None)
    return [r[0] for r in (ai, base) if r]


def build(runs_root: Path, run_ids: list[str]) -> dict:
    """The full comparison payload the Compare view renders."""
    cr = _compare_runs()
    runs_root = Path(runs_root)
    sides: dict[str, list[tuple[dict, dict]]] = {"ai": [], "baseline": []}
    unscored, missing = [], []
    for rid in run_ids:
        if not rid or "/" in rid or "\\" in rid or rid in (".", ".."):
            continue
        d = runs_root / rid
        if not d.is_dir():
            missing.append(rid)
            continue
        s = load_score(d)
        if s is None:
            unscored.append(rid)
            continue
        kind = s.get("kind") or run_kind(d)
        sides["baseline" if kind == "baseline" else "ai"].append((s, phase_stats(d)))

    warnings = []
    # Force exactly one group per side so compare_runs.overlap() is defined even
    # when the picked trials mix modes. Mixed modes get a warning instead.
    scores = []
    for kind, items in sides.items():
        modes = sorted({s.get("mode") or "unspecified" for s, _ in items})
        if len(modes) > 1:
            warnings.append(f"{'AI' if kind == 'ai' else 'Tool'} runs mix modes ({', '.join(modes)}); "
                            "averaged together.")
        for s, _ in items:
            scores.append({**s, "kind": kind, "mode": "+".join(modes)})
    ai_modes = {s.get("mode") for s, _ in sides["ai"]}
    base_modes = {s.get("mode") for s, _ in sides["baseline"]}
    if ai_modes and base_modes and ai_modes != base_modes:
        warnings.append("AI and tool runs used different modes (black-box vs white-box); "
                        "the comparison isn't like-for-like.")

    comparison = cr.build_comparison(scores) if scores else {"groups": {}, "overlap": None}
    out: dict = {"run_ids": run_ids, "unscored": unscored, "missing": missing,
                 "warnings": warnings, "ai": None, "baseline": None,
                 "overlap": comparison.get("overlap"), "missed_by_both": [],
                 "phase_order": PHASE_ORDER, "phase_titles": PHASE_TITLES,
                 "phase_metrics": {p: [{"field": f, "label": l} for f, l in m]
                                   for p, m in PHASE_METRICS.items()},
                 "derived_phases": sorted(DERIVED_PHASES),
                 "tools": tools_by_phase(), "names": {}}
    for gkey, group in comparison["groups"].items():
        kind = group["kind"]
        items = sides[kind]
        out[kind] = _side([s for s, _ in items], group, [st for _, st in items])
    if out["ai"] and out["baseline"]:
        out["missed_by_both"] = sorted(set(out["ai"]["missed_all"]) & set(out["baseline"]["missed_all"]))
        ran = {k: [p for p in PHASE_ORDER if out[k]["phases"][p]["ran"]] for k in ("ai", "baseline")}
        if ran["ai"] != ran["baseline"]:
            only_ai = [PHASE_TITLES[p] for p in ran["ai"] if p not in ran["baseline"]]
            only_tools = [PHASE_TITLES[p] for p in ran["baseline"] if p not in ran["ai"]]
            parts = []
            if only_ai:
                parts.append(f"only the AI ran {', '.join(only_ai)}")
            if only_tools:
                parts.append(f"only the tools ran {', '.join(only_tools)}")
            warnings.append(f"The two sides covered different phases ({'; '.join(parts)}), so total "
                            "time and cost measure different amounts of work. Compare per phase below.")
    names = challenge_names()
    used: set[str] = set(out["missed_by_both"])
    for side in ("ai", "baseline"):
        if out[side]:
            used |= set(out[side]["detected_union"]) | set(out[side]["missed_all"])
    out["names"] = {k: names[k] for k in used if k in names}
    out["_comparison"] = comparison
    return out


def markdown(runs_root: Path, run_ids: list[str]) -> str:
    """comparison.md text, via compare_runs.write_markdown (same as the CLI)."""
    data = build(runs_root, run_ids)
    with tempfile.TemporaryDirectory() as tmp:
        path = _compare_runs().write_markdown(Path(tmp), data["_comparison"])
        return path.read_text(encoding="utf-8")


# -- scoring from the GUI -----------------------------------------------------------

class ScoreError(RuntimeError):
    pass


def score_run(runs_root: Path, run_id: str) -> dict:
    """Run vuln-list/score_run.py on one run (needs PyYAML)."""
    if not run_id or "/" in run_id or "\\" in run_id or run_id in (".", ".."):
        raise ScoreError("bad run id")
    run_dir = Path(runs_root) / run_id
    if not run_dir.is_dir():
        raise ScoreError("run not found")
    if importlib.util.find_spec("yaml") is None:
        raise ScoreError("Scoring needs PyYAML in the GUI's Python "
                         "(pip install pyyaml, or sudo apt install python3-yaml).")
    manifest = _read_json(run_dir / "run.json") or {}
    mode = manifest.get("mode") or "unspecified"
    proc = subprocess.run([sys.executable, str(VULN_LIST_DIR / "score_run.py"), str(run_dir),
                           "--mode", mode], capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout).strip().splitlines()
        raise ScoreError(msg[-1] if msg else f"scorer exited {proc.returncode}")
    return {"run_id": run_id, "output": proc.stdout.strip(), "score": load_score(run_dir)}
