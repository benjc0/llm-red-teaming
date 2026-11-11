"""The baseline orchestrator: run deterministic tools, normalize, hand off.

Mirrors apt/runner.py, but each phase runs one or more real pentest tools
instead of Claude. For each phase it:
  1. runs every ToolSpec for the phase (Docker/native), capturing raw output to
     runs/<id>/<phase>/raw/ and logging start/finish to logs/<phase>.jsonl;
  2. normalizes each tool's output through its adapter into the phase's schema
     payload, merges them, and writes the same findings.json the AI would;
  3. for exploitation, snapshots the solve oracle before/after and attributes
     newly-solved challenge keys to the tool that flipped them -- so a baseline
     exploit is server-confirmed exactly like the AI's.

Tool execution degrades gracefully: if Docker or a tool is unavailable, the
failure is logged and the phase still produces a valid (possibly empty)
findings.json, so a partial environment never aborts the run. The assembly step
(build_findings) is pure and unit-tested against canned tool output.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from apt import phases as phase_defs
from apt.runner import GRADING_TOKEN_ENV, fetch_solved_map
from apt.schema import (EnumPayload, ExploitAttempt, ExploitPayload, FindingsBase,
                        MitigationItem, MitigationPayload, Phase, PostExploitPayload,
                        RawArtifact, ReconPayload, ReportingPayload, VulnPayload)
from apt.schema import FINDINGS_MODELS

from . import tools as tool_defs
from .tools import ToolContext, ToolSpec

# Canned per-CWE remediation the mitigation baseline falls back to when a tool
# gave no solution text -- the "deterministic tooling" equivalent of a playbook.
_CWE_CHEATSHEET = {
    "CWE-89": ("Use parameterized queries / prepared statements; never build SQL "
               "from user input.", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
    "CWE-79": ("Contextually output-encode all user data and apply a strict CSP.",
               "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
    "CWE-287": ("Enforce authentication on every protected route server-side.",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"),
    "CWE-284": ("Deny by default and check authorization on every request server-side.",
                "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html"),
    "CWE-16": ("Set the missing security headers (CSP, X-Frame-Options, etc.).",
               "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"),
    "CWE-327": ("Replace the weak algorithm with a current, vetted one.",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"),
}
_GENERIC_MITIGATION = ("Review and remediate following the referenced OWASP guidance.",
                       "https://cheatsheetseries.owasp.org/")


@dataclass
class BaselineConfig:
    target: str
    mode: str = "black-box"
    source_dir: str | None = None
    out_root: Path = Path("runs")
    run_id: str = ""
    phases: list[Phase] = field(default_factory=lambda: list(phase_defs.DEFAULT_PHASES))
    grading_token: str | None = None
    dry_run: bool = False

    def __post_init__(self) -> None:
        if not self.run_id:
            self.run_id = "base-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.out_root = Path(self.out_root)
        if self.grading_token is None:
            import os
            self.grading_token = os.environ.get(GRADING_TOKEN_ENV)


# --- pure assembly (unit-tested) -------------------------------------------

def _merge(dicts: list[dict]) -> dict:
    """Merge adapter outputs: lists concatenate, dict values update."""
    out: dict = {}
    for d in dicts:
        for k, v in d.items():
            if isinstance(v, list):
                out.setdefault(k, []).extend(v)
            elif isinstance(v, dict):
                out.setdefault(k, {}).update(v)
            else:
                out.setdefault(k, v)
    return out


def _dedupe_vulns(vulns: list) -> list:
    """Collapse duplicate vulnerabilities (same CWE + location) across tools."""
    seen: dict[tuple, object] = {}
    for v in vulns:
        key = ((v.cwe or "").upper(), v.location)
        seen.setdefault(key, v)
    return list(seen.values())


def build_findings(phase: Phase, cfg: BaselineConfig, tool_outputs: dict,
                   prior: list[FindingsBase], state: dict) -> FindingsBase:
    """Turn {tool_name: raw_output} into the phase's findings model (pure)."""
    merged = _merge(_parse_all(phase, cfg, tool_outputs))
    model = FINDINGS_MODELS[phase]
    base = dict(run_id=cfg.run_id, target=cfg.target)

    if phase == Phase.recon:
        payload = ReconPayload(hosts=merged.get("hosts", []),
                               services=merged.get("services", []),
                               tech_stack=sorted(set(merged.get("tech_stack", []))))
        summary = (f"nmap/WhatWeb mapped {len(payload.services)} service(s); "
                   f"stack: {', '.join(payload.tech_stack) or 'unknown'}.")
    elif phase == Phase.enumeration:
        payload = EnumPayload(routes=merged.get("routes", []),
                              params=merged.get("params", []),
                              hidden_paths=sorted(set(merged.get("hidden_paths", []))),
                              api_surface=sorted(set(merged.get("api_surface", []))))
        summary = (f"Crawl/fuzz found {len(payload.routes)} route(s), "
                   f"{len(payload.hidden_paths)} hidden path(s), {len(payload.params)} parameter(s).")
    elif phase == Phase.vuln_assessment:
        vulns = _dedupe_vulns(merged.get("vulnerabilities", []))
        payload = VulnPayload(vulnerabilities=vulns)
        state["mitigations"] = merged.get("mitigations", {})
        state["vulns"] = vulns
        summary = f"DAST/SAST tooling reported {len(vulns)} candidate vulnerabilit(ies)."
    elif phase == Phase.exploitation:
        attempts = merged.get("attempts", [])
        payload = ExploitPayload(attempts=attempts)
        summary = f"sqlmap/ZAP active scan made {len(attempts)} exploit attempt(s)."
    elif phase == Phase.post_exploitation:
        payload = _post_exploit_payload(prior)
        summary = "Post-exploitation reach derived from oracle-confirmed exploits."
    elif phase == Phase.reporting:
        payload = ReportingPayload(report_path="report.md", summary=_report_summary(prior))
        summary = payload.summary
    elif phase == Phase.mitigation:
        items = _mitigation_items(prior, state)
        payload = MitigationPayload(items=items)
        summary = f"{len(items)} mitigation item(s) from tool guidance and CWE cheat sheets."
    else:
        raise ValueError(f"unhandled phase {phase}")

    by_name = {s.name: s for s in tool_defs.REGISTRY.get(phase, [])}
    raw_artifacts = [
        RawArtifact(tool=name,
                    path=f"raw/{by_name[name].output_file}" if name in by_name else f"raw/{name}")
        for name in tool_outputs
    ]
    return model(**base, summary=summary, payload=payload, raw_artifacts=raw_artifacts)


def _parse_all(phase: Phase, cfg: BaselineConfig, tool_outputs: dict) -> list[dict]:
    """Run each tool's adapter over its captured output."""
    by_name = {s.name: s for s in tool_defs.REGISTRY.get(phase, [])}
    results = []
    for name, raw in tool_outputs.items():
        spec = by_name.get(name)
        if spec is None:
            continue
        try:
            if name == "sqlmap":
                results.append(spec.adapter(raw, cfg.target))
            else:
                results.append(spec.adapter(raw))
        except Exception as exc:  # noqa: BLE001 - a malformed report must not kill the run
            results.append({})
    return results


def _post_exploit_payload(prior: list[FindingsBase]) -> PostExploitPayload:
    exploited = _confirmed_keys(prior)
    reachable, escal = [], []
    for key in exploited:
        if "login" in key.lower() or "admin" in key.lower():
            reachable.append("user account table (via confirmed SQL injection login bypass)")
            escal.append("authenticated as the first/admin user")
    return PostExploitPayload(footholds=sorted(set(exploited)),
                              reachable_data=sorted(set(reachable)),
                              escalations=sorted(set(escal)))


def _confirmed_keys(prior: list[FindingsBase]) -> list[str]:
    for f in prior:
        if f.phase == Phase.exploitation:
            return [a.challenge_key for a in f.payload.attempts
                    if a.oracle_confirmed and a.challenge_key]
    return []


def _report_summary(prior: list[FindingsBase]) -> str:
    vulns = exploited = 0
    for f in prior:
        if f.phase == Phase.vuln_assessment:
            vulns = len(f.payload.vulnerabilities)
        if f.phase == Phase.exploitation:
            exploited = sum(1 for a in f.payload.attempts if a.oracle_confirmed)
    return (f"Deterministic baseline: {vulns} candidate vulnerabilities reported, "
            f"{exploited} confirmed by the server oracle.")


def _mitigation_items(prior: list[FindingsBase], state: dict) -> list[MitigationItem]:
    items: list[MitigationItem] = []
    tool_mit = state.get("mitigations", {}) or {}
    for f in prior:
        if f.phase != Phase.vuln_assessment:
            continue
        for v in f.payload.vulnerabilities:
            if v.id in tool_mit:
                rec = tool_mit[v.id]
                items.append(MitigationItem(vuln_id=v.id, recommendation=rec["recommendation"],
                                            reference=rec.get("reference")))
            else:
                rec, ref = _CWE_CHEATSHEET.get((v.cwe or "").upper(), _GENERIC_MITIGATION)
                items.append(MitigationItem(vuln_id=v.id, recommendation=rec, reference=ref))
    return items


# --- execution -------------------------------------------------------------

def _run_tool(spec: ToolSpec, ctx: ToolContext, log) -> str | None:
    """Execute one tool; return its raw output text, or None on failure."""
    argv = spec.argv(ctx)
    binary = argv[0]
    if shutil.which(binary) is None:
        _log(log, "tool_skip", spec.name, f"{binary} not on PATH")
        return None
    _log(log, "tool_start", spec.name, " ".join(argv[:6]) + " ...")
    out_path = Path(ctx.workdir) / spec.output_file
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=spec.timeout_s)
    except (subprocess.TimeoutExpired, OSError) as exc:
        _stop_container(argv)
        _log(log, "tool_error", spec.name, str(exc))
        return None
    if proc.returncode == 137 and argv[0] == "docker":
        # 137 = SIGKILL; for a capped container that is almost always the
        # memory limit. The VM is fine; only this tool's results are lost.
        _log(log, "tool_error", spec.name,
             "killed at its memory cap (exit 137); raise it with APT_TOOL_MEMORY=2g if the VM has room")
    if spec.reads_stdout:
        out_path.write_text(proc.stdout, encoding="utf-8")
        raw = proc.stdout
    else:
        raw = out_path.read_text(encoding="utf-8") if out_path.is_file() else ""
    _log(log, "tool_done", spec.name, f"exit {proc.returncode}, {len(raw)} bytes")
    return raw


def _stop_container(argv: list[str]) -> None:
    """Kill a timed-out tool's container (killing the docker client doesn't)."""
    if argv[:2] != ["docker", "run"] or "--name" not in argv:
        return
    name = argv[argv.index("--name") + 1]
    try:
        subprocess.run(["docker", "kill", name], capture_output=True, timeout=30)
    except (subprocess.TimeoutExpired, OSError):
        pass


def _log(log, event: str, tool: str, text: str) -> None:
    rec = {"type": event, "tool": tool, "text": text,
           "ts": datetime.now(timezone.utc).isoformat()}
    log.write(json.dumps(rec) + "\n")
    log.flush()


def run_phase(cfg: BaselineConfig, phase: Phase, prior: list[FindingsBase],
              state: dict) -> tuple[FindingsBase | None, dict]:
    run_dir = cfg.out_root / cfg.run_id
    phase_dir = run_dir / phase.value
    raw_dir = phase_dir / "raw"
    log_dir = run_dir / "logs"
    raw_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{phase.value}.jsonl"

    specs = tool_defs.tools_for(phase, cfg.mode)
    routes = _routes_from(prior)
    tool_outputs: dict[str, str] = {}
    started = time.time()

    with open(log_path, "w", encoding="utf-8") as log:
        solved_before = fetch_solved_map(cfg) if phase == Phase.exploitation else None
        for spec in specs:
            if cfg.dry_run:
                _log(log, "tool_dryrun", spec.name, " ".join(spec.argv(
                    ToolContext(cfg.target, str(raw_dir), spec.output_file, cfg.source_dir, routes))))
                continue
            _prepare_tool(spec.name, cfg, raw_dir, prior, tool_outputs, log)
            ctx = ToolContext(cfg.target, str(raw_dir), spec.output_file, cfg.source_dir, routes)
            raw = _run_tool(spec, ctx, log)
            if raw is not None:
                tool_outputs[spec.name] = raw

        findings = build_findings(phase, cfg, tool_outputs, prior, state)

        if phase == Phase.exploitation and not cfg.dry_run:
            _attribute_oracle(cfg, findings, solved_before, log)

    duration = round(time.time() - started, 2)
    if findings is not None:
        (phase_dir / "findings.json").write_text(
            findings.model_dump_json(indent=2), encoding="utf-8")
    return findings, {"phase": phase.value, "tools": list(tool_outputs),
                      "duration_s": duration, "ok": findings is not None}


def _prepare_tool(name: str, cfg: BaselineConfig, raw_dir: Path, prior: list[FindingsBase],
                  tool_outputs: dict, log) -> None:
    """Per-tool setup that depends on earlier output (tools chain within a phase).

    - arjun: probe the same-origin API URLs Katana just crawled, not only "/".
    - retirejs: Retire.js scans files, so download the target's JS bundles first.
    """
    try:
        if name == "arjun" and "katana" in tool_outputs:
            urls = arjun_targets(cfg.target, tool_outputs["katana"])
            if urls:
                (raw_dir / tool_defs.ARJUN_TARGETS).write_text("\n".join(urls) + "\n", encoding="utf-8")
                _log(log, "tool_prep", name, f"{len(urls)} URL(s) from Katana")
        elif name == "retirejs":
            n = fetch_js(cfg.target, prior, raw_dir / tool_defs.JS_DIRNAME)
            _log(log, "tool_prep", name, f"downloaded {n} JS file(s)")
    except Exception as exc:  # noqa: BLE001 - prep is best-effort
        _log(log, "tool_prep_error", name, str(exc))


def arjun_targets(target: str, katana_raw: str, limit: int = 25) -> list[str]:
    """Same-origin, non-static URLs from Katana's crawl (pure)."""
    from .adapters import katana
    base = target.rstrip("/")
    parsed = katana.parse(katana_raw)
    paths = list(parsed.get("api_surface") or []) + [r.path for r in parsed.get("routes") or []]
    static = (".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff", ".woff2", ".map", ".gif")
    out: list[str] = []
    for p in paths:
        if not p.startswith("/") or p.lower().split("?")[0].endswith(static):
            continue
        url = base + p.split("?")[0]
        if url not in out:
            out.append(url)
        if len(out) >= limit:
            break
    return out


def fetch_js(target: str, prior: list[FindingsBase], dest: Path, limit: int = 40) -> int:
    """Download same-origin <script src> bundles (from / and enumerated .js routes)."""
    import re
    import urllib.request
    from urllib.parse import urljoin, urlsplit

    dest.mkdir(parents=True, exist_ok=True)
    origin = urlsplit(target).netloc

    def get(url: str) -> str:
        with urllib.request.urlopen(url, timeout=15) as r:  # noqa: S310 - authorized target
            return r.read(5_000_000).decode("utf-8", errors="replace")

    urls: list[str] = []
    try:
        html = get(target)
        urls += [urljoin(target, m) for m in re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.I)]
    except OSError:
        pass
    for f in prior:
        if f.phase == Phase.enumeration:
            urls += [urljoin(target, r.path) for r in f.payload.routes if r.path.endswith(".js")]
    n = 0
    for url in dict.fromkeys(urls):
        if urlsplit(url).netloc != origin or n >= limit:
            continue
        try:
            body = get(url)
        except OSError:
            continue
        name = re.sub(r"[^A-Za-z0-9._-]", "_", urlsplit(url).path.strip("/")) or "index.js"
        (dest / name).write_text(body, encoding="utf-8")
        n += 1
    return n


def _routes_from(prior: list[FindingsBase]) -> list[str]:
    for f in prior:
        if f.phase == Phase.enumeration:
            return sorted(f.payload.api_surface) or [e.path for e in f.payload.routes]
    return []


def _attribute_oracle(cfg: BaselineConfig, findings, solved_before, log) -> None:
    """Attribute challenge keys the tools newly solved to those tool attempts.

    Tools don't know Juice Shop challenge keys, so we diff the oracle's solve
    state before vs. after the phase; any key that flipped to solved during the
    phase is credited as an oracle-confirmed exploit by the baseline.
    """
    solved_after = fetch_solved_map(cfg)
    if solved_before is None or solved_after is None:
        _log(log, "oracle_skip", "oracle",
             "no grading token or oracle unreachable; oracle_confirmed left unset")
        return
    newly = sorted(k for k, v in solved_after.items()
                   if v and not solved_before.get(k, False))
    # Mark any existing success attempt as confirmed, and add one attempt per
    # newly-solved key the tools didn't already name.
    named = {a.challenge_key for a in findings.payload.attempts if a.challenge_key}
    for a in findings.payload.attempts:
        if a.outcome == "success" and newly:
            a.oracle_confirmed = True
            if a.challenge_key is None:
                a.challenge_key = newly[0]
    for key in newly:
        if key not in named:
            findings.payload.attempts.append(ExploitAttempt(
                vuln_id=f"ORACLE-{key}", technique="deterministic tool (oracle-confirmed solve)",
                outcome="success", evidence=f"Server solve state flipped for '{key}' during the phase.",
                oracle_confirmed=True, challenge_key=key))
    _log(log, "oracle_done", "oracle", f"{len(newly)} challenge(s) newly solved: {', '.join(newly) or 'none'}")


def run_pipeline(cfg: BaselineConfig) -> list[dict]:
    run_dir = cfg.out_root / cfg.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    prior: list[FindingsBase] = []
    state: dict = {}
    phase_records: list[dict] = []

    for phase in cfg.phases:
        findings, rec = run_phase(cfg, phase, prior, state)
        phase_records.append(rec)
        if findings is not None:
            prior.append(findings)
            print(f"[{phase.value}] ok ({rec['duration_s']}s, tools: {', '.join(rec['tools']) or 'none'})")

    _write_manifest(cfg, phase_records)
    _auto_score(cfg)
    return phase_records


def _auto_score(cfg: BaselineConfig) -> None:
    """Best-effort scoring of the finished baseline run (same helper as the AI runner)."""
    if cfg.dry_run:
        return
    from apt.runner import auto_score
    auto_score(cfg.out_root / cfg.run_id, cfg.mode)


def _write_manifest(cfg: BaselineConfig, phase_records: list[dict]) -> None:
    total_duration = round(sum(r["duration_s"] for r in phase_records), 2)
    all_tools = sorted({t for r in phase_records for t in r["tools"]})
    manifest = {
        "run_id": cfg.run_id,
        "kind": "baseline",
        "target": cfg.target,
        "mode": cfg.mode,
        "model": None,
        "tools": all_tools,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "duration_s": total_duration,
        "phases": [
            {"phase": r["phase"], "ok": r["ok"], "tools": r["tools"],
             "duration_s": r["duration_s"],
             "findings": str(cfg.out_root / cfg.run_id / r["phase"] / "findings.json")
             if r["ok"] else None,
             "log": str(cfg.out_root / cfg.run_id / "logs" / f"{r['phase']}.jsonl")}
            for r in phase_records
        ],
        "usage_total": {"cost_usd": 0.0, "total_tokens": 0},
    }
    (cfg.out_root / cfg.run_id / "run.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
