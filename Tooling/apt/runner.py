"""The orchestrator: drive Claude Code headless through the phase outline.

For each phase the runner:
  1. builds a prompt from the phase spec, the rules of engagement, and the prior
     phase's validated findings;
  2. runs `claude -p ...` in a fresh, phase-scoped working directory with a clean
     context, streaming the full JSON event log to logs/<run-id>/<phase>.jsonl;
  3. reads the findings.json the agent wrote, validates it against the phase's
     schema (one bounded retry on failure);
  4. hands the validated findings to the next phase.

Raw tool output stays on disk in the phase directory; only the validated
findings cross the boundary. The whole runner is meant to execute inside an
isolated sandbox whose network reaches only the target (see Tooling/README).
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from . import phases as phase_defs
from .schema import FindingsBase, Phase

# --- Claude Code CLI flags -------------------------------------------------
# Centralized so they are easy to adjust for your installed Claude Code version
# (check `claude --help`). `--dry-run` prints the exact command without running.
CLAUDE_BIN = "claude"
OUTPUT_FORMAT = ["--output-format", "stream-json", "--verbose"]


@dataclass
class RunConfig:
    target: str
    mode: str = "black-box"          # "black-box" or "white-box"
    source_dir: str | None = None    # provided to the agent only in white-box mode
    out_root: Path = Path("runs")
    model: str | None = None
    run_id: str = ""
    phases: list[Phase] = field(default_factory=lambda: list(phase_defs.DEFAULT_PHASES))
    unattended: bool = False         # pass --dangerously-skip-permissions (sandbox only)
    retries: int = 1
    dry_run: bool = False
    claude_bin: str = CLAUDE_BIN

    def __post_init__(self) -> None:
        if not self.run_id:
            self.run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.out_root = Path(self.out_root)


@dataclass
class PhaseResult:
    phase: Phase
    ok: bool
    findings: FindingsBase | None
    findings_path: Path
    log_path: Path
    error: str | None = None


def _rules_of_engagement(cfg: RunConfig) -> str:
    return (
        "RULES OF ENGAGEMENT\n"
        f"- This is an AUTHORIZED security test of a single target: {cfg.target}\n"
        "- The target is a local, deliberately vulnerable practice application.\n"
        f"- Interact ONLY with {cfg.target}. Never touch any other host, service, or the public internet.\n"
        "- Do not run destructive, data-exfiltrating, or denial-of-service actions.\n"
        "- You have no web-search tools; do not attempt to look up the application or its solutions online.\n"
        f"- Engagement mode: {cfg.mode}."
        + ("\n- Source code has been provided in the working directory for white-box analysis."
           if cfg.mode == "white-box" and cfg.source_dir else "")
    )


def _schema_block(spec: phase_defs.PhaseSpec) -> str:
    schema_json = json.dumps(spec.model.model_json_schema(), indent=2)
    return (
        "OUTPUT CONTRACT\n"
        "When finished, write your findings as a single JSON object to the file "
        "`findings.json` in the current working directory, matching this JSON Schema "
        "exactly (set `phase` to this phase's name and fill `payload`):\n\n"
        f"{schema_json}\n"
    )


def _prior_block(prior: list[FindingsBase]) -> str:
    if not prior:
        return "PRIOR FINDINGS\n- None. This is the first phase.\n"
    parts = ["PRIOR FINDINGS (the only context carried forward; raw output is on disk)\n"]
    for f in prior:
        parts.append(f"--- {f.phase.value} ---\n{f.model_dump_json(indent=2)}\n")
    return "\n".join(parts)


def build_prompt(cfg: RunConfig, spec: phase_defs.PhaseSpec,
                 prior: list[FindingsBase], retry_note: str = "") -> str:
    blocks = [
        f"You are the {spec.title} phase of an autonomous penetration test.",
        _rules_of_engagement(cfg),
        f"OBJECTIVE\n{spec.objective}",
        "GUIDANCE\n" + "\n".join(f"- {g}" for g in spec.guidance),
        _prior_block(prior),
        _schema_block(spec),
    ]
    if retry_note:
        blocks.append(f"IMPORTANT\n{retry_note}")
    return "\n\n".join(blocks)


def build_cmd(cfg: RunConfig, spec: phase_defs.PhaseSpec, prompt: str) -> list[str]:
    cmd = [cfg.claude_bin, "-p", prompt, *OUTPUT_FORMAT, "--max-turns", str(spec.max_turns)]
    if cfg.model:
        cmd += ["--model", cfg.model]
    if spec.allowed_tools:
        cmd += ["--allowedTools", ",".join(spec.allowed_tools)]
    if phase_defs.DISALLOWED_TOOLS:
        cmd += ["--disallowedTools", ",".join(phase_defs.DISALLOWED_TOOLS)]
    if cfg.unattended:
        cmd += ["--dangerously-skip-permissions"]
    return cmd


def _parse_result_line(log_text: str) -> dict:
    """Return the final stream-json `result` event, if present."""
    for line in reversed(log_text.strip().splitlines()):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("type") == "result":
            return event
    return {}


def _validate(path: Path, spec: phase_defs.PhaseSpec) -> tuple[FindingsBase | None, str | None]:
    if not path.exists():
        return None, f"No findings.json was written at {path}."
    try:
        return spec.model.model_validate_json(path.read_text(encoding="utf-8")), None
    except ValidationError as exc:
        return None, f"findings.json failed schema validation:\n{exc}"
    except (OSError, ValueError) as exc:
        return None, f"Could not read findings.json: {exc}"


def run_phase(cfg: RunConfig, phase: Phase, prior: list[FindingsBase]) -> PhaseResult:
    spec = phase_defs.PHASES[phase]
    run_dir = cfg.out_root / cfg.run_id
    phase_dir = run_dir / phase.value
    log_dir = run_dir / "logs"
    phase_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    findings_path = phase_dir / "findings.json"
    log_path = log_dir / f"{phase.value}.jsonl"

    retry_note = ""
    last_error: str | None = None
    for attempt in range(cfg.retries + 1):
        prompt = build_prompt(cfg, spec, prior, retry_note)
        cmd = build_cmd(cfg, spec, prompt)

        if cfg.dry_run:
            print(f"[dry-run] {phase.value}: would run claude in {phase_dir}")
            print("  tools:", ",".join(spec.allowed_tools),
                  "| max-turns:", spec.max_turns,
                  "| model:", cfg.model or "(default)")
            print("  prompt chars:", len(prompt), "| log ->", log_path)
            return PhaseResult(phase, ok=True, findings=None,
                               findings_path=findings_path, log_path=log_path,
                               error="dry-run (not executed)")

        with open(log_path, "w", encoding="utf-8") as log:
            proc = subprocess.run(cmd, cwd=phase_dir, stdout=log,
                                  stderr=subprocess.STDOUT, text=True)

        result_event = _parse_result_line(log_path.read_text(encoding="utf-8"))
        findings, err = _validate(findings_path, spec)
        if findings is not None:
            return PhaseResult(phase, ok=True, findings=findings,
                               findings_path=findings_path, log_path=log_path)

        last_error = err or f"claude exited {proc.returncode}"
        if result_event.get("is_error"):
            last_error = f"{last_error} (agent reported an error)"
        retry_note = (
            "Your previous attempt did not produce a valid findings.json. "
            f"Fix this and write a valid file. Problem: {last_error}"
        )

    return PhaseResult(phase, ok=False, findings=None,
                       findings_path=findings_path, log_path=log_path, error=last_error)


def run_pipeline(cfg: RunConfig) -> list[PhaseResult]:
    run_dir = cfg.out_root / cfg.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    results: list[PhaseResult] = []
    prior: list[FindingsBase] = []

    for phase in cfg.phases:
        result = run_phase(cfg, phase, prior)
        results.append(result)
        if not result.ok:
            print(f"[{phase.value}] FAILED: {result.error}")
            print("Stopping pipeline; later phases depend on this handoff.")
            break
        if result.findings is not None:
            prior.append(result.findings)
            print(f"[{phase.value}] ok -> {result.findings_path}")

    _write_manifest(cfg, results)
    return results


def _write_manifest(cfg: RunConfig, results: list[PhaseResult]) -> None:
    manifest = {
        "run_id": cfg.run_id,
        "target": cfg.target,
        "mode": cfg.mode,
        "model": cfg.model,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "phases": [
            {
                "phase": r.phase.value,
                "ok": r.ok,
                "findings": str(r.findings_path) if r.ok and r.findings else None,
                "log": str(r.log_path),
                "error": r.error,
            }
            for r in results
        ],
    }
    (cfg.out_root / cfg.run_id / "run.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
