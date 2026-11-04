"""Read-only view over the APT run directory.

The GUI never owns the data model -- the orchestrator (apt/) does. This module
only *reads* what the orchestrator left on disk under ``runs/<run-id>/``:

    run.json                      -- manifest (written when the run finishes)
    <phase>/findings.json         -- validated structured findings per phase
    <phase>/raw/...               -- raw tool output (referenced by findings)
    logs/<phase>.jsonl            -- Claude Code stream-json event log per phase

and turns it into plain dicts the HTTP layer serves as JSON. Nothing here
imports pydantic or the apt package's runtime, so the GUI stays dependency-free
and keeps working even on a partial/in-progress run directory.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator, Optional

# Canonical phase order. We try to borrow it from the apt package so the two
# never drift; if apt isn't importable (e.g. pydantic not installed), fall back
# to the known order. Keep this list in sync with apt/phases.py:ORDER.
try:  # pragma: no cover - trivial import shim
    from apt.phases import ORDER as _APT_ORDER  # type: ignore
    PHASE_ORDER: list[str] = [p.value for p in _APT_ORDER]
except Exception:  # noqa: BLE001 - any import failure falls back
    PHASE_ORDER = [
        "recon", "enumeration", "vuln_assessment", "exploitation",
        "post_exploitation", "reporting", "mitigation",
    ]

PHASE_TITLES = {
    "recon": "Reconnaissance",
    "enumeration": "Enumeration",
    "vuln_assessment": "Vulnerability Assessment",
    "exploitation": "Exploitation",
    "post_exploitation": "Post-Exploitation",
    "reporting": "Reporting",
    "mitigation": "Mitigation Playbook",
}

# A phase dir is considered "active" (being written right now) if its newest
# file changed within this many seconds. Only used when no live launcher status
# is available (e.g. a run started from the CLI, not the GUI).
_ACTIVE_WINDOW_S = 90


def _read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _newest_mtime(path: Path) -> float:
    newest = 0.0
    if path.is_file():
        return path.stat().st_mtime
    for p in path.rglob("*"):
        try:
            newest = max(newest, p.stat().st_mtime)
        except OSError:
            continue
    return newest


class RunStore:
    """Reads runs out of a single ``runs/`` root directory."""

    def __init__(self, runs_root: Path):
        self.root = Path(runs_root)

    # -- listing ------------------------------------------------------------

    def list_runs(self) -> list[dict]:
        if not self.root.is_dir():
            return []
        runs = []
        for d in self.root.iterdir():
            if d.is_dir() and not d.name.startswith("."):
                runs.append(self._run_summary(d))
        # Newest first: run ids are timestamps (YYYYMMDD-HHMMSS) so name sort works.
        runs.sort(key=lambda r: r["run_id"], reverse=True)
        return runs

    def _run_summary(self, run_dir: Path) -> dict:
        manifest = _read_json(run_dir / "run.json")
        phases = self._phase_states(run_dir, manifest)
        status = self._infer_status(run_dir, manifest, phases)
        total_vulns = None
        # Cheap headline number for the list view, if the data is already there.
        vuln = _read_json(run_dir / "vuln_assessment" / "findings.json")
        if vuln:
            total_vulns = len((vuln.get("payload") or {}).get("vulnerabilities") or [])
        return {
            "run_id": run_dir.name,
            "target": (manifest or {}).get("target")
            or self._any_target(run_dir),
            "mode": (manifest or {}).get("mode"),
            "model": (manifest or {}).get("model"),
            "created_at": (manifest or {}).get("created_at"),
            "status": status,
            "phases_done": sum(1 for p in phases if p["state"] == "done"),
            "phases_total": len(phases),
            "current_phase": next(
                (p["phase"] for p in phases if p["state"] == "active"), None
            ),
            "cost_usd": ((manifest or {}).get("usage_total") or {}).get("cost_usd"),
            "vuln_count": total_vulns,
        }

    def _any_target(self, run_dir: Path) -> Optional[str]:
        """Recover the target from any phase's findings if there's no manifest."""
        for phase in PHASE_ORDER:
            f = _read_json(run_dir / phase / "findings.json")
            if f and f.get("target"):
                return f["target"]
        return None

    # -- status / phase state ----------------------------------------------

    def _phase_states(self, run_dir: Path, manifest: Optional[dict]) -> list[dict]:
        """Per-phase state in canonical order: done | active | failed | pending."""
        manifest_phases = {
            p["phase"]: p for p in (manifest or {}).get("phases", [])
        }
        states: list[dict] = []
        # Which phases exist on disk at all (a dir or a log).
        present = set()
        for phase in PHASE_ORDER:
            if (run_dir / phase).is_dir() or (run_dir / "logs" / f"{phase}.jsonl").is_file():
                present.add(phase)

        for phase in PHASE_ORDER:
            mp = manifest_phases.get(phase)
            findings_exists = (run_dir / phase / "findings.json").is_file()
            if mp is not None:
                # Manifest is authoritative once the run has finished.
                state = "done" if mp.get("ok") else "failed"
            elif findings_exists:
                state = "done"
            elif phase in present:
                state = "active"  # has a dir/log but no findings yet -> in progress
            else:
                state = "pending"
            states.append({
                "phase": phase,
                "title": PHASE_TITLES.get(phase, phase),
                "state": state,
                "error": (mp or {}).get("error"),
                "usage": (mp or {}).get("usage"),
                "has_findings": findings_exists,
            })

        # If no manifest, only the *latest* present-but-unfinished phase is truly
        # active; earlier ones with a dir but no findings are stalled, not active.
        if manifest is None:
            actives = [i for i, s in enumerate(states) if s["state"] == "active"]
            for i in actives[:-1]:
                states[i]["state"] = "done" if states[i]["has_findings"] else "stalled"
        return states

    def _infer_status(self, run_dir: Path, manifest: Optional[dict],
                      phases: list[dict]) -> str:
        if manifest is not None:
            if any(p["state"] == "failed" for p in phases):
                return "failed"
            return "completed"
        # No manifest yet: running if something changed very recently, else partial.
        import time
        if time.time() - _newest_mtime(run_dir) < _ACTIVE_WINDOW_S:
            return "running"
        return "partial"

    # -- detail -------------------------------------------------------------

    def run_detail(self, run_id: str) -> Optional[dict]:
        run_dir = self._safe_run_dir(run_id)
        if run_dir is None or not run_dir.is_dir():
            return None
        manifest = _read_json(run_dir / "run.json")
        phases = self._phase_states(run_dir, manifest)
        detail = self._run_summary(run_dir)
        detail["usage_total"] = (manifest or {}).get("usage_total")
        detail["phases"] = []
        for p in phases:
            findings = _read_json(run_dir / p["phase"] / "findings.json")
            detail["phases"].append({**p, "findings": findings})
        detail["report_available"] = (run_dir / "reporting" / "report.md").is_file()
        return detail

    def report_markdown(self, run_id: str) -> Optional[str]:
        run_dir = self._safe_run_dir(run_id)
        if run_dir is None:
            return None
        report = run_dir / "reporting" / "report.md"
        try:
            return report.read_text(encoding="utf-8")
        except OSError:
            return None

    # -- activity stream (the live "what is it doing" feed) -----------------

    def activity(self, run_id: str, phase: str, after: int = 0,
                 limit: int = 500) -> dict:
        """Parse a phase's stream-json log into UI-friendly activity events.

        ``after`` is the sequence number the client already has; only newer
        events are returned, so the live view can poll cheaply.
        """
        run_dir = self._safe_run_dir(run_id)
        events: list[dict] = []
        if run_dir is None or phase not in PHASE_ORDER:
            return {"events": events, "last_seq": after, "complete": False}
        log_path = run_dir / "logs" / f"{phase}.jsonl"
        if not log_path.is_file():
            return {"events": events, "last_seq": after, "complete": False}

        seq = 0
        complete = False
        for raw in self._iter_lines(log_path):
            for ev in self._events_from_line(raw):
                seq += 1
                if ev.get("_type") == "result":
                    complete = True
                if seq <= after:
                    continue
                ev["seq"] = seq
                events.append(ev)
                if len(events) >= limit:
                    return {"events": events, "last_seq": seq, "complete": complete}
        return {"events": events, "last_seq": seq, "complete": complete}

    @staticmethod
    def _iter_lines(path: Path) -> Iterator[str]:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        yield line
        except OSError:
            return

    @staticmethod
    def _events_from_line(raw: str) -> list[dict]:
        """Turn one stream-json line into zero or more flat activity events."""
        try:
            e = json.loads(raw)
        except ValueError:
            return []
        etype = e.get("type")
        out: list[dict] = []

        if etype == "system":
            # Per-turn system/usage events (e.g. subtype "thinking_tokens") are
            # bookkeeping, not activity -- there are hundreds and they bury the
            # real tool calls. Drop them from the stream.
            return []
        if etype == "rate_limit_event":
            out.append({"_type": "rate_limit", "text": "rate limit event"})
        elif etype == "result":
            out.append({
                "_type": "result",
                "is_error": bool(e.get("is_error")),
                "num_turns": e.get("num_turns"),
                "cost_usd": e.get("total_cost_usd"),
                "text": "phase complete" if not e.get("is_error") else "phase error",
            })
        elif etype in ("assistant", "user"):
            for b in (e.get("message", {}) or {}).get("content", []) or []:
                bt = b.get("type")
                if bt == "text":
                    txt = (b.get("text") or "").strip()
                    if txt:
                        out.append({"_type": "text", "text": txt})
                elif bt == "thinking":
                    # Keep only thinking with visible content; redacted blocks
                    # carry just a signature and render as empty noise.
                    txt = (b.get("thinking") or "").strip()
                    if txt:
                        out.append({"_type": "thinking", "text": txt})
                elif bt == "tool_use":
                    out.append(RunStore._tool_use_event(b))
                elif bt == "tool_result":
                    out.append(RunStore._tool_result_event(b))
        return out

    @staticmethod
    def _tool_use_event(b: dict) -> dict:
        name = b.get("name", "tool")
        inp = b.get("input", {}) or {}
        # A short one-line label for the collapsed row, by tool type.
        if name == "Bash":
            label = inp.get("command", "")
        elif name in ("Read", "Write", "Edit"):
            label = inp.get("file_path", "")
        elif name in ("Grep", "Glob"):
            label = inp.get("pattern", "") or inp.get("query", "")
        else:
            label = inp.get("description", "")
        return {
            "_type": "tool_use",
            "tool": name,
            "label": (label or "").strip()[:300],
            "description": (inp.get("description") or "").strip()[:200],
            "input": inp,
        }

    @staticmethod
    def _tool_result_event(b: dict) -> dict:
        content = b.get("content")
        if isinstance(content, list):
            parts = []
            for c in content:
                if isinstance(c, dict) and c.get("type") == "text":
                    parts.append(c.get("text", ""))
            text = "\n".join(parts)
        else:
            text = content if isinstance(content, str) else json.dumps(content)
        text = text or ""
        return {
            "_type": "tool_result",
            "is_error": bool(b.get("is_error")),
            "preview": text[:1500],
            "truncated": len(text) > 1500,
        }

    # -- raw artifacts ------------------------------------------------------

    def raw_file(self, run_id: str, rel_path: str) -> Optional[tuple[bytes, str]]:
        """Return (bytes, content_type) for a raw artifact, or None. Path is
        confined to the run directory -- no traversal out of it."""
        run_dir = self._safe_run_dir(run_id)
        if run_dir is None:
            return None
        target = (run_dir / rel_path).resolve()
        try:
            target.relative_to(run_dir.resolve())
        except ValueError:
            return None  # escaped the run dir
        if not target.is_file():
            return None
        try:
            data = target.read_bytes()
        except OSError:
            return None
        return data, _guess_type(target.name)

    # -- helpers ------------------------------------------------------------

    def _safe_run_dir(self, run_id: str) -> Optional[Path]:
        # Run ids are flat timestamps; reject anything with path separators.
        if not run_id or "/" in run_id or "\\" in run_id or run_id in (".", ".."):
            return None
        d = (self.root / run_id).resolve()
        try:
            d.relative_to(self.root.resolve())
        except ValueError:
            return None
        return d


def _guess_type(name: str) -> str:
    lower = name.lower()
    if lower.endswith(".json"):
        return "application/json; charset=utf-8"
    if lower.endswith((".html", ".htm")):
        return "text/html; charset=utf-8"
    if lower.endswith((".xml",)):
        return "application/xml; charset=utf-8"
    if lower.endswith((".md", ".txt", ".yml", ".yaml", ".log", ".jsonl", ".csv")):
        return "text/plain; charset=utf-8"
    return "application/octet-stream"
