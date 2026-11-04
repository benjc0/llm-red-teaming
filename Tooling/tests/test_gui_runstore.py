"""The GUI's read-only view over the run directory: run listing/status
inference, stream-json activity parsing (noise filtered), and path-safe raw
artifact reads. The GUI never writes run data, so these are the load-bearing
tests for it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apt_gui.runstore import RunStore  # noqa: E402


def _write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj) if not isinstance(obj, str) else obj,
                    encoding="utf-8")


def _findings(phase: str, payload: dict, run_id="R", target="http://t:3000") -> dict:
    return {
        "apt_schema_version": "1.0", "run_id": run_id, "target": target,
        "phase": phase, "summary": f"{phase} summary", "payload": payload,
        "raw_artifacts": [], "next_steps": [],
    }


def test_completed_run_status_from_manifest(tmp_path):
    run = tmp_path / "20260101-000000"
    _write(run / "run.json", {
        "run_id": "20260101-000000", "target": "http://t:3000", "mode": "black-box",
        "phases": [{"phase": "recon", "ok": True}, {"phase": "enumeration", "ok": True}],
        "usage_total": {"cost_usd": 1.23, "total_tokens": 1000},
    })
    _write(run / "recon" / "findings.json", _findings("recon", {"endpoints": []}))
    _write(run / "enumeration" / "findings.json", _findings("enumeration", {}))

    store = RunStore(tmp_path)
    runs = store.list_runs()
    assert len(runs) == 1
    assert runs[0]["status"] == "completed"
    assert runs[0]["cost_usd"] == 1.23

    detail = store.run_detail("20260101-000000")
    states = {p["phase"]: p["state"] for p in detail["phases"]}
    assert states["recon"] == "done"
    assert states["vuln_assessment"] == "pending"  # never ran


def test_failed_phase_marks_run_failed(tmp_path):
    run = tmp_path / "20260101-000001"
    _write(run / "run.json", {
        "run_id": "20260101-000001", "target": "http://t:3000",
        "phases": [{"phase": "recon", "ok": True},
                   {"phase": "enumeration", "ok": False, "error": "boom"}],
    })
    _write(run / "recon" / "findings.json", _findings("recon", {}))
    store = RunStore(tmp_path)
    assert store.list_runs()[0]["status"] == "failed"
    detail = store.run_detail("20260101-000001")
    enum = next(p for p in detail["phases"] if p["phase"] == "enumeration")
    assert enum["state"] == "failed"
    assert enum["error"] == "boom"


def test_in_progress_phase_without_manifest_is_active(tmp_path):
    # A phase dir + log but no findings.json and no run.json => the phase is
    # running right now. (No manifest => status running only if recently touched;
    # we assert phase state here, which does not depend on mtime.)
    run = tmp_path / "20260101-000002"
    _write(run / "recon" / "findings.json", _findings("recon", {}))
    _write(run / "logs" / "enumeration.jsonl", '{"type":"system"}\n')
    (run / "enumeration").mkdir(parents=True, exist_ok=True)

    detail = RunStore(tmp_path).run_detail("20260101-000002")
    states = {p["phase"]: p["state"] for p in detail["phases"]}
    assert states["recon"] == "done"
    assert states["enumeration"] == "active"


def test_activity_filters_noise_and_parses_tools(tmp_path):
    run = tmp_path / "20260101-000003"
    log = run / "logs" / "recon.jsonl"
    events = [
        {"type": "system", "subtype": "thinking_tokens"},   # dropped
        {"type": "system", "subtype": "init"},               # dropped
        {"type": "assistant", "message": {"content": [
            {"type": "thinking", "thinking": "", "signature": "x"},   # empty -> dropped
            {"type": "text", "text": "Starting recon."},
            {"type": "tool_use", "name": "Bash",
             "input": {"command": "curl -s http://t:3000/", "description": "fetch root"}},
        ]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "content": "HTTP/1.1 200 OK", "is_error": False},
        ]}},
        {"type": "result", "is_error": False, "num_turns": 3, "total_cost_usd": 0.1},
    ]
    _write(log, "\n".join(json.dumps(e) for e in events))

    data = RunStore(tmp_path).activity("20260101-000003", "recon")
    kinds = [e["_type"] for e in data["events"]]
    assert kinds == ["text", "tool_use", "tool_result", "result"]  # no system/empty-thinking
    assert data["complete"] is True
    tu = data["events"][1]
    assert tu["tool"] == "Bash"
    assert tu["label"].startswith("curl -s")


def test_activity_after_paginates(tmp_path):
    run = tmp_path / "20260101-000004"
    log = run / "logs" / "recon.jsonl"
    events = [
        {"type": "assistant", "message": {"content": [
            {"type": "text", "text": "one"},
            {"type": "text", "text": "two"},
            {"type": "text", "text": "three"},
        ]}},
    ]
    _write(log, "\n".join(json.dumps(e) for e in events))
    store = RunStore(tmp_path)
    first = store.activity("20260101-000004", "recon", after=0, limit=2)
    assert [e["text"] for e in first["events"]] == ["one", "two"]
    assert first["last_seq"] == 2
    rest = store.activity("20260101-000004", "recon", after=first["last_seq"])
    assert [e["text"] for e in rest["events"]] == ["three"]


def test_raw_file_blocks_traversal(tmp_path):
    run = tmp_path / "20260101-000005"
    _write(run / "recon" / "root.txt", "hello")
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")

    store = RunStore(tmp_path)
    ok = store.raw_file("20260101-000005", "recon/root.txt")
    assert ok is not None and ok[0] == b"hello"
    assert store.raw_file("20260101-000005", "../secret.txt") is None
    assert store.raw_file("20260101-000005", "../../etc/passwd") is None
    assert store.raw_file("../20260101-000005", "recon/root.txt") is None
