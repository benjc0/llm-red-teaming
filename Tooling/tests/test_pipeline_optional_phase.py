"""A failing OPTIONAL phase (post-exploitation) must not abort the pipeline:
reporting and mitigation depend on the exploitation findings, not on post-ex,
so they should still run. A failing REQUIRED phase must still stop it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apt.runner import RunConfig, run_pipeline  # noqa: E402
from apt.schema import Phase  # noqa: E402

# Fake `claude`: writes a minimal valid findings.json for whatever phase it is
# invoked in (phase == the cwd directory name), EXCEPT the phase named in
# FAKE_FAIL_PHASE, where it writes nothing — simulating a blocked/failed phase.
FAKE_CLAUDE_SCRIPT = """#!/usr/bin/env python3
import json, os, pathlib
phase = pathlib.Path.cwd().name
if phase == os.environ.get("FAKE_FAIL_PHASE"):
    raise SystemExit(1)
pathlib.Path("findings.json").write_text(json.dumps({
    "apt_schema_version": "1.0", "run_id": "test", "target": "http://t",
    "summary": "stub", "phase": phase, "payload": {},
}))
"""


@pytest.fixture
def fake_claude_bin(tmp_path: Path) -> str:
    script = tmp_path / "fake_claude.py"
    script.write_text(FAKE_CLAUDE_SCRIPT)
    script.chmod(0o755)
    return str(script)


def _run(tmp_path, fake_claude_bin, phases, fail_phase, monkeypatch):
    monkeypatch.setenv("FAKE_FAIL_PHASE", fail_phase)
    cfg = RunConfig(
        target="http://127.0.0.1:3000",
        out_root=tmp_path / "runs",
        claude_bin=fake_claude_bin,
        phases=phases,
        retries=0,
    )
    return {r.phase: r for r in run_pipeline(cfg)}


def test_failed_post_exploitation_does_not_block_reporting(tmp_path, fake_claude_bin, monkeypatch):
    results = _run(
        tmp_path, fake_claude_bin,
        [Phase.exploitation, Phase.post_exploitation, Phase.reporting],
        fail_phase="post_exploitation", monkeypatch=monkeypatch,
    )

    assert results[Phase.exploitation].ok
    assert not results[Phase.post_exploitation].ok           # it failed...
    assert Phase.reporting in results                        # ...but reporting still ran
    assert results[Phase.reporting].ok


def test_failed_required_phase_still_stops_pipeline(tmp_path, fake_claude_bin, monkeypatch):
    results = _run(
        tmp_path, fake_claude_bin,
        [Phase.exploitation, Phase.reporting],
        fail_phase="exploitation", monkeypatch=monkeypatch,
    )

    assert not results[Phase.exploitation].ok
    assert Phase.reporting not in results                    # pipeline stopped before it
