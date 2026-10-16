"""Regression test: white-box mode must actually make the source tree
available to the agent, not just mention it in the prompt.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apt.runner import RunConfig, run_phase  # noqa: E402
from apt.schema import Phase  # noqa: E402

FAKE_CLAUDE_SCRIPT = """#!/usr/bin/env python3
import json
import pathlib

findings = {
    "apt_schema_version": "1.0",
    "run_id": "test",
    "target": "http://127.0.0.1:3000",
    "summary": "stub",
    "phase": "recon",
    "payload": {},
}
pathlib.Path("findings.json").write_text(json.dumps(findings))
"""


@pytest.fixture
def fake_claude_bin(tmp_path: Path) -> str:
    script = tmp_path / "fake_claude.py"
    script.write_text(FAKE_CLAUDE_SCRIPT)
    script.chmod(0o755)
    return str(script)


def test_white_box_source_is_copied_into_phase_working_dir(tmp_path: Path, fake_claude_bin: str) -> None:
    source_dir = tmp_path / "clean-source"
    source_dir.mkdir()
    (source_dir / "app.ts").write_text("console.log('vulnerable')")

    cfg = RunConfig(
        target="http://127.0.0.1:3000",
        mode="white-box",
        source_dir=str(source_dir),
        out_root=tmp_path / "runs",
        claude_bin=fake_claude_bin,
    )

    result = run_phase(cfg, Phase.recon, prior=[])

    assert result.ok, result.error
    phase_dir = cfg.out_root / cfg.run_id / Phase.recon.value
    copied = phase_dir / "source" / "app.ts"
    assert copied.exists(), "white-box source tree was never placed in the phase working directory"
    assert copied.read_text() == "console.log('vulnerable')"


def test_black_box_mode_never_stages_a_source_dir(tmp_path: Path, fake_claude_bin: str) -> None:
    cfg = RunConfig(
        target="http://127.0.0.1:3000",
        mode="black-box",
        out_root=tmp_path / "runs",
        claude_bin=fake_claude_bin,
    )

    result = run_phase(cfg, Phase.recon, prior=[])

    assert result.ok, result.error
    phase_dir = cfg.out_root / cfg.run_id / Phase.recon.value
    assert not (phase_dir / "source").exists()


def test_dry_run_does_not_copy_source(tmp_path: Path, fake_claude_bin: str) -> None:
    source_dir = tmp_path / "clean-source"
    source_dir.mkdir()
    (source_dir / "app.ts").write_text("console.log('vulnerable')")

    cfg = RunConfig(
        target="http://127.0.0.1:3000",
        mode="white-box",
        source_dir=str(source_dir),
        out_root=tmp_path / "runs",
        claude_bin=fake_claude_bin,
        dry_run=True,
    )

    run_phase(cfg, Phase.recon, prior=[])

    phase_dir = cfg.out_root / cfg.run_id / Phase.recon.value
    assert not (phase_dir / "source").exists()
