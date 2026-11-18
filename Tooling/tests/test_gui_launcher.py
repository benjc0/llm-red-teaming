"""The GUI launcher builds the orchestrator command line from form params.
These lock the parts that silently break: engine selection, white-box source,
and the custom-prompts file wiring.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apt_gui.launcher import Launcher, LaunchError  # noqa: E402


@pytest.fixture
def launcher(tmp_path: Path) -> Launcher:
    return Launcher(tmp_path, tmp_path / "runs")


def test_ai_run_forwards_prompts_file(launcher, tmp_path):
    (tmp_path / "p.yml").write_text("recon: {objective: x}")
    cmd, _ = launcher._build_cmd(
        {"target": "http://127.0.0.1:3000", "engine": "ai", "phases": "recon", "prompts": "p.yml"})
    assert "--prompts" in cmd and cmd[cmd.index("--prompts") + 1] == "p.yml"
    assert cmd[1:3] == ["-m", "apt"]


def test_missing_prompts_file_is_rejected(launcher):
    with pytest.raises(LaunchError):
        launcher._build_cmd({"target": "http://x:3000", "engine": "ai", "prompts": "nope.yml"})


def test_baseline_ignores_prompts(launcher, tmp_path):
    (tmp_path / "p.yml").write_text("recon: {objective: x}")
    cmd, _ = launcher._build_cmd(
        {"target": "http://x:3000", "engine": "baseline", "prompts": "p.yml"})
    assert "--prompts" not in cmd
    assert cmd[1:3] == ["-m", "baseline"]


def test_white_box_requires_source(launcher):
    with pytest.raises(LaunchError):
        launcher._build_cmd({"target": "http://x:3000", "engine": "ai", "mode": "white-box"})
