"""The orchestrator confirms exploits against the server-side solve oracle and
stamps `oracle_confirmed` — and must NOT leak the grading token to the agent.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apt.runner import RunConfig, run_phase, stamp_oracle  # noqa: E402
from apt.schema import ExploitAttempt, ExploitFindings, ExploitPayload, Phase  # noqa: E402


def _attempt(vuln_id, key=None):
    return ExploitAttempt(vuln_id=vuln_id, technique="t", outcome="success",
                          evidence="e", challenge_key=key)


def test_stamp_oracle_sets_true_false_and_leaves_unknowns_none():
    findings = ExploitFindings(
        run_id="r", target="t", summary="s",
        payload=ExploitPayload(attempts=[
            _attempt("V1", "loginAdminChallenge"),   # solved -> True
            _attempt("V2", "unsolvedChallenge"),     # present, not solved -> False
            _attempt("V3", "keyNotInOracle"),        # unknown key -> None
            _attempt("V4", None),                    # no key -> None
        ]),
    )
    solved = {"loginAdminChallenge": True, "unsolvedChallenge": False}

    matched = stamp_oracle(findings, solved)

    att = findings.payload.attempts
    assert matched == 2                              # two attempts had a known key
    assert att[0].oracle_confirmed is True
    assert att[1].oracle_confirmed is False
    assert att[2].oracle_confirmed is None
    assert att[3].oracle_confirmed is None


def test_grading_token_is_not_visible_to_the_agent_subprocess(tmp_path, monkeypatch):
    # Fake claude records whatever APT_GRADING_TOKEN it can see, then writes valid findings.
    script = tmp_path / "fake_claude.py"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import os, json, pathlib\n"
        "pathlib.Path('leaked.txt').write_text(os.environ.get('APT_GRADING_TOKEN', '<absent>'))\n"
        "pathlib.Path('findings.json').write_text(json.dumps({\n"
        "  'apt_schema_version':'1.0','run_id':'r','target':'t','summary':'s',\n"
        "  'phase': pathlib.Path.cwd().name, 'payload': {}}))\n"
    )
    script.chmod(0o755)
    monkeypatch.setenv("APT_GRADING_TOKEN", "super-secret-token")

    cfg = RunConfig(target="http://t", out_root=tmp_path / "runs",
                    claude_bin=str(script), grading_token="super-secret-token")
    run_phase(cfg, Phase.recon, prior=[])

    leaked = (cfg.out_root / cfg.run_id / "recon" / "leaked.txt").read_text()
    assert leaked == "<absent>", "the agent subprocess could read the grading token"
