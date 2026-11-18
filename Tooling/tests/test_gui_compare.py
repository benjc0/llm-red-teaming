"""GUI helpers backed by the vuln-list tools: the free-tool lineup, the HTTP
routes that remain, and launching a free-tools run. (The AI-vs-tools comparison
was removed from the console; those metrics live in vuln-list/compare_runs.py.)"""
from __future__ import annotations

import json
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apt_gui import compare  # noqa: E402
from apt_gui.launcher import Launcher, LaunchError  # noqa: E402
from apt_gui.server import make_server  # noqa: E402


def _write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj) if not isinstance(obj, str) else obj, encoding="utf-8")


def _score(run_id, kind, detected, exploited, cost, duration, mode="black-box"):
    return {
        "run_id": run_id, "kind": kind, "mode": mode, "model": None,
        "metrics": {"detection_rate": len(detected) / 10, "exploitation_rate": len(exploited) / 10},
        "detected_keys": detected, "exploited_keys": exploited,
        "usage_total": {"cost_usd": cost}, "duration_s": duration,
    }


@pytest.fixture
def runs(tmp_path: Path) -> Path:
    root = tmp_path / "runs"
    ai = root / "20260101-000000"
    _write(ai / "run.json", {"kind": "ai", "mode": "black-box", "phases": [
        {"phase": "recon", "ok": True, "duration_s": 30, "usage": {"cost_usd": 0.5}}]})
    _write(ai / "recon" / "findings.json", {"payload": {"services": [{}]}})
    _write(ai / "score.json", _score(ai.name, "ai", ["a", "b"], ["a"], 3.0, 180))

    base = root / "base-20260101-000000"
    _write(base / "run.json", {"kind": "baseline", "mode": "black-box", "tools": ["zap"], "phases": [
        {"phase": "vuln_assessment", "ok": True, "duration_s": 40, "tools": ["zap", "nuclei"]}]})
    _write(base / "score.json", _score(base.name, "baseline", ["a"], [], 0.0, 40))

    # Unscored AI run.
    _write(root / "20260102-000000" / "recon" / "findings.json", {"payload": {}})
    return root


def test_tools_by_phase_lists_lineup_and_derived():
    t = compare.tools_by_phase()
    names = {x["name"] for x in t["enumeration"]["tools"]}
    assert {"katana", "ffuf", "arjun"} <= names
    assert {"retirejs", "zap"} <= {x["name"] for x in t["vuln_assessment"]["tools"]}
    assert t["mitigation"]["tools"] == [] and t["mitigation"]["derived"]


def test_compare_routes_are_gone(runs, tmp_path):
    httpd = make_server("127.0.0.1", 0, tmp_path, runs)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        # The comparison routes no longer exist.
        for path in ("/api/compare", "/api/compare.md"):
            try:
                urllib.request.urlopen(base + path)
                assert False, f"{path} should be gone"
            except urllib.error.HTTPError as e:
                assert e.code == 404
        # The routes that stay still work.
        tools = json.loads(urllib.request.urlopen(base + "/api/tools").read())
        assert "recon" in tools["phases"]
        listing = json.loads(urllib.request.urlopen(base + "/api/runs").read())["runs"]
        kinds = {r["run_id"]: (r["kind"], r["scored"]) for r in listing}
        assert kinds["base-20260101-000000"] == ("baseline", True)
        assert kinds["20260102-000000"] == ("ai", False)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_launcher_builds_baseline_command(tmp_path):
    lz = Launcher(tmp_path, tmp_path / "runs")
    cmd, run_id = lz._build_cmd({"target": "http://127.0.0.1:3000", "engine": "baseline",
                                 "phases": "all", "model": "ignored", "unattended": True,
                                 "dry_run": True})
    assert cmd[1:3] == ["-m", "baseline"]
    assert run_id.startswith("base-")
    assert "--model" not in cmd and "--unattended" not in cmd
    assert "--dry-run" in cmd

    cmd, _ = lz._build_cmd({"target": "http://127.0.0.1:3000", "model": "m"})
    assert cmd[1:3] == ["-m", "apt"] and "--model" in cmd

    with pytest.raises(LaunchError):
        lz._build_cmd({"target": "http://127.0.0.1:3000", "engine": "nope"})
