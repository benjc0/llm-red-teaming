"""The GUI's AI-vs-free-tools comparison: per-phase stats, the comparison
payload, its HTTP routes, and launching a free-tools run."""
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


def _score(run_id, kind, detected, exploited, missed, cost, duration, mode="black-box"):
    return {
        "run_id": run_id, "kind": kind, "mode": mode, "model": None, "tools": None,
        "graded_total": 10, "reported_count": 4,
        "metrics": {"detection_rate": len(detected) / 10, "exploitation_rate": len(exploited) / 10,
                    "precision": 0.5, "recall": len(detected) / 10, "f1": 0.3,
                    "detected": len(detected), "exploited": len(exploited),
                    "matched_findings": 2, "false_positives": 2, "needs_review": 0},
        "by_owasp": {"A03:2021 Injection": {"hit": len(exploited), "total": 4, "rate": len(exploited) / 4}},
        "detection_by_owasp": {"A03:2021 Injection": {"hit": len(detected), "total": 4, "rate": len(detected) / 4}},
        "by_difficulty": {"1": {"hit": len(exploited), "total": 5, "rate": len(exploited) / 5}},
        "detected_keys": detected, "exploited_keys": exploited, "missed_keys": missed,
        "usage_total": {"cost_usd": cost}, "duration_s": duration,
    }


@pytest.fixture
def runs(tmp_path: Path) -> Path:
    root = tmp_path / "runs"
    # AI run: recon + vuln + exploitation, with a stream-json log for recon.
    ai = root / "20260101-000000"
    _write(ai / "run.json", {"kind": "ai", "mode": "black-box", "phases": [
        {"phase": "recon", "ok": True, "duration_s": 30, "usage": {"cost_usd": 0.5}},
        {"phase": "vuln_assessment", "ok": True, "duration_s": 60, "usage": {"cost_usd": 1.0}},
        {"phase": "exploitation", "ok": True, "duration_s": 90, "usage": {"cost_usd": 1.5}}]})
    _write(ai / "recon" / "findings.json", {"payload": {"services": [{}], "tech_stack": ["a", "b"], "endpoints": []}})
    _write(ai / "vuln_assessment" / "findings.json", {"payload": {"vulnerabilities": [{}, {}, {}]}})
    _write(ai / "exploitation" / "findings.json", {"payload": {"attempts": [
        {"oracle_confirmed": True}, {"oracle_confirmed": False}]}})
    log = [{"type": "assistant", "message": {"content": [
        {"type": "tool_use", "name": "Bash", "input": {"command": "curl -s http://t/ | grep -i x && nmap -p 3000 t"}}]}},
           {"type": "assistant", "message": {"content": [
        {"type": "tool_use", "name": "Bash", "input": {"command": "cat <<EOF > notes.txt\nversion 1\nEOF"}}]}}]
    _write(ai / "logs" / "recon.jsonl", "\n".join(json.dumps(x) for x in log))
    _write(ai / "score.json", _score(ai.name, "ai", ["a", "b", "c"], ["a", "b"], ["d", "e"], 3.0, 180))

    # Baseline run: vuln assessment only.
    base = root / "base-20260101-000000"
    _write(base / "run.json", {"kind": "baseline", "mode": "black-box", "tools": ["zap"], "phases": [
        {"phase": "vuln_assessment", "ok": True, "duration_s": 40, "tools": ["zap", "nuclei"]}]})
    _write(base / "vuln_assessment" / "findings.json", {"payload": {"vulnerabilities": [{}]}})
    _write(base / "score.json", _score(base.name, "baseline", ["a", "d"], [], ["b", "c", "e"], 0.0, 40))

    # Unscored AI run.
    _write(root / "20260102-000000" / "recon" / "findings.json", {"payload": {}})
    return root


def test_phase_stats_counts_time_cost_and_ai_tools(runs):
    st = compare.phase_stats(runs / "20260101-000000")
    assert st["recon"]["counts"] == {"services": 1, "tech_stack": 2, "endpoints": 0}
    assert st["exploitation"]["counts"] == {"attempts": 2, "confirmed": 1}
    assert st["recon"]["duration_s"] == 30 and st["recon"]["cost_usd"] == 0.5
    # Real programs only; heredoc body lines are not "tools".
    assert st["recon"]["tools"] == ["curl", "grep", "nmap"]
    assert not st["enumeration"]["ran"]

    bst = compare.phase_stats(runs / "base-20260101-000000")
    assert bst["vuln_assessment"]["tools"] == ["zap", "nuclei"]
    assert bst["vuln_assessment"]["cost_usd"] == 0.0


def test_build_compares_sides_and_overlap(runs):
    d = compare.build(runs, ["20260101-000000", "base-20260101-000000", "20260102-000000"])
    assert d["unscored"] == ["20260102-000000"]
    assert d["ai"]["trials"] == 1 and d["baseline"]["trials"] == 1
    assert d["overlap"]["detection"] == {"ai_only": ["b", "c"], "both": ["a"], "baseline_only": ["d"]}
    assert d["missed_by_both"] == ["e"]
    m = d["ai"]["metrics"]
    assert m["cost_per_exploit"]["mean"] == 1.5      # $3.00 / 2 exploits
    assert m["time_per_exploit"]["mean"] == 90.0     # 180 s / 2
    assert d["baseline"]["metrics"]["cost_per_exploit"]["mean"] is None  # no exploits
    # The sides covered different phases, so the view must say time/cost aren't like-for-like.
    assert any("different phases" in w for w in d["warnings"])


def test_default_selection_picks_one_of_each_kind(runs):
    assert sorted(compare.default_selection(runs)) == ["20260101-000000", "base-20260101-000000"]


def test_build_ignores_traversal_ids(runs):
    d = compare.build(runs, ["../etc", "a/b"])
    assert d["ai"] is None and d["baseline"] is None and d["missing"] == []


def test_tools_by_phase_lists_lineup_and_derived():
    t = compare.tools_by_phase()
    names = {x["name"] for x in t["enumeration"]["tools"]}
    assert {"katana", "ffuf", "arjun"} <= names
    assert {"retirejs", "zap"} <= {x["name"] for x in t["vuln_assessment"]["tools"]}
    assert t["mitigation"]["tools"] == [] and t["mitigation"]["derived"]


def test_http_routes(runs, tmp_path):
    httpd = make_server("127.0.0.1", 0, tmp_path, runs)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        d = json.loads(urllib.request.urlopen(base + "/api/compare").read())
        assert d["ai"]["run_ids"] == ["20260101-000000"]
        assert "_comparison" not in d
        md = urllib.request.urlopen(base + "/api/compare.md").read().decode()
        assert md.startswith("# Run comparison")
        tools = json.loads(urllib.request.urlopen(base + "/api/tools").read())
        assert "recon" in tools["phases"]
        listing = json.loads(urllib.request.urlopen(base + "/api/runs").read())["runs"]
        kinds = {r["run_id"]: (r["kind"], r["scored"], r["scorable"]) for r in listing}
        assert kinds["base-20260101-000000"] == ("baseline", True, True)
        assert kinds["20260102-000000"] == ("ai", False, False)
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
