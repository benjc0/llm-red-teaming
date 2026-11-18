"""The deterministic baseline: adapters normalize real tool output into the
APT schema, and the runner assembles a scorable findings set from them.

These exercise the pure parts (adapters + build_findings); the Docker/native
tool execution is not invoked here.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apt.schema import Confidence, ExploitFindings, Phase, VulnFindings  # noqa: E402
from baseline import runner  # noqa: E402
from baseline.adapters import nikto, nmap, nuclei, sqlmap, zap  # noqa: E402
from baseline.runner import BaselineConfig, build_findings  # noqa: E402

NMAP_XML = """<?xml version="1.0"?><nmaprun><host><address addr="127.0.0.1"/>
<ports><port protocol="tcp" portid="3000"><state state="open"/>
<service name="http" product="Node.js Express framework" version="1.0"/></port></ports>
</host></nmaprun>"""

ZAP_JSON = {"site": [{"@name": "http://t", "alerts": [
    {"name": "SQL Injection", "cweid": "89", "riskdesc": "High (Medium)",
     "desc": "Injectable", "solution": "Use parameterized queries.",
     "reference": "https://owasp.org/sqli", "instances": [{"uri": "http://t/rest/user/login"}]},
    {"name": "X-Frame-Options Header Missing", "cweid": "16", "riskdesc": "Low (Medium)",
     "desc": "No XFO", "instances": [{"uri": "http://t/"}]},
]}]}

NUCLEI_JSONL = ('{"template-id":"weak-cipher","info":{"name":"Weak Cipher",'
                '"severity":"medium","classification":{"cwe-id":["CWE-327"]}},'
                '"matched-at":"t:443"}')

NIKTO_JSON = {"host": "t", "vulnerabilities": [
    {"url": "http://t/", "method": "GET", "msg": "X-Content-Type-Options header is not set."}]}


def _cfg():
    return BaselineConfig(target="http://t", run_id="base-test", dry_run=True)


def test_nmap_adapter_extracts_services_and_stack():
    out = nmap.parse(NMAP_XML)
    assert out["services"][0].port == 3000
    assert "Node.js Express framework" in out["tech_stack"]


def test_zap_adapter_sets_cwe_owasp_and_mitigation():
    out = zap.parse(ZAP_JSON)
    sqli = out["vulnerabilities"][0]
    assert sqli.cwe == "CWE-89"
    assert sqli.owasp_web == "A03:2021 Injection"
    assert sqli.confidence == Confidence.high
    assert out["mitigations"]["ZAP-001"]["reference"] == "https://owasp.org/sqli"


def test_nikto_keyword_cwe_table():
    out = nikto.parse(NIKTO_JSON)
    assert out["vulnerabilities"][0].cwe == "CWE-16"


def test_vuln_phase_merges_tools_and_dedupes():
    cfg = _cfg()
    state: dict = {}
    findings = build_findings(
        Phase.vuln_assessment, cfg,
        {"zap": ZAP_JSON, "nuclei": NUCLEI_JSONL, "nikto": NIKTO_JSON},
        prior=[], state=state,
    )
    assert isinstance(findings, VulnFindings)
    cwes = {v.cwe for v in findings.payload.vulnerabilities}
    assert {"CWE-89", "CWE-16", "CWE-327"} <= cwes
    # Mitigation side channel is stashed for the mitigation phase.
    assert "ZAP-001" in state["mitigations"]


def test_exploitation_oracle_delta_adds_confirmed_attempt():
    cfg = _cfg()
    findings = build_findings(Phase.exploitation, cfg, {}, prior=[], state={})
    assert isinstance(findings, ExploitFindings)
    # Simulate the server solving loginAdminChallenge during the phase.
    class _Log:
        def write(self, *_): pass
        def flush(self): pass
    # Drive attribution directly with before/after oracle snapshots.
    import baseline.runner as r
    orig = r.fetch_solved_map
    r.fetch_solved_map = lambda cfg: {"loginAdminChallenge": True}
    try:
        r._attribute_oracle(cfg, findings, {"loginAdminChallenge": False}, _Log())
    finally:
        r.fetch_solved_map = orig
    confirmed = [a for a in findings.payload.attempts if a.oracle_confirmed]
    assert any(a.challenge_key == "loginAdminChallenge" for a in confirmed)


def test_mitigation_falls_back_to_cwe_cheatsheet():
    cfg = _cfg()
    state: dict = {}
    vuln = build_findings(Phase.vuln_assessment, cfg, {"nuclei": NUCLEI_JSONL}, [], state)
    mit = build_findings(Phase.mitigation, cfg, {}, prior=[vuln], state=state)
    item = mit.payload.items[0]
    assert item.vuln_id == vuln.payload.vulnerabilities[0].id
    assert "cheatsheetseries.owasp.org" in (item.reference or "")


# --- gap-fill tools: Arjun (params), Retire.js (A06), ZAP active scan (exploit) ---

def test_arjun_params_and_api_surface():
    from baseline.adapters import arjun
    out = arjun.parse({"http://t/rest/products/search": {"method": "GET", "params": ["q"]},
                       "http://t/api/Users": {"method": "JSON", "params": ["email", "role"]},
                       "http://t/nothing": {"method": "GET", "params": []}})
    assert [(p.endpoint, p.name, p.location) for p in out["params"]] == [
        ("GET /rest/products/search", "q", "query"),
        ("POST /api/Users", "email", "body"), ("POST /api/Users", "role", "body")]
    assert out["api_surface"] == ["/rest/products/search", "/api/Users"]


def test_retirejs_maps_to_a06_and_dedupes():
    from baseline.adapters import retirejs
    vuln = {"severity": "medium", "identifiers": {"summary": "XSS in jQuery", "CVE": ["CVE-2020-11022"]},
            "info": ["https://example.org/advisory"]}
    report = {"data": [
        {"file": "/work/js/vendor.js", "results": [
            {"component": "jquery", "version": "2.2.4", "vulnerabilities": [vuln, vuln]}]},
    ]}
    out = retirejs.parse(report)
    assert len(out["vulnerabilities"]) == 1
    v = out["vulnerabilities"][0]
    assert v.cwe == "CWE-1395"
    assert v.owasp_web == "A06:2021 Vulnerable and Outdated Components"
    assert "jquery 2.2.4" in v.location
    assert out["mitigations"][v.id]["reference"] == "https://example.org/advisory"
    # Old-CLI shape (bare list) parses too.
    assert len(retirejs.parse(report["data"])["vulnerabilities"]) == 1


def test_zap_active_only_attacked_alerts_become_attempts():
    from baseline.adapters import zap_active
    report = {"site": [{"@name": "http://t", "alerts": [
        {"name": "SQL Injection", "cweid": "89", "riskdesc": "High (Medium)",
         "instances": [{"uri": "http://t/rest/products/search?q=x", "method": "GET",
                        "param": "q", "attack": "')) OR 1=1--"}]},
        {"name": "Missing header", "riskdesc": "Low (Medium)", "instances": [{"uri": "http://t/"}]},
    ]}]}
    out = zap_active.parse(report)
    assert len(out["attempts"]) == 1
    a = out["attempts"][0]
    assert a.outcome == "success" and "CWE-89" in a.technique and a.challenge_key is None


def test_arjun_targets_from_katana_are_same_origin_and_not_static():
    import json as _json
    lines = "\n".join(_json.dumps({"request": {"method": "GET", "endpoint": u}}) for u in (
        "http://127.0.0.1:3000/rest/products/search?q=a",
        "http://127.0.0.1:3000/main.js",
        "http://127.0.0.1:3000/api/Users"))
    urls = runner.arjun_targets("http://127.0.0.1:3000/", lines)
    assert "http://127.0.0.1:3000/main.js" not in urls
    assert all(u.startswith("http://127.0.0.1:3000/") for u in urls)


def test_docker_tools_are_memory_capped_and_named(tmp_path, monkeypatch):
    from baseline import tools
    from baseline.tools import REGISTRY, ToolContext
    monkeypatch.delenv("APT_TOOL_MEMORY", raising=False)
    ctx = ToolContext("http://127.0.0.1:3000", str(tmp_path), "out.json", str(tmp_path))
    names = set()
    for specs in REGISTRY.values():
        for spec in specs:
            argv = spec.argv(ctx)
            if argv[0] != "docker":
                continue
            assert argv[argv.index("--memory") + 1] == argv[argv.index("--memory-swap") + 1]
            names.add(argv[argv.index("--name") + 1])
    assert len(names) >= 8  # every container gets its own name (for docker kill on timeout)
    zap = tools._zap_argv(ctx)
    assert zap[zap.index("--memory") + 1] == "1536m"
    assert "JAVA_TOOL_OPTIONS=-XX:MaxRAMPercentage=60" in zap

    monkeypatch.setenv("APT_TOOL_MEMORY", "3g")
    nuc = tools._nuclei_argv(ctx)
    assert nuc[nuc.index("--memory") + 1] == "3g"
    assert nuc[nuc.index("-c") + 1] == "10"
