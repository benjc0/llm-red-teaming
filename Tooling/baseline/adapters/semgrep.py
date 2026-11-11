"""Semgrep -> schema (white-box / SAST baseline only).

Semgrep (`--json`) returns `results[]`, each with a `check_id`, a `path` and
`start.line` (the file:line location, which white-box findings are matched on),
and `extra.metadata` carrying `cwe` and `owasp` lists plus the rule `message`
and an optional `fix` we reuse for mitigation.
"""
from __future__ import annotations

import json

from apt.schema import Confidence, Vulnerability

from .common import norm_cwe, owasp_for_cwe

_SEV_TO_CONF = {"error": Confidence.high, "warning": Confidence.medium,
                "info": Confidence.low}


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def parse(raw: str | dict) -> dict:
    report = raw if isinstance(raw, dict) else json.loads(raw)
    vulns: list[Vulnerability] = []
    mitigations: dict[str, dict] = {}
    for i, r in enumerate(report.get("results", []) or [], 1):
        meta = (r.get("extra", {}) or {}).get("metadata", {}) or {}
        cwe = norm_cwe(_first(meta.get("cwe")))
        owasp = _first(meta.get("owasp")) or owasp_for_cwe(cwe)
        line = (r.get("start", {}) or {}).get("line")
        location = r.get("path", "")
        if line:
            location = f"{location}:{line}"
        sev = (r.get("extra", {}) or {}).get("severity", "warning").lower()
        vid = f"SEMGREP-{i:03d}"
        vulns.append(Vulnerability(
            id=vid,
            title=r.get("check_id", "semgrep rule").split(".")[-1],
            type=r.get("check_id", "semgrep"),
            location=location,
            evidence=((r.get("extra", {}) or {}).get("message") or "")[:500]
            or "Semgrep rule match.",
            confidence=_SEV_TO_CONF.get(sev, Confidence.medium),
            owasp_web=str(owasp) if owasp else None,
            cwe=cwe,
        ))
        fix = (r.get("extra", {}) or {}).get("fix") or meta.get("references")
        if fix:
            mitigations[vid] = {
                "recommendation": (meta.get("message") or "Apply the suggested fix.")[:800],
                "reference": _first(meta.get("references")) if meta.get("references") else None,
            }
    return {"vulnerabilities": vulns, "mitigations": mitigations}
