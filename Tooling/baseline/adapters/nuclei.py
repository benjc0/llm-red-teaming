"""Nuclei -> schema.

Nuclei emits one JSON object per finding (its `-jsonl` output). Each has
`template-id`, `info` (name, severity, `classification.cwe-id`), and
`matched-at` (the URL/location). We take the first CWE id when several are
listed.
"""
from __future__ import annotations

import json

from apt.schema import Confidence, Vulnerability

from .common import norm_cwe, owasp_for_cwe

_SEV_TO_CONF = {"critical": Confidence.high, "high": Confidence.high,
                "medium": Confidence.medium, "low": Confidence.low,
                "info": Confidence.low, "unknown": Confidence.low}


def parse(raw: str | list) -> dict:
    """Accept JSONL text or an already-parsed list of finding dicts."""
    findings = raw if isinstance(raw, list) else _read_jsonl(raw)
    vulns: list[Vulnerability] = []
    for i, f in enumerate(findings, 1):
        info = f.get("info", {}) or {}
        cwe_list = (info.get("classification", {}) or {}).get("cwe-id") or []
        cwe = norm_cwe(cwe_list[0] if isinstance(cwe_list, list) and cwe_list else cwe_list or None)
        sev = (info.get("severity") or "unknown").lower()
        vulns.append(Vulnerability(
            id=f"NUCLEI-{i:03d}",
            title=info.get("name") or f.get("template-id", "nuclei finding"),
            type=f.get("template-id", "nuclei"),
            location=f.get("matched-at") or f.get("host", ""),
            evidence=(info.get("description") or f.get("template-id", ""))[:500]
            or "Nuclei template match.",
            confidence=_SEV_TO_CONF.get(sev, Confidence.low),
            owasp_web=owasp_for_cwe(cwe),
            cwe=cwe,
        ))
    return {"vulnerabilities": vulns}


def _read_jsonl(text: str) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
