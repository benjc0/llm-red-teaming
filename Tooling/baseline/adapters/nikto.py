"""Nikto -> schema.

Nikto (`-Format json`) reports a list of `vulnerabilities`, each with `url`,
`method` and a free-text `msg`. It carries no CWE, so detection matching would
have nothing to key on. We attach a coarse CWE by keyword on the message -- a
deliberately conservative table, so an unmatched Nikto line stays CWE-less (and
the scorer treats it as a candidate false positive) rather than being
mis-attributed.
"""
from __future__ import annotations

import json

from apt.schema import Confidence, Vulnerability

from .common import owasp_for_cwe

# (substring in msg, CWE). First match wins; order most-specific first.
_MSG_CWE = [
    ("x-frame-options", "CWE-16"),
    ("content-security-policy", "CWE-16"),
    ("x-content-type-options", "CWE-16"),
    ("strict-transport-security", "CWE-319"),
    ("directory indexing", "CWE-548"),
    ("directory listing", "CWE-548"),
    ("default", "CWE-16"),
    ("outdated", "CWE-1035"),
    ("backup", "CWE-530"),
    ("cgi", "CWE-78"),
]


def _cwe_for(msg: str) -> str | None:
    low = (msg or "").lower()
    for needle, cwe in _MSG_CWE:
        if needle in low:
            return cwe
    return None


def parse(raw: str | dict) -> dict:
    report = raw if isinstance(raw, dict) else json.loads(raw)
    # Nikto may emit a list (one per host) or a single object.
    hosts = report if isinstance(report, list) else [report]
    vulns: list[Vulnerability] = []
    n = 0
    for host in hosts:
        for v in host.get("vulnerabilities", []) or []:
            n += 1
            msg = v.get("msg", "")
            cwe = _cwe_for(msg)
            vulns.append(Vulnerability(
                id=f"NIKTO-{n:03d}",
                title=(msg[:80] or "Nikto finding"),
                type="server misconfiguration",
                location=v.get("url") or host.get("host", ""),
                evidence=msg[:500] or "Nikto finding.",
                confidence=Confidence.low,
                owasp_web=owasp_for_cwe(cwe),
                cwe=cwe,
            ))
    return {"vulnerabilities": vulns}
