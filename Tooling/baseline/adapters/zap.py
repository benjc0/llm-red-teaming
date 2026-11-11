"""OWASP ZAP -> schema.

ZAP is the primary DAST baseline. We parse its "traditional-json" report
(`-r` / the JSON report format), whose `site[].alerts[]` carry a name, a CWE id
(`cweid`), the affected URLs (`instances[].uri`), a `riskdesc`, and a `solution`
plus `reference` we reuse for the mitigation phase.
"""
from __future__ import annotations

import json

from apt.schema import Confidence, Vulnerability

from .common import norm_cwe, owasp_for_cwe

_RISK_TO_CONF = {"high": Confidence.high, "medium": Confidence.medium,
                 "low": Confidence.low, "informational": Confidence.low}


def _conf(alert: dict) -> Confidence:
    risk = (alert.get("riskdesc") or alert.get("risk") or "").split("(")[0].strip().lower()
    return _RISK_TO_CONF.get(risk, Confidence.medium)


def parse(raw: str | dict) -> dict:
    """Return {"vulnerabilities": [...], "mitigations": {id: {...}}}.

    `mitigations` is a side channel the runner carries into the mitigation phase
    so the baseline can reuse ZAP's own `solution`/`reference` text.
    """
    report = raw if isinstance(raw, dict) else json.loads(raw)
    vulns: list[Vulnerability] = []
    mitigations: dict[str, dict] = {}
    n = 0
    for site in report.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            n += 1
            cwe = norm_cwe(alert.get("cweid"))
            instances = alert.get("instances") or []
            location = (instances[0].get("uri") if instances else None) or site.get("@name", "")
            vid = f"ZAP-{n:03d}"
            vulns.append(Vulnerability(
                id=vid,
                title=alert.get("name", "ZAP alert"),
                type=alert.get("name", "ZAP alert"),
                location=location,
                evidence=(alert.get("desc") or "")[:500] or "ZAP active-scan alert.",
                confidence=_conf(alert),
                owasp_web=owasp_for_cwe(cwe),
                cwe=cwe,
            ))
            if alert.get("solution"):
                mitigations[vid] = {
                    "recommendation": _strip_html(alert["solution"])[:800],
                    "reference": _first_ref(alert.get("reference", "")),
                }
    return {"vulnerabilities": vulns, "mitigations": mitigations}


def _strip_html(text: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", text or "").replace("\n", " ").strip()


def _first_ref(text: str) -> str | None:
    ref = _strip_html(text).split()
    return ref[0] if ref else None
