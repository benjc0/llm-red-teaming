"""Retire.js -> schema (vulnerability assessment: outdated JS components).

Retire.js fingerprints JavaScript libraries and reports the ones with known
vulnerabilities, which covers OWASP A06 (Vulnerable and Outdated Components).
None of the other DAST scanners in the baseline cover that category well.
The runner downloads the target's same-origin JS bundles into raw/js/ and
Retire.js scans that directory.

JSON output (`--outputformat json`) is either a bare list of file results (old
CLI) or {"data": [...]} (v4+). Each file result has
`results[].{component, version, vulnerabilities[]}`, and each vulnerability
carries `severity`, `identifiers.{summary, CVE[]}`, `info[]` and, in newer
repos, `cwe[]`.
"""
from __future__ import annotations

import json
from pathlib import PurePath

from apt.schema import Confidence, Vulnerability

from .common import norm_cwe, owasp_for_cwe

# CWE-1395: Dependency on Vulnerable Third-Party Component (what the answer key
# uses for A06 entries). Used when Retire.js doesn't name a CWE of its own.
_DEFAULT_CWE = "CWE-1395"
_SEV = {"critical": Confidence.high, "high": Confidence.high,
        "medium": Confidence.medium, "low": Confidence.low}


def parse(raw: str | dict | list) -> dict:
    """Return {"vulnerabilities": [...], "mitigations": {id: {...}}}."""
    if not raw:
        return {"vulnerabilities": [], "mitigations": {}}
    report = raw if isinstance(raw, (dict, list)) else json.loads(raw)
    files = report.get("data", []) if isinstance(report, dict) else report
    vulns: list[Vulnerability] = []
    mitigations: dict[str, dict] = {}
    seen: set[tuple] = set()
    n = 0
    for f in files or []:
        fname = PurePath(str(f.get("file") or "")).name
        for res in f.get("results", []) or []:
            comp, ver = res.get("component", "?"), res.get("version", "?")
            for v in res.get("vulnerabilities", []) or []:
                ids = v.get("identifiers") or {}
                summary = ids.get("summary") or ", ".join(ids.get("CVE") or []) or "known vulnerability"
                key = (comp, ver, summary)
                if key in seen:
                    continue
                seen.add(key)
                n += 1
                cwes = v.get("cwe") or []
                cwe = norm_cwe(cwes[0]) if cwes else _DEFAULT_CWE
                vid = f"RETIRE-{n:03d}"
                vulns.append(Vulnerability(
                    id=vid,
                    title=f"Vulnerable {comp} {ver}: {summary}"[:200],
                    type="Vulnerable and Outdated Component",
                    location=f"{fname} ({comp} {ver})" if fname else f"{comp} {ver}",
                    evidence=f"Retire.js matched {comp} {ver}; "
                             f"CVE: {', '.join(ids.get('CVE') or []) or 'n/a'}.",
                    confidence=_SEV.get(str(v.get("severity", "")).lower(), Confidence.medium),
                    owasp_web=owasp_for_cwe(cwe) or "A06:2021 Vulnerable and Outdated Components",
                    cwe=cwe,
                ))
                info = v.get("info") or []
                mitigations[vid] = {
                    "recommendation": f"Upgrade {comp} from {ver} to a release without this "
                                      f"vulnerability ({summary}); remove it if it's unused.",
                    "reference": info[0] if info else None,
                }
    return {"vulnerabilities": vulns, "mitigations": mitigations}
