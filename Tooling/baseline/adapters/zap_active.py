"""OWASP ZAP active scan -> schema (exploitation).

The vulnerability-assessment phase runs ZAP's passive baseline. Here ZAP's full
scan actually fires attack payloads (SQLi, XSS, path traversal, ...) at the
spidered surface. That makes it the closest free equivalent to the agent's
exploitation phase.

The report format is identical to the baseline scan (see zap.py). Each alert
whose instance carries an `attack` string becomes an ExploitAttempt. A High or
Medium alert with an attack counts as a "success" by ZAP's own verdict. As with
sqlmap, the oracle solve-state delta is what the scorer trusts, so
`oracle_confirmed` is stamped by the runner, not here.
"""
from __future__ import annotations

import json

from apt.schema import ExploitAttempt

from .common import norm_cwe


def parse(raw: str | dict) -> dict:
    """Return {"attempts": [ExploitAttempt, ...]}."""
    if not raw:
        return {"attempts": []}
    report = raw if isinstance(raw, dict) else json.loads(raw)
    attempts: list[ExploitAttempt] = []
    n = 0
    for site in report.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            attacked = [i for i in alert.get("instances") or [] if i.get("attack")]
            if not attacked:
                continue  # passive finding: nothing was attempted
            n += 1
            risk = (alert.get("riskdesc") or alert.get("risk") or "").split("(")[0].strip().lower()
            inst = attacked[0]
            cwe = norm_cwe(alert.get("cweid"))
            attempts.append(ExploitAttempt(
                vuln_id=f"ZAPA-{n:03d}",
                technique=f"ZAP active scan: {alert.get('name', 'alert')}"
                          + (f" ({cwe})" if cwe else ""),
                outcome="success" if risk in ("high", "medium") else "inconclusive",
                evidence=(f"{inst.get('method', 'GET')} {inst.get('uri', '')} "
                          f"param '{inst.get('param', '')}' attack: {inst.get('attack', '')}")[:500],
                challenge_key=None,  # attributed from the oracle delta by the runner
            ))
    return {"attempts": attempts}
