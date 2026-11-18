"""sqlmap -> schema (exploitation).

sqlmap is the realistic deterministic exploiter for the injection class. With
`--batch --output-dir=<dir>` it records, per target, a machine-readable
`log`/`target.txt` and a `session.sqlite`; the simplest stable signal is its
stdout, which states for each tested parameter whether it "is vulnerable" and
the injection type. We turn each confirmed-injectable parameter into an
ExploitAttempt.

The oracle (fetch_solved_map) is what actually confirms a Juice Shop solve, so
`oracle_confirmed` is left for the runner to stamp from the solve-state delta;
here we only record the attempt and sqlmap's own verdict as evidence.
"""
from __future__ import annotations

import re

from apt.schema import ExploitAttempt

# "Parameter: email (POST)" ... "Type: boolean-based blind" ... "is vulnerable"
_PARAM_RE = re.compile(r"Parameter:\s*([^\s(]+)\s*\(([^)]+)\)")
_VULN_RE = re.compile(r"sqlmap identified the following injection point", re.I)


def parse(raw: str, target_url: str = "") -> dict:
    """Return {"attempts": [...]}. `raw` is sqlmap's stdout/log text."""
    attempts: list[ExploitAttempt] = []
    if not raw:
        return {"attempts": attempts}

    injectable = bool(_VULN_RE.search(raw)) or "is vulnerable" in raw.lower()
    params = _PARAM_RE.findall(raw)
    if not params and injectable:
        params = [("(unknown)", "GET")]

    for i, (name, where) in enumerate(params, 1):
        types = _types_near(raw, name)
        attempts.append(ExploitAttempt(
            vuln_id=f"SQLMAP-{i:03d}",
            technique=f"sqlmap SQL injection on {where} parameter '{name}'"
                      + (f" ({', '.join(types)})" if types else ""),
            outcome="success" if injectable else "failure",
            evidence=f"sqlmap reports parameter '{name}' injectable at {target_url}."
                     if injectable else f"sqlmap found no injection in '{name}'.",
            challenge_key=None,  # the runner attributes keys from the oracle delta
        ))
    return {"attempts": attempts}


def _types_near(raw: str, param: str) -> list[str]:
    """Pull the 'Type:' lines sqlmap prints under a parameter block."""
    idx = raw.find(f"Parameter: {param}")
    if idx < 0:
        return []
    block = raw[idx: idx + 600]
    return re.findall(r"Type:\s*([^\n]+)", block)
