"""Adapters: raw tool output -> apt.schema payload objects.

Each adapter is a pure function `parse(raw) -> dict` whose keys are field names
on the phase's payload model (e.g. a vuln-assessment adapter returns
{"vulnerabilities": [Vulnerability, ...]}). The runner merges the dicts from
every tool it ran for a phase and builds the one findings.json. Keeping parsing
pure (no network, no disk) is what lets us unit-test each adapter against a
small checked-in sample of real tool output.
"""
from __future__ import annotations

from . import (arjun, ffuf, katana, nikto, nmap, nuclei, retirejs, semgrep, sqlmap,
               whatweb, zap, zap_active)

# Which adapter(s) feed which phase. The runner consults this to assemble a
# phase's findings from whatever tools actually produced output.
__all__ = ["nmap", "whatweb", "zap", "katana", "ffuf", "arjun", "nuclei", "nikto",
           "retirejs", "semgrep", "sqlmap", "zap_active", "common"]
