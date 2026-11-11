"""Shared helpers for the baseline adapters.

The main job here is normalizing the CWE ids that different tools emit into the
"CWE-###" form the scorer matches on (score_run.match_detection), and a coarse
CWE -> OWASP Web Top 10 (2021) mapping so a tool finding carries the same
industry label the answer key uses even when the tool didn't name it.
"""
from __future__ import annotations

import re

_CWE_RE = re.compile(r"(\d+)")


def norm_cwe(value) -> str | None:
    """Return 'CWE-89' from 89, '89', 'CWE-89', 'cwe-89', etc. None if absent."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s in ("0", "-1"):
        return None
    m = _CWE_RE.search(s)
    if not m:
        return None
    return f"CWE-{m.group(1)}"


# Coarse CWE -> OWASP 2021 category. Deliberately small: just the categories our
# answer key uses most, so a tool's bare CWE still lands in the right bucket for
# the by-OWASP breakdown. Unknown CWEs simply get no owasp_web (that's honest).
_CWE_TO_OWASP = {
    # A01 Broken Access Control
    "CWE-22": "A01:2021 Broken Access Control", "CWE-284": "A01:2021 Broken Access Control",
    "CWE-285": "A01:2021 Broken Access Control", "CWE-639": "A01:2021 Broken Access Control",
    "CWE-425": "A01:2021 Broken Access Control", "CWE-668": "A01:2021 Broken Access Control",
    # A02 Cryptographic Failures
    "CWE-327": "A02:2021 Cryptographic Failures", "CWE-328": "A02:2021 Cryptographic Failures",
    "CWE-311": "A02:2021 Cryptographic Failures", "CWE-319": "A02:2021 Cryptographic Failures",
    # A03 Injection
    "CWE-89": "A03:2021 Injection", "CWE-79": "A03:2021 Injection",
    "CWE-78": "A03:2021 Injection", "CWE-91": "A03:2021 Injection",
    "CWE-943": "A03:2021 Injection",
    # A04 Insecure Design
    "CWE-602": "A04:2021 Insecure Design",
    # A05 Security Misconfiguration
    "CWE-16": "A05:2021 Security Misconfiguration", "CWE-548": "A05:2021 Security Misconfiguration",
    "CWE-611": "A05:2021 Security Misconfiguration", "CWE-756": "A05:2021 Security Misconfiguration",
    # A06 Vulnerable and Outdated Components
    "CWE-1035": "A06:2021 Vulnerable and Outdated Components",
    "CWE-937": "A06:2021 Vulnerable and Outdated Components",
    "CWE-1395": "A06:2021 Vulnerable and Outdated Components",
    "CWE-1104": "A06:2021 Vulnerable and Outdated Components",
    # A07 Identification and Authentication Failures
    "CWE-287": "A07:2021 Identification and Authentication Failures",
    "CWE-307": "A07:2021 Identification and Authentication Failures",
    "CWE-521": "A07:2021 Identification and Authentication Failures",
    # A08 Software and Data Integrity Failures
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
    # A09 Security Logging and Monitoring Failures
    "CWE-532": "A09:2021 Security Logging and Monitoring Failures",
    # A10 SSRF
    "CWE-918": "A10:2021 Server-Side Request Forgery (SSRF)",
}


def owasp_for_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    return _CWE_TO_OWASP.get(cwe.upper())
