"""Deterministic-tooling baseline for the APT pipeline.

Runs industry pentest tools (nmap, OWASP ZAP, Nuclei, Nikto, sqlmap, Semgrep,
...) over the SAME authorized target and normalizes their output into the SAME
findings.json schema the AI agent produces (apt/schema.py). A baseline run lands
in the same runs/<id>/ layout, so the existing scorer, oracle confirmation and
GUI treat it exactly like an AI run -- which is what makes the two directly
comparable. See cli.py for usage.
"""

__version__ = "0.1.0"
