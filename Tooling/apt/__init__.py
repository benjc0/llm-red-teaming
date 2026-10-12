"""APT: autonomous pentest pipeline.

Drives Claude Code headless through a phase outline (recon -> enumeration ->
vulnerability assessment -> exploitation -> ...), passing a schema-validated
findings.json between phases. See cli.py for usage.
"""

__version__ = "0.1.0"
