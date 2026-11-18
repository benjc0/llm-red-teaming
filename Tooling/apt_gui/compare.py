"""GUI helpers that shell out to the vuln-list tools, plus the free-tool lineup.

Read-only, like runstore.py. Provides what the console needs from the scoring
layer without re-implementing it:

  * tools_by_phase()  -- the free-tool lineup shown in the baseline run form
  * score_run()       -- run vuln-list/score_run.py on one run (Score button)
  * exec_report()     -- run vuln-list/exec_report.py on one run (Executive PDF)

The AI-vs-tools *comparison* is intentionally not part of the console: produce
those metrics for the report with `vuln-list/compare_runs.py` (comparison.md).
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

from .runstore import PHASE_ORDER, PHASE_TITLES

VULN_LIST_DIR = Path(__file__).resolve().parents[2] / "vuln-list"

# The free-tool lineup per phase, with a one-line purpose for the GUI. Mirrors
# baseline/tools.py:REGISTRY. tools_by_phase() prefers the live registry and
# falls back to this table if baseline (pydantic) isn't importable.
TOOL_INFO: dict[str, str] = {
    "nmap": "Port and service/version scan",
    "whatweb": "Tech-stack fingerprinting",
    "katana": "JavaScript-aware crawler",
    "ffuf": "Content discovery (wordlist fuzzing)",
    "arjun": "Hidden parameter discovery",
    "zap": "DAST passive baseline scan",
    "nuclei": "Template-based vulnerability scanner",
    "nikto": "Web-server misconfiguration scanner",
    "retirejs": "Outdated JavaScript library detection",
    "semgrep": "SAST over the source tree",
    "sqlmap": "SQL injection exploitation",
    "zap_active": "DAST active attack scan",
}
_FALLBACK_REGISTRY = {
    "recon": [("nmap", False), ("whatweb", False)],
    "enumeration": [("katana", False), ("ffuf", False), ("arjun", False)],
    "vuln_assessment": [("zap", False), ("nuclei", False), ("nikto", False),
                        ("retirejs", False), ("semgrep", True)],
    "exploitation": [("sqlmap", False), ("zap_active", False)],
}
_DERIVED_NOTE = {
    "post_exploitation": "Derived from oracle-confirmed exploits",
    "reporting": "Rendered from accumulated findings",
    "mitigation": "Tool remediation text, else CWE → OWASP Cheat Sheet",
}


def tools_by_phase() -> dict:
    """{phase: {"tools": [{name, purpose, white_box_only}], "derived": note|None}}."""
    try:
        from baseline.tools import REGISTRY  # type: ignore
        reg = {p.value: [(s.name, s.white_box_only) for s in specs] for p, specs in REGISTRY.items()}
    except Exception:  # noqa: BLE001 - pydantic missing, etc.
        reg = _FALLBACK_REGISTRY
    out = {}
    for phase in PHASE_ORDER:
        out[phase] = {
            "title": PHASE_TITLES.get(phase, phase),
            "tools": [{"name": n, "purpose": TOOL_INFO.get(n, ""), "white_box_only": wb}
                      for n, wb in reg.get(phase, [])],
            "derived": _DERIVED_NOTE.get(phase),
        }
    return out


# -- loading shared code / data ------------------------------------------------

def _read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def load_score(run_dir: Path) -> Optional[dict]:
    return _read_json(run_dir / "score.json")



# -- scoring from the GUI -----------------------------------------------------------

class ScoreError(RuntimeError):
    pass


def score_run(runs_root: Path, run_id: str) -> dict:
    """Run vuln-list/score_run.py on one run (needs PyYAML)."""
    if not run_id or "/" in run_id or "\\" in run_id or run_id in (".", ".."):
        raise ScoreError("bad run id")
    run_dir = Path(runs_root) / run_id
    if not run_dir.is_dir():
        raise ScoreError("run not found")
    if importlib.util.find_spec("yaml") is None:
        raise ScoreError("Scoring needs PyYAML in the GUI's Python "
                         "(pip install pyyaml, or sudo apt install python3-yaml).")
    manifest = _read_json(run_dir / "run.json") or {}
    mode = manifest.get("mode") or "unspecified"
    proc = subprocess.run([sys.executable, str(VULN_LIST_DIR / "score_run.py"), str(run_dir),
                           "--mode", mode], capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout).strip().splitlines()
        raise ScoreError(msg[-1] if msg else f"scorer exited {proc.returncode}")
    return {"run_id": run_id, "output": proc.stdout.strip(), "score": load_score(run_dir)}


def exec_report(runs_root: Path, run_id: str) -> dict:
    """Generate the executive report (md + html + pdf) for one run via
    vuln-list/exec_report.py. Returns which artifacts were produced."""
    if not run_id or "/" in run_id or "\\" in run_id or run_id in (".", ".."):
        raise ScoreError("bad run id")
    run_dir = Path(runs_root) / run_id
    if not run_dir.is_dir():
        raise ScoreError("run not found")
    if importlib.util.find_spec("yaml") is None:
        raise ScoreError("The executive report needs PyYAML in the GUI's Python "
                         "(pip install pyyaml, or sudo apt install python3-yaml).")
    manifest = _read_json(run_dir / "run.json") or {}
    mode = manifest.get("mode") or "unspecified"
    proc = subprocess.run([sys.executable, str(VULN_LIST_DIR / "exec_report.py"), str(run_dir),
                           "--mode", mode], capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout).strip().splitlines()
        raise ScoreError(msg[-1] if msg else f"exec_report exited {proc.returncode}")
    return {
        "run_id": run_id,
        "output": proc.stdout.strip(),
        "pdf": (run_dir / "exec-report.pdf").is_file(),
        "html": (run_dir / "exec-report.html").is_file(),
        "md": (run_dir / "exec-report.md").is_file(),
    }
