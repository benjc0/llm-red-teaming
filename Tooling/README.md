Tooling and scripts that is our 'product'

Our products name: APT (Automated Pentesting)

## What's here

| Path | What it is |
|---|---|
| `apt/` | The orchestrator: drives Claude Code headless through the pentest phases, passing a schema-validated `findings.json` between them. See `apt/README.md`. |
| `apt_gui/` | A local, browser-based console that reads the run directory and launches runs. Zero dependencies. See `apt_gui/README.md`. |
| `preflight.py` | Environment check (OS-agnostic). Verifies Claude Code is present, runnable and authenticated. Replaces `setup.sh`. |
| `verify_oracle.py` | Oracle smoke test (OS-agnostic). Fires one known exploit and confirms the server-side solve tracker flips. Replaces `verify_oracle.sh`. |
| `tests/` | `pytest` suite for the orchestrator and the GUI's run-directory reader. |
| `runs/` | Output, one directory per run. |

The `.py` scripts use only the Python standard library, so APT runs the same on
Linux, macOS and Windows. (`setup.sh` / `verify_oracle.sh` are the old bash
versions, kept until the team has moved over.)

## Quick start

```bash
cd Tooling
pip install -r requirements.txt     # pydantic; Claude Code must be on PATH
python3 preflight.py                # check the environment
python3 -m apt --target http://127.0.0.1:3000 --dry-run   # inspect the pipeline
python3 -m apt_gui                  # open the console in your browser
```
