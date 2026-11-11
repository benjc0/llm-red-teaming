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

## Running a fair AI vs. free-tools comparison

Both sides must attack **identical, fresh** targets in the **same mode**, one
after the other, never at the same time. Juice Shop keeps solve state in memory,
so a restart between runs is what keeps one side's exploits from being credited
to the other.

### One-time setup

```bash
# 1. Swap: a safety net so the VM kills a process instead of freezing (see below).
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# 2. The target image (from the repo root).
cd juice-shop-copy && docker build -t custom-juice-shop . && cd ..

# 3. Pre-pull the free-tool images so no download happens mid-scan.
for img in guardicore/whatweb projectdiscovery/katana secsi/ffuf zaproxy/zap-stable \
           projectdiscovery/nuclei sullo/nikto googlesky/sqlmap; do docker pull "$img"; done

# 4. Optional native tools (skipped and logged if missing).
pip install arjun                 # hidden-parameter discovery
# npm install -g retire           # outdated JS libraries (needs Node.js)
```

### Each comparison

```bash
cd Tooling
source ../.venv/bin/activate      # the project venv (pydantic, PyYAML)
python3 preflight.py              # checks packages, memory and swap

# --- AI run ---------------------------------------------------------------
export APT_GRADING_TOKEN=$(openssl rand -hex 16)
docker run -d --rm --memory 1g -p 127.0.0.1:3000:3000 -e APT_GRADING_TOKEN \
    --name juice-shop custom-juice-shop
python3 -m apt --target http://127.0.0.1:3000 --phases all --mode black-box --unattended
docker stop juice-shop            # wipes solve state

# --- Free-tools run (fresh container, same mode) -----------------------------
export APT_GRADING_TOKEN=$(openssl rand -hex 16)
docker run -d --rm --memory 1g -p 127.0.0.1:3000:3000 -e APT_GRADING_TOKEN \
    --name juice-shop custom-juice-shop
python3 -m baseline --target http://127.0.0.1:3000 --phases all --mode black-box
docker stop juice-shop

# --- Compare -----------------------------------------------------------------
python3 -m apt_gui                # ⇄ Compare AI vs tools
```

The same runs can be launched from the GUI (**+ New run**, Engine AI agent / Free
tools, Phases *all*, paste the grading token). Restart the container between the
two either way. Don't Ctrl-C the GUI while a run it launched is going; that
stops the run too. Both runs score themselves when they finish; if one doesn't,
use its **Score** button. For a ± spread, repeat each side 2–3 times (fresh
container each time) and tick all of them in the Compare picker.

`--unattended` lets the agent run tools without approval prompts. Use it only in
an isolated VM whose network reaches nothing but the target.

### Low-memory machines (≈4–6 GiB, e.g. a VM)

Where the memory goes during a run:

| Process | Typical | Cap |
|---|---|---|
| Desktop + VS Code + Claude Code extension | ~2 GiB | — |
| Juice Shop container | 0.3–0.6 GiB | `--memory 1g` above |
| Claude Code, one headless phase at a time (AI run) | 0.3–0.5 GiB | — |
| ZAP (Java), the largest free tool | ~1.5 GiB | 1.5 GiB |
| Nuclei | 0.3–1 GiB | 1 GiB, lower concurrency |
| Other tools (one at a time) | < 0.5 GiB | 768 MiB |

What the tooling already does:

- **Every tool container has a hard memory cap.** A tool that hits it is killed on
  its own (logged as `exit 137`) and the run continues. The VM is never at risk.
  On a bigger machine, raise every cap with `APT_TOOL_MEMORY=2g`.
- **Tools run one at a time**, and a timed-out tool's container is stopped
  before the next starts, so containers never pile up.
- ZAP's Java heap is sized from its cap, not from the machine's total RAM. Nuclei
  runs with lower concurrency (`-c 10 -bs 10 -rl 50`).

What you can do:

- **Add swap** (one-time setup above). With none, the kernel stalls when memory
  runs out (the "frozen VM") instead of quickly killing one process.
- **Give the VM more RAM** in the hypervisor if you can; 8 GiB removes the problem.
- **Never run the AI and free-tools runs at the same time**, and close browsers
  and other apps first. Check headroom with `free -h`; watch a run with
  `docker stats` or `watch -n5 free -h`.
- Don't start Ollama or another local LLM on the same VM during a run; one model
  needs several GiB by itself.
