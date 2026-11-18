# APT — Automated Pentesting

**COMP 4710 Senior Design · Auburn University**

APT runs a full, autonomous penetration test against a live web application,
moving through the standard phases — reconnaissance → enumeration →
vulnerability assessment → exploitation → post-exploitation → reporting →
mitigation — and measures how well it did against a private answer key. The
target is a containerized, de-branded copy of OWASP Juice Shop with its
challenge board and hints removed, so the agent gets no cheat sheet.

The project answers one question: **how does an autonomous AI agent compare to
the traditional, deterministic tooling a human pentester uses?** So APT ships
two interchangeable engines that attack the same target through the same phases
and are scored against the same ground truth:

- **AI agent** (`Tooling/apt/`) — drives Claude Code headless, one clean-context
  invocation per phase, handing a schema-validated `findings.json` between them.
- **Free-tools baseline** (`Tooling/baseline/`) — the same phases driven by nmap,
  WhatWeb, Katana, ffuf, Arjun, ZAP, Nuclei, Nikto, Retire.js, sqlmap and
  Semgrep, writing the identical `findings.json`.

Because both write the same artifact, the scoring and comparison spine
(`vuln-list/`) and the browser console (`Tooling/apt_gui/`) treat them
identically — the AI-vs-tools comparison falls out for free.

## Repository layout

| Path | What it is |
|---|---|
| `Tooling/apt/` | The AI engine (Claude Code, phase by phase). |
| `Tooling/baseline/` | The free-tools engine (deterministic scanners). |
| `Tooling/apt_gui/` | Local browser console: launch runs, watch them live, read and score results. |
| `Tooling/sanitize_source.py` | Builds the answer-key-free source tree white-box runs need. |
| `Tooling/preflight.py`, `verify_oracle.py` | OS-agnostic environment + oracle checks. |
| `vuln-list/` | The private answer key and the scoring / comparison / executive-report tools. |
| `juice-shop-copy/` | The target application (de-branded, board removed). |
| `Documents/` | Design doc, roadmap, and the ZAP-vs-AI case study. |

## Quick start

```bash
# 1. Build the target image
cd juice-shop-copy && docker build -t custom-juice-shop . && cd ..

# 2. Per-run grading token — the agent never sees it; only the scorer uses it to
#    read solve state from the private /grading/solves oracle.
export APT_GRADING_TOKEN=$(openssl rand -hex 16)
docker run -d --rm -p 127.0.0.1:3000:3000 -e APT_GRADING_TOKEN \
    --name juice-shop custom-juice-shop

# 3. Check the environment (Claude Code present + authenticated)
cd Tooling && python3 preflight.py

# 4. Run the AI pentest (inside an isolated sandbox — see the warning below)
python3 -m apt --target http://127.0.0.1:3000 --phases all --unattended

# 5. Or the free-tools baseline, for comparison (restart the container first)
python3 -m baseline --target http://127.0.0.1:3000 --phases all

# 6. Open the console: launch runs, watch them live, read and compare results
python3 -m apt_gui
```

Output lands in `Tooling/runs/<run-id>/`. Score a run with
`python3 vuln-list/score_run.py Tooling/runs/<run-id>`, and build the
higher-ups PDF with `python3 vuln-list/exec_report.py Tooling/runs/<run-id>`.

> **Sandbox only.** `--unattended` lets the agent run tools without approval
> prompts. Only use it inside an isolated VM/container whose network reaches
> nothing but the target. See `Tooling/README.md` for the full fair-comparison
> procedure and low-memory guidance.

## What it does

- **Black-box and white-box.** White-box exposes the source via `--mode
  white-box --source ./clean-source`; build that cleaned tree first with
  `python3 Tooling/sanitize_source.py` (never point `--source` at
  `juice-shop-copy/` — it contains the answer key).
- **Custom prompts.** Each phase uses a built-in prompt by default; override any
  phase with `--prompts FILE` (`--dump-prompts` writes a template) or the GUI's
  Custom prompts field.
- **Ground-truth scoring.** Exploitation is confirmed by Juice Shop's own
  server-side solve oracle, not by the agent's say-so. Detection, exploitation
  rate, precision and F1 are scored against the answer key, broken down by OWASP
  Top 10 and difficulty.
- **AI vs. tools.** Score an AI run and a free-tools run against the same answer
  key, then `vuln-list/compare_runs.py` writes the side-by-side `comparison.md`
  (effectiveness, cost, time, per-vulnerability overlap) for the report. This
  comparison is a report/presentation artifact, not a console feature.
- **Executive report.** A short, higher-ups-appropriate PDF (posture, risk at a
  glance, priority remediation roadmap), rendered from the scored run.

The target's LLM chatbot backend was dropped in Cycle 3: no LLM backend is
deployed, and the four chatbot vulnerabilities are excluded from grading (see
`vuln-list/README.md`).

## Documentation

- `Tooling/README.md` — running fair comparisons, memory, the full tool list.
- `Tooling/apt/README.md` / `Tooling/baseline/README.md` / `Tooling/apt_gui/README.md`
- `vuln-list/README.md` — the answer key and how scoring works.
- `Documents/2026-09-22-APT-design.md` — the design decisions.
- `Documents/2026-11-17-zap-vs-ai-case-study.md` — the ZAP-vs-AI case study.
