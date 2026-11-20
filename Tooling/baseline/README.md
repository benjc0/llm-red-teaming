# Deterministic baseline pipeline

The industry-tool counterpart to `apt/` (the AI agent). It runs standard pentest
tools over the **same authorized target**, through the **same seven phases**, and
normalizes their output into the **same `findings.json` schema** (`apt/schema.py`).
Because a baseline run lands in the identical `runs/<id>/` layout, the existing
scorer (`vuln-list/score_run.py`), the solve oracle, and the GUI treat it exactly
like an AI run — which is what makes the two directly comparable.

This answers the sponsor's central question: *what does the AI add or miss versus
the tools a team already runs?*

## Tool per phase

| Phase | Tool(s) | Normalized into |
|---|---|---|
| Recon | nmap (`-sV`, native), WhatWeb | `services`, `tech_stack` |
| Enumeration | Katana (JS crawl), ffuf (content discovery), Arjun (hidden parameters, fed Katana's URLs) | `routes`, `hidden_paths`, `api_surface`, `params` |
| Vulnerability assessment | OWASP ZAP (DAST), Nuclei, Nikto, Retire.js (outdated JS libraries, OWASP A06); Semgrep (SAST, white-box only) | `vulnerabilities` (with CWE + OWASP) |
| Exploitation | sqlmap, ZAP active scan, plus the solve-oracle delta | `attempts` (oracle-confirmed) |
| Post-exploitation | derived from oracle-confirmed exploits | `reachable_data`, `escalations` |
| Reporting | rendered from the accumulated findings | `report.md` |
| Mitigation | ZAP/Semgrep remediation text, else a CWE → OWASP Cheat Sheet table | `items` |

Tools run as Docker images with `--network host`. nmap, Arjun (`pip install arjun`)
and Retire.js (`npm install -g retire`) run natively. Retire.js scans files, so the
runner first downloads the target's same-origin JS bundles into `raw/js/`. A missing tool or Docker is logged and skipped — the phase still writes a
valid (possibly empty) `findings.json`, so a partial environment never aborts a run.

## Use

```bash
cd Tooling

# See exactly which tool command each phase would run, without executing:
python3 -m baseline --target http://127.0.0.1:3000 --phases all --dry-run

# Run for real (needs Docker; nmap native). Use a FRESH container so the oracle
# solve state is clean, the same as for an AI run:
python3 -m baseline --target http://127.0.0.1:3000 --phases all \
    --grading-token "$APT_GRADING_TOKEN"

# White-box adds Semgrep over a cleaned source tree:
python3 -m baseline --target http://127.0.0.1:3000 --phases all \
    --mode white-box --source ./clean-source
```

Or start it from the GUI: **+ New run → Engine: Free tools**, then open
**⇄ Compare AI vs tools**. From the CLI, the run is scored automatically when
PyYAML is installed; to score and compare by hand:

```bash
python3 ../vuln-list/score_run.py runs/<baseline-id> --mode black-box
python3 ../vuln-list/compare_runs.py runs/<ai-id> runs/<baseline-id>
```

## Requirements & known limitations

- **Docker access.** Most tools run as pinned containers, so your user needs to
  reach the Docker daemon (be in the `docker` group, or run with `sudo`). A run
  with no Docker access fails every containerized tool with exit 126.
- **A few tools run natively**, not via Docker: `nmap`, `whatweb`, `nikto`,
  `ffuf`, `arjun`, `retire`. They must be on `PATH` (Kali ships the first four;
  `arjun`/`retire` are skipped with a log note if absent). `ffuf` uses a host
  wordlist — override with `APT_FFUF_WORDLIST` if yours isn't at
  `/usr/share/wordlists/dirb/common.txt`.
- **Memory — the most common cause of a "ZAP found nothing" run.** ZAP (the
  passive *and* active scans) plus nuclei are memory-hungry, and they run
  **alongside** the live target container. On a small host (~4 GB RAM) the
  kernel's OOM killer can take out the **target** (Juice Shop) mid-scan, because
  the scanner containers are memory-capped but the target is not. When that
  happens you'll see ZAP exit 3 — `Job spider failed … Connection refused`
  followed by `Failed to access summary file` — and every later tool reports
  little or nothing, because the target is simply gone (and `--rm` removes the
  dead container, so `docker ps` looks empty). This is an **environment limit,
  not a tool bug**. Mitigations, best first:
  - Run on a host with **≥ 8 GB RAM** (comfortably fits ZAP + nuclei + target).
  - Protect the target from the OOM killer so a scanner is sacrificed instead:
    start Juice Shop with `--oom-score-adj=-800` (and keep `--rm`).
  - Lower the scanner caps with `APT_TOOL_MEMORY` (e.g. `1g`), accepting that
    nuclei may then OOM itself (exit 137) instead.
  - Run the heavy ZAP active scan on its own rather than in a full `--phases all`
    pass. The authoritative ZAP result for the AI-vs-tools comparison is the
    standalone ZAP Automation Framework scan documented in the case study, not
    this in-pipeline step.
- **Diagnosing a failed tool.** The runner logs each tool's exit code *and its
  stderr* on any non-zero exit (see the phase's `logs/<phase>.jsonl` or the GUI
  Activity tab), so a failure says *why* instead of just "0 bytes".

## Oracle attribution

Tools don't know Juice Shop challenge keys, so the runner snapshots the
`/grading/solves` oracle before and after the exploitation phase; any challenge
that flips to solved during the phase is credited to the baseline as an
oracle-confirmed exploit. Without a grading token this step is skipped and
`oracle_confirmed` is left unset, exactly like the AI runner.

## Layout

| File | Role |
|---|---|
| `tools.py` | The tool registry: one `ToolSpec` per tool, grouped by phase (image, argv, output file, adapter). |
| `adapters/*.py` | Pure `parse(raw) -> {payload_field: value}` functions, one per tool. Unit-tested against sample output. |
| `runner.py` | Runs the tools, attributes oracle solves, and assembles each phase's `findings.json`. `build_findings` is pure. |
| `cli.py` | `python3 -m baseline` entrypoint. |
