# APT GUI

A local, browser-based console for the APT pipeline. It **reads** the run
directory the orchestrator writes and **launches** `python -m apt` (AI agent) or
`python -m baseline` (free tools) for new runs; it never re-implements any
pipeline logic, so the CLI and GUI can't drift.

Zero third-party dependencies: the backend is Python's standard-library
`http.server`, the frontend is plain HTML/CSS/JS with no build step. It runs the
same on Linux, macOS and Windows.

## Run it

```bash
cd Tooling
python3 -m apt_gui            # opens http://127.0.0.1:8787 in your browser
python3 -m apt_gui --port 9000 --no-browser
python3 -m apt_gui --runs /path/to/runs    # read a different run directory
```

The orchestrator (`apt/`) must be importable from `Tooling/` and runnable
(`pydantic` installed, Claude Code on PATH) for *launching* runs. Just
*browsing* past runs needs neither.

## What it shows

- **Run list** — every run under `runs/`, newest first, with status
  (completed / running / failed / partial), phases done, vulnerability count and
  cost.
- **Phase pipeline** — the seven phases with live state (done / active / failed /
  pending) and a progress bar. Click a phase to focus it.
- **Findings** — the structured `findings.json` for the focused phase, rendered
  per phase type: endpoints, candidate vulnerabilities (with OWASP/CWE/
  confidence), exploit attempts (with oracle-confirmed badges), the mitigation
  playbook, and links to every raw artifact.
- **Activity** — the live "what is it doing" feed, parsed from the phase's
  `logs/<phase>.jsonl` stream: each shell command, file write, tool result and
  the agent's reasoning, as collapsible rows. Bookkeeping/system events are
  filtered out.
- **Report** — the generated `reporting/report.md`.
- **Compare AI vs tools** — see below.

## Comparing the AI with free tools

The **⇄ Compare AI vs tools** button (or `#compare`) puts AI runs next to runs of
the free-tools baseline (`../baseline/`). Both kinds attack the same target
through the same seven phases, write the same `findings.json`, and are scored
against the same answer key, so the numbers are directly comparable.

Start a free-tools run from **+ New run → Engine: Free tools** (needs Docker;
nmap, Arjun and Retire.js run natively if installed). Missing tools are skipped
and logged, never fatal. A run must be **scored** (`score.json`) to be compared.
Both runners score automatically, and unscored runs get a **Score** button.

**Tools per phase**

| Phase | Free tools | What they cover |
|---|---|---|
| Recon | nmap, WhatWeb | services/versions, tech stack |
| Enumeration | Katana, ffuf, Arjun | JS-aware crawl, content discovery, hidden parameters |
| Vulnerability assessment | ZAP (baseline), Nuclei, Nikto, Retire.js, Semgrep (white-box) | DAST, known-CVE templates, server misconfig, outdated JS libraries (OWASP A06), SAST |
| Exploitation | sqlmap, ZAP active scan | SQL injection, active attack payloads; credited via the solve-oracle delta |
| Post-exploitation / reporting / mitigation | *derived* | no real free-tool equivalent; built from earlier output and labelled "derived" in the view |

**What it measures**

- *Effectiveness* (answer key): detection rate, exploitation rate (oracle-
  confirmed, so ground truth), precision, F1, confirmed exploits, false positives.
- *Efficiency*: cost, wall time, cost per confirmed exploit, time per confirmed exploit.
- *Consistency*: pick several runs per side and each metric shows mean ± spread.
- *Per phase*: what each side used (the AI's shell programs are read from its
  logs) and produced (services, routes, parameters, findings, attempts…), with time and cost.
- *Coverage*: hit rate per OWASP Top 10 category and per difficulty, for
  exploits or detections.
- *Overlap*: which vulnerabilities only the AI found, both found, only the
  tools found, and what both missed, listed by name.

**Layout, top to bottom:** run picker (AI runs | tool runs) → caveat banners (e.g.
the sides ran different phases, so total time/cost aren't like-for-like) →
headline tiles (only-AI / both / only-tools / both-missed) → scorecard of paired
bars with a "who's ahead" verdict per metric → phase-by-phase table → coverage
bars → named overlap. **↓ comparison.md** downloads the same table
`vuln-list/compare_runs.py` writes, ready for the written report.

While a run is live the view polls and updates: the pipeline advances, the
activity feed tails, and structured findings snap in as each phase completes.

### Deep links

`#<run>/<phase>/<tab>` opens straight to a view, e.g.
`#20261016-194900/exploitation/activity`. `#compare/<run>,<run>` opens a
specific comparison. Handy for demos and bookmarks.

## Scope (v1)

- **Read-what-exists.** Structured findings appear at phase boundaries (that's
  when the agent writes `findings.json`); the activity feed is what moves
  continuously mid-phase. True mid-phase findings need a `record_finding` tool in
  the engine — see the roadmap in `Documents/`.
- **Launching is the only write.** `--unattended` is forwarded only when checked
  in the launch form; the grading token is passed via the environment, never on
  the command line or to the agent.
- Updates are by polling. Server-sent events are a later nicety, not needed yet.

## Layout

| File | Role |
|---|---|
| `runstore.py` | Read-only parse of the run directory into API dicts. No pydantic. |
| `launcher.py` | Validates launch params and spawns `python -m apt` or `python -m baseline`. |
| `compare.py` | AI-vs-tools comparison: per-phase stats, grouping via `vuln-list/compare_runs.py`, scoring from the GUI. |
| `server.py` | Standard-library HTTP router: JSON API + static files. |
| `cli.py` | `python3 -m apt_gui` entrypoint. |
| `static/` | The single-page frontend (`index.html`, `app.js`, `styles.css`). |
