# APT GUI

A local, browser-based console for the APT pipeline. It **reads** the run
directory the orchestrator writes and **launches** `python -m apt` for new runs;
it never re-implements any pipeline logic, so the CLI and GUI can't drift.

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

While a run is live the view polls and updates: the pipeline advances, the
activity feed tails, and structured findings snap in as each phase completes.

### Deep links

`#<run>/<phase>/<tab>` opens straight to a view, e.g.
`#20261016-194900/exploitation/activity`. Handy for demos and bookmarks.

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
| `launcher.py` | Validates launch params and spawns `python -m apt`. |
| `server.py` | Standard-library HTTP router: JSON API + static files. |
| `cli.py` | `python3 -m apt_gui` entrypoint. |
| `static/` | The single-page frontend (`index.html`, `app.js`, `styles.css`). |
