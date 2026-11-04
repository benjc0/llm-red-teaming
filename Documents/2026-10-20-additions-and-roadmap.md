# APT — Proposed Additions & Sponsor-Idea Roadmap

**Date:** 2026-10-20
**Status:** Draft for team review. Two items already built (see §1); the rest is a
prioritized backlog, not committed work.
**Related:** `Documents/2026-09-22-APT-design.md`, `Tooling/apt/README.md`,
`vuln-list/README.md`.

This document does two things:

1. Records the changes just made to the code (OS-agnostic scripts + a GUI).
2. Triages the sponsor's suggestions into a roadmap, each tied to the question
   it answers and to where it plugs into the existing architecture.

The guiding principle for all of it: **the orchestrator (`apt/`) stays the single
source of truth.** New capabilities are either a new *phase cartridge*, a flag on
a run, a *scoring* step over the artifacts, or a *reader* of the run directory
(like the GUI). We don't fork the engine.

---

## 1. Built now

### 1.1 OS-agnostic scripts (Python, no bash)
- `Tooling/preflight.py` replaces `setup.sh` — same checks (Claude Code present,
  runnable, authenticated; optional curl/nmap), standard library only, colour
  handling that degrades on Windows legacy terminals.
- `Tooling/verify_oracle.py` replaces `verify_oracle.sh` — same SQLi-login →
  oracle-flip smoke test, but via `urllib` instead of `curl`+`jq`, so it has no
  external dependencies. (Note: it still reads `/api/Challenges/`, the same
  endpoint the old script used; see the oracle-endpoint note in §3.)

The `.sh` versions are left in place until the team migrates.

### 1.2 The GUI (`Tooling/apt_gui/`)
A local browser console. Decisions locked with the team:
- **Reads the run directory, launches the orchestrator.** It does not
  re-implement pipeline logic, so CLI and GUI never drift.
- **Browser-based, standard-library backend, no build step.** `python3 -m
  apt_gui` opens a tab. Runs the same on any OS.
- **v1 is read-what-exists.** Structured findings render at phase boundaries
  (when the agent writes `findings.json`); the live Activity feed — parsed from
  the stream-json logs — is what moves continuously mid-phase.

Shows: run list with status/cost/vuln-count; a seven-phase pipeline with live
state and a progress bar; per-phase structured findings (endpoints, vulns with
OWASP/CWE/confidence, exploit attempts with oracle badges, mitigation playbook,
raw-artifact links); the live Activity stream; and the report. See
`Tooling/apt_gui/README.md`.

---

## 2. The sponsor ideas, triaged

The sponsor notes are mostly **research questions**, not features. Grouped, with
the question each answers and how it maps onto what we already have. Priority is
my recommendation for the team to argue with, not a decision.

### Tier A — highest leverage, builds directly on what exists

**A1. Baseline comparison: AI agent vs. industry DAST/SAST (ZAP, Nikto).**
*Question: what is the benefit over the tools a team already runs? Where is the
AI better or worse?*
We already score a run against the private answer key (`vuln-list/score_run.py`:
detection rate, exploitation rate, precision, by OWASP category and difficulty).
Make the **scorer tool-agnostic**: add thin adapters that turn a ZAP JSON report
and a Nikto report into the same "findings" shape, score them on the *same*
answer key, and emit a side-by-side table (AI vs ZAP vs Nikto vs — later —
human). This is the single most convincing artifact for the "replace/augment the
human?" question, and it reuses the scoring we already trust.
*Plugs in:* new `vuln-list/adapters/` + a `compare` mode in the scorer. GUI gets
a comparison view later.

**A2. Purpose-built single-vulnerability testbed.**
*Question (sponsor's exact words): "Use cc to generate some code with one
specific vulnerability to test on, compare results of industry tools vs our AI
agent."*
A tiny app with exactly one known, documented vulnerability is clean ground
truth — no Juice-Shop training-data contamination, no ambiguity about what
"should" be found. It's the ideal first subject for A1. Start with 2–3 such
micro-apps (one injection, one access-control, one misconfig).
*Plugs in:* a new target under a `testbeds/` dir; the orchestrator already takes
`--target`, so no engine change. Pairs with A1 for the first real experiment.

**A3. Deterministic validators ("vulnerable: yes/no").**
*Question: "here's one vuln that's exploitable / validate it. run a deterministic
tool against it." Customer vulnerable or not?*
`verify_oracle.py` already is one such validator (SQLi login → oracle flip).
Generalize the pattern: a small library of scripted, non-AI PoCs keyed by
challenge/vuln, each returning a hard boolean. This turns an AI *claim* into a
*reproducible* result and is exactly what a customer wants as the bottom line.
*Plugs in:* `Tooling/validators/`; the orchestrator's oracle step already proves
the model works. These complement the oracle for vulns the oracle can't see.

### Tier B — research studies the harness already almost supports

**B1. Prompt-sensitivity study.**
*Question: "are we prompting it poorly? how much does the prompt impact
results?"*
The phase prompts are already centralized (`apt/phases.py`). Add the ability to
run a phase/pipeline under **named prompt variants** and compare outcomes across
K runs. The design doc already commits to parseable per-run logging "from day
one"; this is the payoff — vary one thing, hold the rest, score the delta.
*Plugs in:* a `--prompt-set` selector + variant files; scoring already aggregates
across runs.

**B2. Per-phase strength analysis.**
*Question: "maybe AI is better at a particular phase?"*
The scorer already breaks results down by category and difficulty. Add a
per-phase cut, and (with A1) an AI-phase-vs-tool cut — e.g. is the AI's edge in
*exploitation* (chaining, reasoning) rather than *discovery* (where scanners are
exhaustive)?
*Plugs in:* reporting in `score_run.py`; no engine change.

**B3. Gap / risk framing vs. a traditional pentest.**
*Question: "what is the AI doing, what is it missing, overall impact to the
customer in terms of risk?"*
We measure misses already (answer-key entries not detected). Reframe the missed
set in **customer-risk** terms: severity × exploitability, not just a count.
Largely a reporting/weighting layer over the answer key, plus a short "what a
human would additionally have checked" section.
*Plugs in:* `overrides.yml` gains a severity/risk weight; scorer reports a risk
delta.

### Tier C — new capability, real engine/ops work

**C1. `record_finding` — incremental findings (the deferred GUI item).**
*Question: can the console show a vuln the instant the agent finds it, not only
at phase end?*
Give the agent a tool/file contract to append findings *during* a phase (the
design doc floated this in §3). The GUI's live view then shows structured
findings mid-phase, not just the activity feed. This is the natural v2 of the
GUI and the only item here that changes the agent's contract.
*Plugs in:* `apt/schema.py` + a record step in `apt/runner.py`; GUI reads it.

**C2. Stealth-mode run option.**
*Question: "stealthy pentest option?"*
A run mode that throttles request rate, prefers low-noise techniques, and avoids
load-generating scans — to model an attacker evading detection, and to study
the speed/thoroughness trade-off. (Authorized-testing framing only; the rules of
engagement already forbid DoS and off-target traffic.)
*Plugs in:* a `--profile stealth` that adjusts phase guidance and tool limits.
No new phase.

**C3. Report → remediate → re-test loop (close the degrade path).**
*Question: sponsor's "report -> remediate."*
Design doc §7 already specifies this: draft playbook (have it) → human applies →
**verify-mode re-run** = the exploitation phase re-run as a regression test,
success = previously-solved challenges now report unsolved. Wire verify-mode as
a first-class run type and surface the before/after delta in the GUI.
*Plugs in:* a `--verify` run reusing exploitation + the oracle; GUI diff view.

**C4. Continuous / CI pentesting.**
*Question: "CI/pentesting via AI constantly running?"*
Scheduled or trigger-on-deploy runs against a target, with **run-to-run diff**
(new/fixed/regressed vulns). The GUI already lists runs over time; add a diff
between two runs. This is the "always-on" story but depends on cost control
(a full run in the sample was ~$6.86), so pair it with phase-scoping and model
choice.
*Plugs in:* a scheduler wrapper + a diff over two run directories; mostly ops.

### Tier D — bigger bets, flagged as future work (consistent with design doc §8)
- **More realistic target** beyond Juice Shop (sponsor: "scale back ... to a more
  realistic environment"). The design doc lists general-purpose targeting as
  future work; A2's testbeds are the incremental bridge.
- **Per-phase-pipeline vs. long-session baseline ablation** (already planned,
  Cycle 3).

---

## 3. Open questions for the team / sponsor

1. **Priority order.** I've proposed A1+A2 first (the tool-vs-AI comparison on a
   clean testbed) because it answers the sponsor's headline question and reuses
   the scorer. Agree?
2. **Scope of the comparison (A1).** Which tools — ZAP and Nikto only, or add a
   SAST (e.g. Semgrep) for the white-box run?
3. **Oracle endpoint inconsistency (pre-existing, worth a ticket).** The design
   doc and `apt/runner.py` use a private `/grading/solves` endpoint; the README
   and both oracle scripts read `/api/Challenges/`. These should be reconciled so
   "the agent can't read the answer key from the running app" actually holds.
   Not changed here — flagging it.
4. **Cost ceiling for CI (C4).** A full 7-phase run was ~$6.86 and ~3.5M tokens.
   What's an acceptable per-run budget for continuous runs?
