# APT (Automated Pentester) — Design Document

**Course:** COMP 4710 Senior Design · Auburn University · Fall 2026
**Date:** 2026-09-22
**Status:** Design finalized (prototype/PoC scope). No code written yet.
**Related docs:** `Planning.txt`, `Sponsor_Progress_Plan.docx`

> This document captures the design decisions reached in a design-review
> session. It is the shared reference for the team and sponsor. It is
> intentionally scoped to a single-semester proof of concept.

---

## 1. What we are building (and what we are not)

**Thesis.** APT is an autonomous AI agent that runs a full penetration test
against a live, containerized copy of OWASP Juice Shop, moving through the
standard phases — reconnaissance → enumeration → vulnerability assessment →
exploitation → post-exploitation → reporting → mitigation playbook →
(stretch) remediation & before/after re-assessment.

**This is a prototype / proof of concept.** The goal is to *demonstrate that
structured, autonomous LLM-driven pentesting works* and to *produce results*
against a known target. 

**Explicit non-goals (out of scope this semester):**

- **No competitive benchmark.** We are *not* claiming "better than
  PentestGPT / Strix / etc." The graded contribution is a working
  autonomous full-cycle agent measured against our own ground truth, not a
  head-to-head win. (A competitor benchmark is a possible future/publication
  angle only.)
- **No general-purpose targeting.** Single target: local Juice Shop. General
  abstraction to arbitrary targets is future work.
- **Agentic patch-writing is a stretch, not a requirement** (see §7).

### Naming note
The repo is currently `llm-red-teaming`, which describes a *different* class
of tool attacking an LLM's outputs

APT attacks an *application* using an LLM as the brain Attacking a 
locally-hosted LLM is one *tool in the kit* (JuiceShop has such challenges), 
not the project's identity. Consider renaming to
avoid signaling scope confusion.

---

## 2. The spine: per-phase agents + schema-first handoff

The core engineering contribution is **structured context handoff between
phases**, realized as:

1. **Each phase is a separate, headless agent invocation with a clean
   context.** The pipeline does *not* run as one long-lived interactive
   session. A phase starts fresh, is given only the distilled findings of
   the prior phase, does its work, and exits. (Driven via Claude Code
   headless mode, e.g. `claude -p ... --output-format json`, per phase, with
   a phase-specific system prompt and tool set.)

2. **Phases communicate through a validated `findings.json` artifact**, not
   through raw conversation scrollback. This file is the *only* thing that
   crosses a phase boundary by default.

3. **The orchestrator:** run phase → read its
   `findings.json` → validate against schema → hand to next phase. 

### The baseline is (almost) free
The "one long session, no phase structure" version is kept as the **control
/ baseline**, not built as a second product. It is essentially Claude Code
run once with all tools and no orchestration. The per-phase pipeline is the
*product*; the long-session run is the *ablation* it will be compared
against in Cycle 3 — once the oracle and trial harness exist to judge them.
**Do not A/B the two by feel during Cycle 1.**

---

## 3. The findings schema (load-bearing)


**Decisions:**

- **File/tool-based, not final-message-based.** Each phase writes its
  structured findings *during* the phase via a `record_finding` tool (or a
  "write to `findings.json`" contract). We do **not** rely on parsing the
  agent's final chat message as JSON
- **Validated before hand-off.** The orchestrator validates the artifact
  before passing it forward.

**v1 schema sketch (to be refined this week):**

```
recon   → { hosts:[], ports:[], services:[], endpoints:[], tech_stack:[] }
enum    → { routes:[], params:[], users:[], roles:[], hidden_paths:[], api_surface:[] }
vuln    → [ { id, type, location, evidence, confidence } ]
exploit → [ { vuln_id, payload, result, oracle_confirmed: bool } ]
```

`oracle_confirmed` is where the Juice Shop server-side oracle (§5) plugs
directly into the data model: the exploit phase does not merely *claim*
success — the orchestrator checks the oracle and stamps the field. Grading
falls out of the schema for free.

**Action item (week of Sep 22):** draft v1 of this schema *before* writing
the orchestrator.

---

## 4. Context discipline (information ≠ tokens)

The single most important mental model for the build:

- **Information the next phase builds on** (endpoints, tech stack, params) —
  should be *rich*. It lives in `findings.json` (and on disk) and can be
  large; structured data is cheap.
- **Tokens in the model's context window** (raw tool scrollback) — must stay
  *lean*. Dumping 5,000 lines of `ffuf` output into the window does not make
  the next phase smarter; it drowns the *current* phase before it can even
  produce a handoff.

These are **not in tension.** Rich handoff + lean context is exactly what
schema-first buys you.

**Rules:**

1. **Tools write raw output to disk** (`recon_raw/nmap.txt`,
   `recon_raw/ffuf.json`, …). The agent works over it with
   `grep`/`head`/targeted reads, or a per-tool summarizer, so only distilled
   facts enter its context.
2. **The structured findings artifact is the triage**, not the hoard. A
   recon phase's value is deciding "here are the 40 real endpoints, these 6
   are juicy" — not carrying 5,000 raw lines forward.
3. **Raw is retrievable on demand.** A later phase (e.g. exploitation) that
   needs the full raw response for one endpoint reads that one file. Rich
   information *available*; lean context *by default*.

This applies **within** a phase as much as between phases — the noisiest
phases (recon/enum, due first) are exactly where intra-phase overflow would
otherwise break the Sep 30 milestone.

---

## 5. Evaluation & ground truth

**Two ground truths, used together:**

- **Server-side solve oracle (numerator — what was *actually* exploited).**
  Juice Shop detects challenge solutions *server-side*, independent of the
  scoreboard UI. The solved-state is queryable (e.g. `/api/Challenges`) and
  flips the instant an exploit condition is met. **We keep this oracle even
  though the scoreboard UI is removed** — we only hide the UI/hints from the
  agent, we do not disable server-side detection.
- **Hand-written vulnerability list (denominator — what is *possible*).** The
  team's private answer key of all known Juice Shop vulns. Tells us what
  *should* be findable; the oracle tells us what the agent *did*.

**Blinding.** Scoreboard/challenge board removed and hints/tutorials disabled
so the agent gets no cheat sheet. The oracle runs behind the agent's back for
grading only.

**Detection vs. exploitation.** We score *exploitation* (agent actually
popped the challenge, per the oracle), not merely "the agent said a vuln
exists."

**Comparisons (internal, no competitor needed):**

- **Black-box vs. white-box** (Cycle 2): same everything, only source-code
  access differs. Hold all other variables constant for the comparison to
  mean anything.
- **Before vs. after remediation** (Cycle 3): re-run exploitation against the
  patched target; success = previously-solved challenges now report
  *unsolved*.
- **Per-phase pipeline vs. long-session baseline** (Cycle 3 ablation): does
  the structure actually help (vulns popped / tokens / failures)?

**Nondeterminism / trials.** A single run is an anecdote. We do **not** need
to *report* multi-run statistics until end of Cycle 3 — but the orchestrator
must **log every run in a parseable form from day one**, so "report a
distribution across K runs" is free later rather than a November rebuild.

---

## 6. Operations

- **Autonomy.** The agent runs tools unattended (no per-command human
  approval) — via allowed-tools / skip-permissions. For now it runs directly
  inside a **throwaway VM**, which contains the blast radius (the agent can
  damage that VM; that's fine, it's disposable — never run it anywhere we'd
  miss). A dedicated container with network scoped to the Juice Shop target
  only is planned for **late Cycle 2 / Cycle 3**.
- **Target.** Containerized Juice Shop, port-forwarded to localhost, board
  removed, hints/tutorials disabled.
- **CLI.** Runs from the user's PATH; parameters for target, model, mode
  (pentest depth), and report location, with defaults for all except target.
- **Install flow.** Setup checks for Claude Code, offers to install it, user
  authenticates with their *own* Claude account (we do not provide it).
- **Demo.** Cycle demos use a **recorded run**, 

---

## 7. Remediation: degrade path

Full agentic patch-writing is the item most likely to slip, so it is
explicitly degradable and the sponsor is satisfied without full integration:

1. **Minimum (committed):** the agent *drafts* a mitigation playbook from the
   findings. A human applies it.
2. **Verify mode (committed, cheap):** re-invoke APT with the playbook + the
   now-patched live target. This is just the **exploitation phase re-run as a
   regression test** — success = the server-side oracle reports the
   previously-solved challenges as *unsolved*. Same code, same oracle, run
   twice; the delta is the before/after metric.
3. **Stretch:** the agent *implements* the fixes itself (edit source →
   rebuild → re-test) and verifies they hold.

Decide the degrade level *before* Cycle 3, not during it.

---

## 8. Known limitations / future work

- **Strict linear pipeline.** Real pentesting loops backward (exploitation
  reveals new attack surface worth re-recon). v1 is one-way for
  buildability; iterative loop-back is future work.
- **Agentic patch-writing** (§7 stretch).
- **General-purpose targeting** beyond Juice Shop.
- **Competitor benchmark** (vs. Strix / PentestGPT) as a publication angle.
- **Dashboard.** The sponsor plan includes a live monitoring dashboard; treat
  it as lower priority than the agent itself. Logging-to-file + a simple
  report is the fallback if the dashboard competes for time.

---

## 9. Open items to resolve this week (Cycle 1)

1. **Draft v1 of the `findings.json` schema** (§3) — before the orchestrator.
2. **Confirm the headless invocation mechanism** (`claude -p` per phase,
   clean context, phase-specific prompt + tool set).
3. **Wire the `record_finding` tool / file contract** so structured output is
   a side effect during the phase.
4. **Build parseable run-logging into the orchestrator now** (for Cycle 3
   trials).
5. **Confirm unattended tool execution** works inside the throwaway VM.

---

## Appendix: decisions locked in the design session

| Question | Decision |
|---|---|
| Beat a competing tool? | No — PoC demonstrating functionality only. |
| Thesis | Autonomous full-cycle pentest of Juice Shop vs. private ground truth. |
| Phase architecture | Per-phase headless agents, clean context each. |
| Handoff mechanism | Validated, file/tool-based `findings.json` (not prose, not final-message parsing). |
| Long-session variant | Kept as free baseline/ablation, not a second product. |
| Exploitation oracle | Juice Shop server-side solve detection (UI hidden, detection kept). |
| Possible-set ground truth | Hand-written vuln answer key. |
| Score detection or exploitation? | Exploitation (oracle-confirmed). |
| Context strategy | Raw → disk; structured triage → handoff; raw pulled on demand. |
| Remediation | Draft playbook + human apply + verify-mode regression re-run; agentic patching is stretch. |
| Sandbox | Throwaway VM now → scoped container late Cycle 2/3. |
| Demo | Recorded run. |
| Multi-run results | Logged from day one, reported end of Cycle 3. |
