# Case study: a traditional vulnerability scanner (OWASP ZAP) vs. the AI agent

**Date:** 2026-11-17 · Cycle 3
**Status:** Framework + AI side populated from a real run. The ZAP column is
filled by running the scan below (needs Docker, which the write-up author did
not have); numbers there are **not** to be invented.
**Scope note:** This is a *case study* for the written report and presentation.
It is deliberately **not** built into the APT product — it is one focused,
hand-run comparison, per the sponsor's steer ("if we could just show one
comparison of a traditional vulnerability scan tool vs the relevant phase of our
AI tool, that would be enough").

---

## 1. The question

A traditional web pentest leans on an automated DAST scanner — most commonly
**OWASP ZAP** — to find vulnerabilities. Our AI agent does the same job in its
**vulnerability-assessment phase**. So, on the identical target:

> What does a conventional vulnerability scanner find that the AI misses, what
> does the AI find that the scanner misses, and where do they agree?

We answer it for the *vulnerability-assessment* phase specifically, because that
is the phase a DAST scanner maps onto. (Recon/enumeration map onto nmap/ffuf;
exploitation maps onto sqlmap; a scanner has no real equivalent for
post-exploitation, reporting or mitigation — see the phase map below.)

## 2. Traditional tool path, by phase

Where a human-run engagement reaches for off-the-shelf tooling, and what the APT
free-tools baseline (`Tooling/baseline/`) uses to stand in for it:

| Phase | Traditional tools | DAST scanner's role |
|---|---|---|
| Reconnaissance | nmap, WhatWeb | services, versions, tech stack |
| Enumeration | Katana, ffuf, Arjun | crawl, content & parameter discovery |
| **Vulnerability assessment** | **ZAP** (DAST), Nuclei, Nikto, Retire.js, Semgrep (white-box) | **the scanner's core job: flag vulnerabilities** |
| Exploitation | sqlmap, ZAP active scan | prove injection / active attacks |
| Post-exploitation | *(no scanner equivalent)* | — |
| Reporting | *(no scanner equivalent)* | — |
| Mitigation | *(no scanner equivalent)* | — |

The bolded row is the comparison. ZAP is the representative "traditional
vulnerability scanner."

## 3. Method (reproducible)

Both sides hit an **identical, freshly restarted** Juice Shop container (solve
state lives in memory, so a restart between runs stops one side's exploits being
credited to the other — see `Tooling/README.md`).

**AI side** (already have it — run `20261022-174505`):
```bash
python3 -m apt --target http://127.0.0.1:3000 --phases vuln_assessment --unattended
python3 vuln-list/score_run.py Tooling/runs/<ai-run>
```

**ZAP side** — a single, standalone scanner, the purest "one traditional tool":
```bash
# fresh container first
docker run -d --rm -p 127.0.0.1:3000:3000 --name juice-shop custom-juice-shop
# ZAP baseline (passive) scan; add -I so a WARN exit doesn't fail the run
docker run --rm -v "$PWD:/zap/wrk" zaproxy/zap-stable \
    zap-baseline.py -t http://host.docker.internal:3000 -J zap.json -r zap.html -I
```
Map ZAP's alerts to the answer key the same way the baseline adapter does, or
run the integrated baseline (`python3 -m baseline --phases vuln_assessment`),
whose vuln-assessment phase is ZAP-led, and score it with `score_run.py`. Then
`vuln-list/compare_runs.py` produces the only-AI / both / only-ZAP overlap.

> Fill the ZAP cells below from that scan. Do not estimate them.

## 4. What the AI found (real data, run `20261022-174505`)

The AI's vulnerability-assessment phase reported **18 candidate vulnerabilities**
across 7 OWASP Top-10 categories:

| # | OWASP | Conf. | Title |
|---|---|---|---|
| VULN-001 | A03 Injection | high | SQLi authentication bypass on login |
| VULN-002 | A03 Injection | high | Error-based SQLi in product search |
| VULN-003 | A01 Broken Access Control | high | Mass-assignment privilege escalation on registration |
| VULN-004 | A01 Broken Access Control | high | /ftp access-control bypass via null-byte/double-extension |
| VULN-005 | A05 Misconfiguration | high | Directory listing + backup/secret files at /ftp |
| VULN-006 | A05 Misconfiguration | high | Unauthenticated admin config disclosure |
| VULN-007 | A02 Cryptographic Failures | high | Unsalted password hash embedded in JWT |
| VULN-008 | A05 Misconfiguration | high | Verbose errors leak SQL / stack traces |
| VULN-009 | A05 Misconfiguration | medium | Permissive CORS wildcard |
| VULN-010 | A05 Misconfiguration | high | Unauthenticated Prometheus /metrics |
| VULN-011 | A01 Broken Access Control | high | PII enumeration via reviews/feedback |
| VULN-012 | A03 Injection | medium | Stored XSS via feedback comment |
| VULN-013 | A01 Broken Access Control | medium | IDOR on basket / order / B2B resources |
| VULN-014 | (LLM) | medium | Prompt injection against support chatbot* |
| VULN-015 | A03 Injection | low | NoSQL/blind injection candidate in order tracking |
| VULN-016 | A07 AuthN Failures | medium | Insecure password reset via security question |
| VULN-017 | A06 Vulnerable Components | medium | Dependency versions leaked via package manifests |
| VULN-018 | A02 Cryptographic Failures | medium | Exposed KeePass credential store |

\* VULN-014 is the chatbot prompt injection. Our build ships **no LLM backend**,
so this one is excluded from grading (`relevance: disabled`); it is listed here
only to show what the agent reported.

## 5. The comparison (fill ZAP from §3)

| Metric (vuln-assessment phase) | AI agent | ZAP |
|---|---|---|
| Candidate vulnerabilities reported | 18 | _fill_ |
| Graded answer-key detections | _from score_run_ | _fill_ |
| Detection rate (of 71 graded) | _fill_ | _fill_ |
| False positives / noise | _fill_ | _fill_ |
| Wall-clock time | from `run.json` `duration_s` | from ZAP output |
| Cost | from `run.json` `usage_total` | ~0 (compute/licence only) |

**Overlap (from `compare_runs.py`):**

- Only the AI found: _list_
- Both found: _list_
- Only ZAP found: _list_
- Neither found: _list_

## 6. What to expect, and how to read it

Frame the results around where each approach is structurally strong — the point
of the case study is the *shape* of the difference, not just a score:

- **A passive DAST scanner is strong at breadth of known signatures**: missing
  or weak security headers, the permissive CORS wildcard (VULN-009), verbose
  error pages (VULN-008), the exposed `/metrics` and `/ftp` listings
  (VULN-005/010), outdated JS libraries (VULN-017 — ZAP/Retire territory). Expect
  heavy **overlap with the AI on the misconfiguration (A05) and components (A06)
  rows**, and expect ZAP to surface low-severity hygiene findings the AI didn't
  bother to report.
- **The AI is structurally strong at business-logic and chained access-control
  flaws a signature scanner cannot reason about**: mass-assignment privilege
  escalation (VULN-003), the JWT-embedded password hash (VULN-007), IDOR across
  per-id resources (VULN-013), the null-byte `/ftp` filter bypass (VULN-004), and
  insecure password reset (VULN-016). These are the likely **only-AI** column —
  and they are the higher-severity ones.
- **Detection ≠ exploitation.** A scanner *flags* candidates; it rarely *proves*
  them. Our exploitation phase + the server-side oracle confirm which are real.
  So the strongest story is two-dimensional: breadth of detection (where ZAP is
  competitive) vs. confirmed exploitation and severity (where the AI's reasoning
  pays off). Report both, not a single headline number.

## 7. One-paragraph takeaway (to be finalized with the ZAP numbers)

> On the vulnerability-assessment phase, OWASP ZAP and the AI agent are expected
> to converge on configuration and hygiene findings, while diverging on
> access-control and business-logic flaws, which the AI reasons about and the
> scanner cannot. The scanner is fast and free but shallow and noisy; the AI is
> slower and has a token cost but reaches higher-severity, exploitable issues.
> The value is complementary, not either/or — which is itself the finding.
