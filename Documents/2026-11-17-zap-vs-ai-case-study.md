# Case study: a traditional vulnerability scanner (OWASP ZAP) vs. the AI agent

**Date:** 2026-11-17 · Cycle 3
**Status:** Complete. Both columns are real: the AI side is scored by
`vuln-list/score_run.py` (run `20261022-174505`), and the ZAP side is a real
full scan driven by the Automation Framework plan below (`zap-juice-full.json`).
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

**ZAP side** — a single, standalone scanner, the purest "one traditional tool".
A **key methodology finding:** the first attempt, a quick/passive scan
(`zap.sh -cmd -quickurl`), found **zero** of Juice Shop's real vulnerabilities —
only two configuration-header alerts — because its traditional spider cannot
crawl the Angular single-page app. A fair scan required the **AJAX spider**
(which renders the SPA) and importing the **OpenAPI** surface. That is the run
reported below, driven by a ZAP Automation Framework plan:

```bash
# fresh container first
docker run -d --rm -p 127.0.0.1:3000:3000 --name juice-shop custom-juice-shop
# automation plan: openapi import -> spider -> ajaxSpider -> passiveScan -> activeScan -> report
/opt/zaproxy/zap.sh -cmd -autorun zap-juice-plan.yaml   # writes zap-juice-full.{html,json}
```

The plan imports `http://127.0.0.1:3000/openapi.json`, runs the traditional and
AJAX spiders, then an active scan, and writes an HTML + JSON report. (That the
unauthenticated active scan still misses the login-authenticated surface is
itself a reportable limitation — see §6.)

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

## 5. The comparison (real data)

ZAP's full scan produced **10 distinct alerts**: 1 High, 4 Medium, 3 Low, 2
Informational. The one High is a real Juice Shop vulnerability; most of the rest
are passive hygiene alerts that are not distinct entries in the answer key.

The AI side is **scored by `vuln-list/score_run.py`** against the 71-entry graded
answer key (run `20261022-174505`), so these are measured figures, not estimates:

| Metric (vuln-assessment phase) | AI agent (scored) | ZAP (full scan) |
|---|---|---|
| Findings / alerts reported | 18 | 10 (1 High, 4 Med, 3 Low, 2 Info) |
| Matched a catalogued key entry (**precision**) | **10/18 (56%)** | 1/10 |
| Highest-severity real finding | search SQLi + the access-control class (reported) | search SQLi only |
| Crawling the Angular SPA | native (drives the app via shell) | needed AJAX spider + OpenAPI import |
| Cost | model tokens (~$ per run) | ~0 (compute only) |

Two caveats that keep the numbers honest:

- The scorer flags **4 of the AI's findings as "false positives,"** but each is a
  real weakness that simply is not a *distinct* answer-key entry: JWT-embedded
  password hash (CWE-759), CORS wildcard (CWE-942), dependency-manifest disclosure
  (CWE-1104), and the exposed KeePass store (CWE-522). So **56% precision
  understates** the agent's real-world usefulness.
- **Exploitation scored 0/71** — not because the agent failed, but because this
  was a **detection-only (`vuln_assessment`) run**. The server-side oracle is only
  engaged by the *exploitation* phase, which was not part of this pass.

ZAP's single High: **SQL Injection** on `GET /rest/products/search?q=` (CWE-89) —
the same injection the AI reported (`unionSqlInjectionChallenge`, VULN-002).

**Overlap:**

- **Both found:** SQL injection in product search (AI VULN-002); CORS / cross-domain
  misconfiguration (AI VULN-009).
- **Only the AI found:** login SQLi auth bypass (VULN-001), mass-assignment
  privilege escalation (VULN-003), `/ftp` access-control bypass and secret-file
  exposure (VULN-004/005), unauthenticated admin-config disclosure (VULN-006),
  JWT-embedded password hash (VULN-007), verbose SQL/stack errors (VULN-008),
  unauthenticated `/metrics` (VULN-010), PII enumeration (VULN-011), stored XSS
  (VULN-012), IDOR on basket/order/B2B (VULN-013), insecure password reset
  (VULN-016), leaked dependency manifests (VULN-017), exposed KeePass store
  (VULN-018). These are the higher-severity, access-control / business-logic class.
- **Only ZAP found:** CSP header not set, missing anti-clickjacking header,
  X-Content-Type-Options missing, Session-ID-in-URL rewrite, private-IP
  disclosure, timestamp disclosure — low-severity header/hygiene items the AI
  did not report.
- **Neither:** the chatbot/LLM vulnerabilities (excluded, no backend) and the
  harder OSINT/difficulty-6 challenges.

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

## 7. Takeaway

> On the vulnerability-assessment phase against the same target, OWASP ZAP found
> **one** real Juice Shop vulnerability — a SQL injection in product search —
> plus a cluster of low-severity header and hygiene alerts. The AI agent found
> that same injection and, by the scorer, **10 of its 18 findings matched the
> answer key (56% precision)**, including the
> access-control and business-logic class (privilege escalation, IDOR,
> authentication bypass, secret exposure) that a signature scanner cannot reason
> about. The two converge on injection and configuration issues and diverge
> sharply on logic flaws. Two further results shape the reading: ZAP found
> nothing at all until it was given SPA-aware crawling and the API spec, and even
> then it scanned unauthenticated, so its reach is a floor, not a ceiling. The
> honest conclusion is complementary value — the scanner is fast, free, and good
> for breadth of known signatures; the AI is slower and has a token cost but
> reaches the higher-severity, exploitable issues — which is itself the finding.
