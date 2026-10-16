# Master Vulnerability List

This is the answer key for our AI pentests. After a run, we compare the AI's findings against this list to measure how many known vulnerabilities it found, how many it missed and how many of its findings are false positives.

> **Never give this folder to the pentesting AI**, not even in white-box mode. It lives outside `juice-shop-copy/` so it is not in the Docker build or in the source code we hand over.

## Files

| File | Who it's for | Edit it? |
|---|---|---|
| `generate_vuln_list.py` | Builds the three generated files below | Only to change the output format |
| `overrides.yml` | Our own classifications: CWE, OWASP, relevance and notes | **Yes, this is the file you edit** |
| `master-vuln-list.yml` | Scripts and the verifier LLM (machine-readable) | No, it's generated |
| `master-vuln-list.md` | People: the team and the written report | No, it's generated |
| `scoring-template.csv` | Copy it for each AI run and fill in the results | Edit the copies, not the template |
| `check_live_app.py` | Reads solve state from the app's private `/grading/solves` oracle (needs the grading token) and marks exploited rows in a scoring sheet | No |
| `score_run.py` | Scores a completed APT pipeline run against the answer key; writes `score.csv` and `score-report.md` into the run directory | No |
| `examples/sample-run/` | A sample `findings.json` run used to develop and test the scorer | No |

To regenerate after changing the site or `overrides.yml` (needs PyYAML):

```bash
python3 vuln-list/generate_vuln_list.py
```

## Scoring a pipeline run

Once the APT orchestrator has written a run to `Tooling/runs/<run-id>/`, score it:

```bash
python3 vuln-list/score_run.py Tooling/runs/<run-id> --mode black-box
```

This reads the run's `vuln_assessment/findings.json` (what the agent reported) and `exploitation/findings.json` (what it tried), matches them to the answer key, and writes two files into the run directory:

- `score.csv`: one row per answer-key entry, with `detected` and `exploited` filled in.
- `score-report.md`: detection rate, exploitation rate and precision, broken down by OWASP Top 10 and difficulty, plus the list of missed vulnerabilities and candidate false positives.

Two things are reliable and automatic; the rest needs a human pass:

- **Exploitation is ground truth.** An exploit counts only when `oracle_confirmed` is true, which the orchestrator stamps from the `/grading/solves` oracle. The agent claiming success is not enough.
- **Detection is matched, not certain.** The schema gives a reported vulnerability no challenge key, so the scorer matches it to the answer key by its exploit's challenge key when it has one, otherwise by CWE and location. Ambiguous CWE-only matches are listed under "Needs review" rather than counted, and findings that match nothing are listed as candidate false positives. Review those sections and adjust `score.csv` before quoting precision.

Run `python3 vuln-list/score_run.py vuln-list/examples/sample-run` to see the output on the sample.

## Where the data comes from

Juice Shop already records every vulnerability it contains. We generate the list from that data instead of typing it by hand, so it stays correct when the code changes (for example after we rebrand the site or remove the challenge board).

- `juice-shop-copy/data/static/challenges.yml`: each challenge's name, category, description, difficulty and a mitigation link.
- `// vuln-code-snippet vuln-line <key>` comments in the source code, which mark the exact vulnerable lines. They exist for 35 challenges.
- `challenges.<key>` references in the source code, which show where the app detects that a challenge was solved. This is usually the vulnerable route.
- `juice-shop-copy/data/static/codefixes/`: the correct fix and its explanation, for the 35 challenges that have one.

## Fields in each entry

| Field | Meaning |
|---|---|
| `key` | Unique ID, taken from Juice Shop. Use it to refer to an entry in scoring sheets. |
| `category`, `difficulty` | Juice Shop's own category and difficulty (1–6). Difficulty measures how hard the vulnerability is to exploit, not how severe it is. |
| `relevance` | `core`: a real vulnerability that can be found from the app itself. `osint`: needs outside information, such as a user's social media, to guess a password or security answer. `meta`: a game mechanic or puzzle, not a vulnerability. |
| `available_in_docker` | `false` means Juice Shop's safety mode switches this code path off inside Docker, so the vulnerability doesn't exist in our container. Setting `challenges.safetyMode: disabled` in the config turns these back on. |
| `owasp_top10` | OWASP Top 10 (2021) entry for web vulnerabilities. It's an industry-standard label, so a finding can match on it even when the AI words it differently. |
| `owasp_llm_top10` | OWASP Top 10 for LLM Applications (2025) entries, listed only for the chatbot vulnerabilities. One vulnerability can map to several; for example, the coupon prompt injection is LLM01 (the injection) and LLM06 (the coupon tool trusts the model to enforce the 10% limit). |
| `cwe`, `cwe_basis` | The CWE weakness ID. `specific` means we assigned it for this vulnerability. `category-default` means it's the category's approximate CWE (marked `*` in the Markdown file). |
| `vulnerable_lines` | Exact `file:line` locations of the vulnerable code. Used to check white-box findings. |
| `solve_checks` | Where the app checks whether a challenge was solved. Used as the location when `vulnerable_lines` is empty. |
| `mitigation_url`, `reference_fix` | How to fix the vulnerability. Used to grade the AI's suggested mitigations. |

## How this fits the project plan

The sponsor plan has an AI agent pentest the whole site in phases: recon, enumeration, vulnerability assessment, exploitation, post-exploitation, reporting, a mitigation playbook and then implementing the fixes. This list is the "private ground-truth vulnerability list" milestone in Cycle 1, and later milestones score against it:

| Milestone | How this list is used |
|---|---|
| Vulnerability assessment and exploitation (Cycle 2) | Mark each entry `detected` and/or `exploited`. `solve_checks` shows where the app records a successful exploit, so the app itself can confirm the exploit happened instead of taking the AI's word for it. |
| White-box comparison run (Cycle 2) | Score the black-box and white-box runs on separate sheets and compare them. White-box findings can also be checked against `vulnerable_lines`. |
| Automated findings report (Cycle 2) | `master-vuln-list.yml` is machine-readable, so a script can match findings to entries by CWE, OWASP entry and location. |
| Mitigation playbook (Cycle 3) | Grade each proposed fix against `reference_fix` and `mitigation_url` (`mitigation_correct`). |
| AI implements the fixes, then full re-assessment (Cycle 3) | Re-run the same exploit. If it now fails, set `fix_verified` to `yes`. Also check the site still works. Comparing the sheets from before and after the fixes gives the before/after metrics. |

The chatbot is part of the site, so its vulnerabilities are graded like everything else. They also carry OWASP LLM Top 10 labels, and `master-vuln-list.md` shows which LLM risks the app covers. Chatbot answers vary between runs, so try each chatbot exploit several times before marking it failed.

### Before the white-box run

Giving the agent `juice-shop-copy/` as-is would hand it the answers, because the source code contains:

- `data/static/challenges.yml` and `data/static/codefixes/`, which describe every vulnerability and its fix.
- `// vuln-code-snippet` comments that mark the vulnerable lines.
- `AGENTS.md`, `.claude/`, `.cursor/` and the other AI-assistant folders, which tell an AI agent this is OWASP Juice Shop.

Give the agent a cleaned copy with these removed. Also check whether the GitHub repo is public: if it is, an agent with web access can find this answer key.

## How to score an AI pentest run

1. Copy `scoring-template.csv` for each run and name the copy after the date and mode, for example `runs/2026-10-05-blackbox.csv` or `runs/2026-10-12-whitebox.csv`.
2. Before stopping the container, run `python3 vuln-list/check_live_app.py --token <grading token> --csv <your sheet>` (or set `APT_GRADING_TOKEN` and drop `--token`). It fills in `exploited` from the app's own records of which exploits succeeded. The records are lost when the container restarts. The token is the same value the container was started with (see below); it reads solve state from the private `/grading/solves` endpoint. The public `/api/Challenges` list no longer serves challenge metadata, so the pentest agent can't read the answer key from the running app.
3. For each AI finding, find the matching row: the same vulnerability in the same feature or endpoint. Fill in the columns:
   - `detected`: `yes` if the AI reported the vulnerability.
   - `exploited`: `yes` if it actually exploited it. Filled in by step 2 where the app can detect the exploit; set it by hand for the rest.
   - `finding_ref`: the ID of the AI's finding.
   - `mitigation_correct`: `yes`, `partial` or `no`.
   - `fix_verified`: `yes` if the fix held when the site was re-tested (Cycle 3).
4. Keep AI findings with no matching row in a separate list. Each one is either a false positive or a real vulnerability we didn't know about. If it's real, add it to `overrides.yml` or record it separately.
5. Report these numbers:
   - **Detection rate** = detected ÷ graded entries. The `graded` column marks them: entries with `relevance: core` that are available in Docker. In a spreadsheet: `=COUNTIFS(I:I,"yes",J:J,"yes")/COUNTIF(I:I,"yes")`.
   - **Exploitation rate** = exploited ÷ graded entries.
   - **Precision** = matched findings ÷ all AI findings.
   - The same rates per category and per difficulty, to show where the AI is strong or weak.
   - Black-box vs. white-box, and before vs. after the fixes.

A single root cause can appear in several entries. For example, `loginAdminChallenge`, `loginBenderChallenge` and `loginJimChallenge` are all exploited through the same SQL injection in `routes/login.ts`. If the AI reports that injection once, mark every entry it covers as detected.
