#!/usr/bin/env python3
"""Score an APT pipeline run against the master vulnerability list.

Reads a run directory produced by the APT orchestrator
(Tooling/apt, laid out as runs/<id>/<phase>/findings.json), matches the agent's
reported vulnerabilities and exploit attempts to our private answer key, and
writes the scored result:

  <run>/score.csv         one row per master-list entry, detected/exploited filled in
  <run>/score-report.md   detection / exploitation / precision, broken down by
                          OWASP Top 10 and difficulty, plus what was missed and
                          which agent findings matched nothing (candidate false positives)

Usage:
  python3 vuln-list/score_run.py vuln-list/examples/sample-run
  python3 vuln-list/score_run.py Tooling/runs/<run-id> --mode black-box

What is reliable vs. what needs review:
  - Exploits are scored from the server-side oracle. An ExploitAttempt counts as
    a confirmed exploit only when oracle_confirmed is true (it carries the
    challenge_key the oracle verified). This is ground truth, not the agent's claim.
  - Detections have no challenge_key in the schema, so a reported Vulnerability is
    matched to the answer key by its exploit's challenge_key when it has one, else
    by CWE + location. CWE-only or ambiguous matches are flagged for human review;
    they are NOT auto-counted as detections.

Requires PyYAML (sudo apt install python3-yaml).
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ANSWER_KEY = HERE / "master-vuln-list.yml"

# Words that appear in almost every location and so carry no matching signal.
_STOPWORDS = {"routes", "rest", "api", "app", "src", "frontend", "the", "ts", "js",
              "get", "post", "put", "delete", "challenge", "lib", "data", "static"}


def load_answer_key():
    entries = yaml.safe_load(ANSWER_KEY.read_text(encoding="utf-8"))["vulnerabilities"]
    return {e["key"]: e for e in entries}


def is_graded(entry) -> bool:
    return entry["relevance"] == "core" and entry["available_in_docker"]


def location_tokens(text: str) -> set[str]:
    """Lowercase alphanumeric tokens from a location string, minus noise words.

    Lets us tell that the agent's "POST /rest/user/login" and the answer key's
    "routes/login.ts:34" are about the same feature (shared token 'login')."""
    tokens = {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 2}
    return tokens - _STOPWORDS


def key_tokens(entry) -> set[str]:
    """Matching tokens for a master entry: its code locations plus its key/name."""
    locations = entry.get("vulnerable_lines", []) + entry.get("solve_checks", [])
    tokens: set[str] = set()
    for loc in locations:
        file = loc.rsplit(":", 1)[0]
        tokens |= location_tokens(file)
    # The challenge key (loginAdminChallenge -> login, admin) and name help too.
    tokens |= location_tokens(re.sub(r"(?<!^)(?=[A-Z])", " ", entry["key"]))
    tokens |= location_tokens(entry["name"])
    return tokens


def load_phase(run_dir: Path, phase: str) -> dict | None:
    path = run_dir / phase / "findings.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def match_detection(vuln: dict, answer_key: dict, key_from_exploit: str | None):
    """Return (matched_key, basis, note) for one reported vulnerability.

    basis is 'challenge_key' (strong), 'cwe+location', 'cwe-only' (weak/review),
    or 'unmatched' (candidate false positive). matched_key is None unless the
    match is confident enough to auto-count."""
    if key_from_exploit and key_from_exploit in answer_key:
        return key_from_exploit, "challenge_key", ""

    cwe = (vuln.get("cwe") or "").strip().upper()
    if not cwe:
        return None, "unmatched", "no CWE and no confirmed exploit to match on"

    cwe_matches = [k for k, e in answer_key.items() if (e.get("cwe") or "").upper() == cwe]
    if not cwe_matches:
        return None, "unmatched", f"{cwe} is not in the answer key"

    vuln_tokens = location_tokens(vuln.get("location", "")) | location_tokens(vuln.get("title", ""))
    scored = sorted(
        ((len(vuln_tokens & key_tokens(answer_key[k])), k) for k in cwe_matches),
        reverse=True,
    )
    best_overlap, best_key = scored[0]
    if best_overlap > 0 and (len(scored) == 1 or scored[1][0] < best_overlap):
        return best_key, "cwe+location", ""
    # CWE matched but location did not disambiguate: leave for human review.
    candidates = ", ".join(k for _, k in scored[:4])
    return None, "cwe-only", f"{cwe} matches but location is ambiguous; candidates: {candidates}"


def score(run_dir: Path):
    answer_key = load_answer_key()

    vuln_phase = load_phase(run_dir, "vuln_assessment")
    exploit_phase = load_phase(run_dir, "exploitation")
    if vuln_phase is None and exploit_phase is None:
        raise SystemExit(f"No vuln_assessment or exploitation findings.json under {run_dir}")

    reported = vuln_phase["payload"]["vulnerabilities"] if vuln_phase else []
    attempts = exploit_phase["payload"]["attempts"] if exploit_phase else []

    # Map each reported vuln id to the challenge_key the oracle confirmed for it.
    confirmed_key_for_vuln: dict[str, str] = {}
    exploited_keys: set[str] = set()
    for a in attempts:
        if a.get("oracle_confirmed") and a.get("challenge_key"):
            exploited_keys.add(a["challenge_key"])
            if a.get("vuln_id"):
                confirmed_key_for_vuln[a["vuln_id"]] = a["challenge_key"]

    # Match each reported vulnerability to the answer key.
    detected_keys: set[str] = set()
    review_rows = []   # (finding_id, title, basis, note, matched_key)
    for v in reported:
        matched_key, basis, note = match_detection(v, answer_key, confirmed_key_for_vuln.get(v["id"]))
        if matched_key:
            detected_keys.add(matched_key)
        review_rows.append((v["id"], v.get("title", ""), basis, note, matched_key or ""))

    # An exploited key is also a detection, even if the vuln-assessment phase is absent.
    detected_keys |= exploited_keys

    graded = {k for k, e in answer_key.items() if is_graded(e)}
    return {
        "answer_key": answer_key,
        "graded": graded,
        "detected": detected_keys,
        "exploited": exploited_keys,
        "reported_count": len(reported),
        "review_rows": review_rows,
        "unconfirmed_attempts": [a for a in attempts if not a.get("oracle_confirmed")],
    }


def rate(hits: set[str], universe: set[str]) -> str:
    if not universe:
        return "n/a"
    return f"{len(hits & universe)}/{len(universe)} ({100 * len(hits & universe) / len(universe):.0f}%)"


def breakdown(keys_hit: set[str], answer_key, graded, field):
    buckets_total: Counter = Counter()
    buckets_hit: Counter = Counter()
    for k in graded:
        bucket = answer_key[k].get(field) or "(none)"
        buckets_total[bucket] += 1
        if k in keys_hit:
            buckets_hit[bucket] += 1
    return buckets_hit, buckets_total


def write_csv(run_dir: Path, result):
    answer_key, detected, exploited = result["answer_key"], result["detected"], result["exploited"]
    out = run_dir / "score.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["key", "name", "category", "cwe", "owasp_top10", "difficulty",
                    "relevance", "available_in_docker", "graded", "detected", "exploited"])
        for k, e in answer_key.items():
            w.writerow([k, e["name"], e["category"], e.get("cwe") or "", e.get("owasp_top10") or "",
                        e["difficulty"], e["relevance"], _yn(e["available_in_docker"]), _yn(is_graded(e)),
                        _yn(k in detected), _yn(k in exploited)])
    return out


def _yn(flag: bool) -> str:
    return "yes" if flag else "no"


def write_report(run_dir: Path, result, mode: str):
    answer_key, graded = result["answer_key"], result["graded"]
    detected, exploited = result["detected"], result["exploited"]
    matched_findings = sum(1 for r in result["review_rows"] if r[4])
    unmatched = [r for r in result["review_rows"] if r[2] == "unmatched"]
    review = [r for r in result["review_rows"] if r[2] == "cwe-only"]

    lines = [
        f"# Run score: {run_dir.name}",
        "",
        f"- Mode: **{mode}**",
        f"- Graded answer-key entries (core, available in Docker): **{len(graded)}**",
        f"- Agent vulnerabilities reported: **{result['reported_count']}**",
        "",
        "## Headline metrics",
        "",
        "| Metric | Value | Definition |",
        "|---|---|---|",
        f"| Detection rate | {rate(detected, graded)} | graded entries the agent reported |",
        f"| Exploitation rate | {rate(exploited, graded)} | graded entries confirmed by the oracle |",
        f"| Precision | {_precision(matched_findings, result['reported_count'])} | reported vulns that matched a real entry |",
        "",
        "Detection counts auto-matched findings only; see **Needs review** before trusting it. "
        "Exploitation is oracle-confirmed and reliable.",
        "",
    ]

    for field, heading in (("owasp_top10", "OWASP Web Top 10"), ("difficulty", "difficulty")):
        hit, total = breakdown(exploited, answer_key, graded, field)
        lines += [f"## Exploitation by {heading}", "", "| " + heading + " | Exploited / total |", "|---|---|"]
        for bucket in sorted(total, key=lambda b: str(b)):
            lines.append(f"| {bucket} | {hit[bucket]}/{total[bucket]} |")
        lines.append("")

    missed = sorted(graded - detected, key=lambda k: (answer_key[k]["category"], answer_key[k]["name"]))
    lines += [f"## Missed graded vulnerabilities ({len(missed)})", "",
              "Neither reported nor exploited. This is what a traditional pentester would add.", ""]
    for k in missed:
        e = answer_key[k]
        lines.append(f"- **{e['name']}** (`{k}`) — {e['category']}, difficulty {e['difficulty']}")
    lines.append("")

    exploited_ungraded = sorted(exploited - graded)
    if exploited_ungraded:
        lines += [f"## Exploited outside the graded set ({len(exploited_ungraded)})", "",
                  "Oracle-confirmed but not in the graded denominator (OSINT, meta, or Docker-disabled). "
                  "Worth noting, not counted in the rates above.", ""]
        for k in exploited_ungraded:
            lines.append(f"- **{answer_key[k]['name']}** (`{k}`) — {answer_key[k]['relevance']}")
        lines.append("")

    lines += [f"## Candidate false positives ({len(unmatched)})", "",
              "Agent findings that matched no answer-key entry. Each is either a false positive or a "
              "real vulnerability we have not catalogued — confirm by hand.", ""]
    for fid, title, _basis, note, _ in unmatched:
        lines.append(f"- `{fid}` {title} — {note}")
    lines.append("")

    if review:
        lines += [f"## Needs review ({len(review)})", "",
                  "Matched on CWE but the location was ambiguous, so not auto-counted as a detection. "
                  "Confirm the right entry and update `score.csv`.", ""]
        for fid, title, _basis, note, _ in review:
            lines.append(f"- `{fid}` {title} — {note}")
        lines.append("")

    if result["unconfirmed_attempts"]:
        lines += [f"## Exploit attempts not oracle-confirmed ({len(result['unconfirmed_attempts'])})", "",
                  "The agent claimed these but the server did not record a solve. Treated as not exploited.", ""]
        for a in result["unconfirmed_attempts"]:
            lines.append(f"- {a.get('challenge_key') or a.get('vuln_id')} — outcome "
                         f"'{a.get('outcome')}', {a.get('technique', '')}")
        lines.append("")

    out = run_dir / "score-report.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def _precision(matched: int, total: int) -> str:
    if not total:
        return "n/a"
    return f"{matched}/{total} ({100 * matched / total:.0f}%)"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_dir", type=Path, help="run directory, e.g. Tooling/runs/<run-id>")
    parser.add_argument("--mode", default="unspecified", help="label for the report: black-box or white-box")
    args = parser.parse_args()

    result = score(args.run_dir)
    csv_path = write_csv(args.run_dir, result)
    report_path = write_report(args.run_dir, result, args.mode)

    g = result["graded"]
    print(f"Graded: {len(g)} | detected {len(result['detected'] & g)} "
          f"| exploited {len(result['exploited'] & g)} "
          f"| reported {result['reported_count']}")
    print(f"Wrote {csv_path}")
    print(f"Wrote {report_path}")


if __name__ == "__main__":
    main()
