#!/usr/bin/env python3
"""APT (Automated Pentesting) -- environment preflight.

OS-agnostic replacement for setup.sh. Minimal, non-comprehensive check that the
machine is ready to run APT. Authentication is delegated entirely to Claude
Code; this script only verifies that Claude Code is present, runnable, and
authenticated by firing a single headless call.

Usage:  python3 preflight.py

Exit code: 0 if all required checks pass, 1 otherwise. Warnings never fail.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

# --- pretty output (colours only on a TTY that supports them) --------------
# On Windows, only enable ANSI when the terminal advertises VT support; the
# modern Windows Terminal / VS Code terminal set it, legacy conhost does not.
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


class Counters:
    hard_fails = 0
    warnings = 0


def _p(label_colour: str, label: str, msg: str) -> None:
    print(f"  {label_colour}[ {label} ]{RESET} {msg}")


def ok(msg: str) -> None:
    _p(GREEN, "PASS", msg)


def warn(msg: str) -> None:
    _p(YELLOW, "WARN", msg)
    Counters.warnings += 1


def fail(msg: str) -> None:
    _p(RED, "FAIL", msg)
    Counters.hard_fails += 1


def _run(cmd: list[str], timeout: float | None = None) -> subprocess.CompletedProcess:
    """Run a command, capturing text output. Raises on timeout like the shell
    `timeout` guard did (caller decides what a timeout means)."""
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
    )


def main() -> int:
    print(f"{BOLD}== APT environment preflight =={RESET}\n")

    # --- 1. Is Claude Code on PATH? ----------------------------------------
    claude = shutil.which("claude")
    if claude:
        ok(f"Claude Code found: {claude}")
    else:
        fail("Claude Code ('claude') is not on your PATH.")
        print("         Install it, then re-run this script:\n")
        print("           curl -fsSL https://claude.ai/install.sh | bash")
        print("             or")
        print("           npm install -g @anthropic-ai/claude-code\n")
        print("         (Other install methods: https://docs.claude.com/en/docs/claude-code)")
        _summary()
        return 1

    # --- 2. Is it runnable? ------------------------------------------------
    try:
        res = _run([claude, "--version"], timeout=30)
        if res.returncode == 0:
            ok(f"Claude Code runs: {res.stdout.strip() or '(no version string)'}")
        else:
            fail("'claude --version' did not run cleanly -- the install may be broken.")
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"'claude --version' could not be run: {exc}")

    # --- 3. The spike: headless call works AND is authenticated ------------
    print(f"  {YELLOW}...{RESET} testing a headless Claude call (auth + invocation)...")
    sentinel = "APT_OK"
    try:
        res = _run(
            [claude, "-p", f"Reply with exactly this word and nothing else: {sentinel}"],
            timeout=90,
        )
        if res.returncode == 0:
            if sentinel in (res.stdout or ""):
                ok("Headless call succeeded and Claude Code is authenticated.")
            else:
                warn("Headless call returned, but output was unexpected: "
                     f"{(res.stdout or '').strip()[:120]}")
        else:
            fail(f"Headless Claude call failed (exit {res.returncode}). "
                 "You are likely not authenticated.")
            print("         Authenticate Claude Code yourself, then re-run:")
            print("           claude        # then follow its login prompts")
    except subprocess.TimeoutExpired:
        fail("Headless Claude call timed out (90s). Check your network / Claude Code.")
    except OSError as exc:
        fail(f"Headless Claude call could not be run: {exc}")

    # --- 4. Optional pentest tooling (warn only, never fatal) --------------
    for tool in ("curl", "nmap"):
        if shutil.which(tool):
            ok(f"Optional tool present: {tool}")
        else:
            warn(f"Optional tool missing: {tool} (install later; not required for preflight)")

    return _summary()


def _summary() -> int:
    print(f"\n{BOLD}== Summary =={RESET}  ", end="")
    if Counters.hard_fails == 0:
        print(f"{GREEN}all required checks passed{RESET} ({Counters.warnings} warnings)")
        print("Environment is ready for APT.")
        return 0
    print(f"{RED}{Counters.hard_fails} required check(s) failed{RESET} "
          f"({Counters.warnings} warnings)")
    print("Fix the failures above and re-run: python3 preflight.py")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
