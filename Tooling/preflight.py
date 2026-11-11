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

    # --- 5. Python packages for this interpreter ------------------------------
    check_python_packages()

    # --- 6. Memory headroom (warn only) -------------------------------------
    check_memory()

    return _summary()


def check_python_packages() -> None:
    """The pipelines run under *this* interpreter, so check its packages: a
    system python3 without pydantic is the usual cause of a failed first run."""
    import importlib.util
    venv_hint = ("Activate the project venv first (source ../.venv/bin/activate from "
                 "Tooling/), or: pip install -r requirements.txt")
    if importlib.util.find_spec("pydantic") is None:
        fail(f"pydantic is not installed for {sys.executable}. {venv_hint}")
    else:
        ok(f"pydantic available ({sys.executable})")
    if importlib.util.find_spec("yaml") is None:
        warn("PyYAML missing: runs will not be scored automatically, so they won't "
             f"appear in the Compare view. {venv_hint}")
    else:
        ok("PyYAML available (runs score themselves)")


def _meminfo() -> dict[str, int] | None:
    """MemTotal / MemAvailable / SwapTotal in MiB, from /proc/meminfo (Linux only)."""
    try:
        text = open("/proc/meminfo", encoding="utf-8").read()
    except OSError:
        return None
    out = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        if key in ("MemTotal", "MemAvailable", "SwapTotal"):
            out[key] = int(rest.split()[0]) // 1024
    return out


def check_memory() -> None:
    """Warn when a full run is likely to exhaust RAM. A free-tools run peaks
    around 2 GiB (ZAP is capped at 1.5 GiB) on top of the target container
    (~0.5 GiB) and Claude Code (~0.5 GiB per headless phase)."""
    mem = _meminfo()
    if mem is None:
        return  # not Linux; nothing to check
    avail, total, swap = mem.get("MemAvailable", 0), mem.get("MemTotal", 0), mem.get("SwapTotal", 0)
    msg = f"{avail / 1024:.1f} GiB of {total / 1024:.1f} GiB RAM available, swap {swap / 1024:.1f} GiB"
    if avail < 2560:
        warn(f"Low memory: {msg}. Close other apps and run the AI and free-tools runs "
             "one at a time, never together.")
    else:
        ok(f"Memory: {msg}")
    if swap == 0:
        warn("No swap. When RAM runs out the VM can freeze instead of killing one process. "
             "A 4 GiB swap file is a cheap safety net (see Tooling/README.md).")


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
