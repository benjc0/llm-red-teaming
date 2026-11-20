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

    # --- 6. Free-tools baseline engine readiness (warn only) ----------------
    # The AI engine needs none of this; skip the whole section if there's no
    # intent to run the deterministic baseline.
    check_docker()
    check_baseline_tools()

    # --- 7. Memory headroom (warn only) -------------------------------------
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


def check_docker() -> None:
    """The free-tools baseline runs most scanners (katana, ZAP, nuclei, sqlmap)
    as Docker containers. The AI engine needs no Docker, so this only warns."""
    docker = shutil.which("docker")
    if docker is None:
        warn("Docker not found: the free-tools baseline can't run its "
             "containerized tools (katana, ZAP, nuclei, sqlmap). Not needed for "
             "the AI engine.")
        return
    # 'docker ps' is a fast check that the daemon is up AND this user may reach
    # it -- the two failure modes that silently broke baseline runs.
    try:
        res = _run([docker, "ps"], timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        warn(f"Docker is installed but 'docker ps' could not run: {exc}")
        return
    if res.returncode == 0:
        ok("Docker is installed and reachable (free-tools baseline can run).")
        return
    err = (res.stderr or "").lower()
    if "permission denied" in err:
        warn("Docker is installed but this user can't reach the daemon "
             "(permission denied). Add yourself to the 'docker' group:")
        print("           sudo usermod -aG docker \"$USER\"   # then log out and back in")
    elif "cannot connect" in err or "daemon running" in err:
        warn("Docker is installed but the daemon isn't running. Start it, e.g.:")
        print("           sudo systemctl start docker")
    else:
        last = (res.stderr or "").strip().splitlines()
        warn("Docker is installed but not usable: "
             f"{last[-1][:160] if last else 'unknown error'}")


def check_baseline_tools() -> None:
    """Baseline tools that run natively (the rest come from Docker images):
    nmap is checked above; whatweb, nikto and ffuf must be on PATH or the
    baseline skips them. arjun/retire also degrade to a logged skip."""
    for tool in ("whatweb", "nikto", "ffuf"):
        if shutil.which(tool):
            ok(f"Baseline tool present: {tool}")
        else:
            warn(f"Baseline tool missing: {tool} (runs natively; the baseline "
                 f"skips it if absent). On Kali/Debian: sudo apt install {tool}")
    # ffuf needs a wordlist; a missing one fails ffuf with exit 1.
    wordlist = os.environ.get("APT_FFUF_WORDLIST", "/usr/share/wordlists/dirb/common.txt")
    if os.path.isfile(wordlist):
        ok(f"ffuf wordlist present: {wordlist}")
    else:
        warn(f"ffuf wordlist not found at {wordlist}. Install a wordlist (e.g. "
             "'sudo apt install wordlists' or SecLists) or set APT_FFUF_WORDLIST.")


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
