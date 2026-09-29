#!/usr/bin/env bash
#
# APT (Automated Pentesting) — environment preflight
#
# Minimal, non-comprehensive check that the machine is ready to run APT.
# Authentication is delegated entirely to Claude Code; this script only
# verifies that Claude Code is present, runnable, and authenticated by
# firing a single headless call.
#
# Usage:   ./setup.sh

# Note: intentionally NOT using `set -e` — we want to run every check and
# print a full summary rather than abort on the first failure.
set -uo pipefail

# --- pretty output (colours only when writing to a terminal) ---------------
if [ -t 1 ]; then
  GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; RED=$'\033[0;31m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; BOLD=''; RESET=''
fi

HARD_FAILS=0   # missing hard requirements -> non-zero exit
WARNINGS=0     # optional/nice-to-have gaps -> reported, not fatal

pass() { printf '  %s[ PASS ]%s %s\n' "$GREEN" "$RESET" "$1"; }
warn() { printf '  %s[ WARN ]%s %s\n' "$YELLOW" "$RESET" "$1"; WARNINGS=$((WARNINGS + 1)); }
fail() { printf '  %s[ FAIL ]%s %s\n' "$RED" "$RESET" "$1"; HARD_FAILS=$((HARD_FAILS + 1)); }

printf '%s== APT environment preflight ==%s\n\n' "$BOLD" "$RESET"

# --- 1. Is Claude Code on PATH? --------------------------------------------
if command -v claude >/dev/null 2>&1; then
  pass "Claude Code found: $(command -v claude)"
else
  fail "Claude Code ('claude') is not on your PATH."
  printf '         Install it, then re-run this script:\n\n'
  printf '           curl -fsSL https://claude.ai/install.sh | bash\n'
  printf ' 			     or\n'
  printf '           npm install -g @anthropic-ai/claude-code\n\n'
  printf '         (Other install methods: https://docs.claude.com/en/docs/claude-code)\n'
  # No point running the later Claude checks without the binary.
  printf '\n%s== Summary ==%s  %s%d failed%s, %d warnings\n' \
    "$BOLD" "$RESET" "$RED" "$HARD_FAILS" "$RESET" "$WARNINGS"
  exit 1
fi

# --- 2. Is it runnable? -----------------------------------------------------
if CLAUDE_VERSION="$(claude --version 2>/dev/null)"; then
  pass "Claude Code runs: ${CLAUDE_VERSION}"
else
  fail "'claude --version' did not run cleanly — the install may be broken."
fi

# --- 3. The spike: does a headless call work AND is it authenticated? -------
# A single `claude -p` call proves both at once. `timeout` guards against a
# hang; we accept success if the call exits 0 and echoes our sentinel.
printf '  %s...%s testing a headless Claude call (auth + invocation)...\n' "$YELLOW" "$RESET"
SENTINEL="APT_OK"
if HEADLESS_OUT="$(timeout 90 claude -p "Reply with exactly this word and nothing else: ${SENTINEL}" 2>/dev/null)"; then
  if printf '%s' "$HEADLESS_OUT" | grep -q "$SENTINEL"; then
    pass "Headless call succeeded and Claude Code is authenticated."
  else
    # Exit 0 but unexpected content — treat as a soft pass, surface the output.
    warn "Headless call returned, but output was unexpected: $(printf '%s' "$HEADLESS_OUT" | head -c 120)"
  fi
else
  RC=$?
  if [ "$RC" -eq 124 ]; then
    fail "Headless Claude call timed out (90s). Check your network / Claude Code."
  else
    fail "Headless Claude call failed (exit ${RC}). You are likely not authenticated."
    printf '         Authenticate Claude Code yourself, then re-run:\n'
    printf '           claude        # then follow its login prompts\n'
  fi
fi

# --- 4. Optional pentest tooling (warn only, never fatal) -------------------
for tool in curl nmap; do
  if command -v "$tool" >/dev/null 2>&1; then
    pass "Optional tool present: ${tool}"
  else
    warn "Optional tool missing: ${tool} (install later; not required for preflight)"
  fi
done

# --- Summary ----------------------------------------------------------------
printf '\n%s== Summary ==%s  ' "$BOLD" "$RESET"
if [ "$HARD_FAILS" -eq 0 ]; then
  printf '%sall required checks passed%s (%d warnings)\n' "$GREEN" "$RESET" "$WARNINGS"
  printf 'Environment is ready for APT.\n'
  exit 0
else
  printf '%s%d required check(s) failed%s (%d warnings)\n' "$RED" "$HARD_FAILS" "$RESET" "$WARNINGS"
  printf 'Fix the failures above and re-run ./setup.sh\n'
  exit 1
fi
