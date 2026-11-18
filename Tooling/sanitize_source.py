#!/usr/bin/env python3
"""Build the cleaned source tree for white-box APT runs.

White-box mode hands the agent the target's source. Our Juice Shop copy also
contains its own answer key, so giving it over as-is would make a white-box run
meaningless. This script writes a copy with the answer key removed:

  * removes the files that describe or solve the challenges: challenges.yml,
    the code fixes, the challenge translations, the test suite (which solves
    every challenge), SOLUTIONS.md, the threat model, the snippet cache, and the
    AI-assistant folders that tell an agent what the app is;
  * strips the `vuln-code-snippet` comments that mark vulnerable lines, and
    blanks the `hide-line` lines and `hide-start`...`hide-end` blocks (the
    code that detects a solved challenge);
  * renames every challenge key to an opaque id (`ch001`...), so the remaining
    solve checks no longer name the vulnerability they detect.

Removed lines are blanked, not deleted, so every line keeps its number and a
white-box finding's `file:line` points at the same line in the original.

Finally it audits the output and exits 1 if any challenge key, challenge
description or marker comment survived.

Usage:  python3 sanitize_source.py [--src DIR] [--out DIR] [--force]
        defaults: --src ../juice-shop-copy  --out ./clean-source
Then:   python3 -m apt --target ... --mode white-box --source ./clean-source
"""
from __future__ import annotations

import argparse
import html
import re
import shutil
import sys
from pathlib import Path

TOOLING_DIR = Path(__file__).resolve().parent
DEFAULT_SRC = TOOLING_DIR.parent / "juice-shop-copy"
DEFAULT_OUT = TOOLING_DIR / "clean-source"

# Written into the output so --force only ever deletes a tree this script made.
MARKER_FILE = ".clean-source"

CHALLENGES_YML = "data/static/challenges.yml"

# Paths (relative to the source root) that are answer key, not application.
REMOVE = [
    CHALLENGES_YML,
    "data/static/codefixes",     # the correct fix for each coding challenge
    "data/static/i18n",          # challenge names/descriptions in 43 languages
    "test",                      # e2e + API tests that solve every challenge
    "rsn",                       # cached vulnerable-snippet diffs
    "SOLUTIONS.md",              # links to walkthroughs
    "threat-model.json",
    "screenshots",
    "cypress.config.ts",         # config for the removed e2e tests
    "AGENTS.md", ".ai", ".claude", ".codeium", ".continue", ".cursor", ".junie",
]

# Directory names skipped wherever they appear: build output and dependencies.
SKIP_DIRS = {"node_modules", "build", "dist", ".git", ".angular", ".cache"}

_MARKER = r"(?://|#)\s*vuln-code-snippet"
HIDE_START = re.compile(_MARKER + r"\s+hide-start\b")
HIDE_END = re.compile(_MARKER + r"\s+hide-end\b")
HIDE_LINE = re.compile(_MARKER + r"\s+hide-line\b")
MARKER_COMMENT = re.compile(r"[ \t]*" + _MARKER + r"\b.*$")


# --- reading the answer key -------------------------------------------------

def read_challenges(yml_path: Path) -> list[tuple[str, str]]:
    """(key, description) for every challenge, in file order. Uses PyYAML when
    installed, otherwise the one-line `key:` / `description:` fields."""
    text = yml_path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        return [(c["key"], c.get("description", "")) for c in yaml.safe_load(text)]
    except ImportError:
        keys = re.findall(r"^\s*key:\s*['\"]?(\w+)", text, re.M)
        descs = re.findall(r"^\s*description:\s*['\"](.*)['\"]\s*$", text, re.M)
        if len(keys) != len(descs):
            raise SystemExit(f"Could not parse {yml_path} without PyYAML; install it.")
        return list(zip(keys, descs))


def key_renamer(keys: list[str]):
    """Return (rename_fn, mapping): whole-word replacement key -> ch001..."""
    mapping = {k: f"ch{i:03d}" for i, k in enumerate(keys, start=1)}
    # Longest first so no key is matched as part of a longer one.
    pattern = re.compile(r"\b(" + "|".join(sorted(map(re.escape, keys), key=len, reverse=True)) + r")\b")
    return (lambda text: pattern.sub(lambda m: mapping[m.group(1)], text)), mapping


# --- cleaning one file ------------------------------------------------------

def _split_ending(line: str) -> tuple[str, str]:
    stripped = line.rstrip("\r\n")
    return stripped, line[len(stripped):]


def clean_text(text: str, rename) -> tuple[str, list[str]]:
    """Strip markers and hidden code from one file. Returns (text, warnings).
    Line count is preserved: removed lines become empty lines."""
    out: list[str] = []
    warnings: list[str] = []
    hiding = False
    for line in text.splitlines(keepends=True):
        body, ending = _split_ending(line)
        if hiding:
            if HIDE_END.search(body):
                hiding = False
            out.append(ending)
            continue
        if HIDE_START.search(body):
            hiding = not HIDE_END.search(body)  # a one-line block ends here
            out.append(ending)
            continue
        if HIDE_LINE.search(body):
            out.append(ending)
            continue
        cleaned = MARKER_COMMENT.sub("", body)
        if cleaned != body and not cleaned.strip():
            cleaned = ""  # the line was only a marker
        out.append(cleaned + ending)
    if hiding:
        warnings.append("hide-start without hide-end; blanked to end of file")
    return rename("".join(out)), warnings


# --- building the tree ------------------------------------------------------

def _is_removed(rel: Path) -> bool:
    rel_s = rel.as_posix()
    return any(rel_s == r or rel_s.startswith(r + "/") for r in REMOVE)


def build(src: Path, out: Path, rename) -> dict:
    stats = {"text": 0, "binary": 0, "removed": 0, "warnings": []}
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if _is_removed(rel):
            if rel.as_posix() in REMOVE:
                stats["removed"] += 1
            continue
        if path.is_symlink() or not path.is_file():
            continue
        dest = out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            shutil.copy2(path, dest)
            stats["binary"] += 1
            continue
        cleaned, warns = clean_text(text, rename)
        stats["warnings"] += [f"{rel}: {w}" for w in warns]
        dest.write_bytes(cleaned.encode("utf-8"))
        shutil.copystat(path, dest)
        stats["text"] += 1
    (out / MARKER_FILE).write_text("Generated by Tooling/sanitize_source.py\n", encoding="utf-8")
    return stats


# --- auditing the result ----------------------------------------------------

def _plain(description: str) -> str:
    """A challenge description reduced to a searchable plain-text fragment."""
    text = html.unescape(re.sub(r"<[^>]+>", "", description))
    return re.sub(r"\s+", " ", text).strip()[:60]


def audit(out: Path, challenges: list[tuple[str, str]]) -> dict:
    """Search the output for anything that still gives the answers away."""
    keys = re.compile(r"\b(" + "|".join(re.escape(k) for k, _ in challenges) + r")\b")
    fragments = [f for f in (_plain(d) for _, d in challenges) if len(f) >= 25]
    found = {"keys": [], "descriptions": [], "markers": []}
    solve_hooks = 0
    for path in out.rglob("*"):
        if not path.is_file() or path.name == MARKER_FILE:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(out).as_posix()
        if keys.search(text):
            found["keys"].append(rel)
        flat = re.sub(r"\s+", " ", text)
        if any(f in flat for f in fragments):
            found["descriptions"].append(rel)
        if re.search(_MARKER, text):
            found["markers"].append(rel)
        solve_hooks += len(re.findall(r"challengeUtils\.(?:solveIf|solve|notSolved)\(", text))
    found["solve_hooks"] = solve_hooks
    return found


# --- cli ----------------------------------------------------------------------

def _prepare_out(src: Path, out: Path, force: bool) -> None:
    if out == src or src in out.parents or out in src.parents:
        raise SystemExit(f"--out {out} must not be, contain, or sit inside --src {src}.")
    if out.exists():
        if not (out / MARKER_FILE).exists():
            raise SystemExit(f"{out} exists and was not made by this script; refusing to touch it.")
        if not force:
            raise SystemExit(f"{out} already exists. Re-run with --force to rebuild it.")
        shutil.rmtree(out)
    out.mkdir(parents=True)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build the cleaned source tree for white-box APT runs.")
    p.add_argument("--src", type=Path, default=DEFAULT_SRC, help=f"source tree (default {DEFAULT_SRC})")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT, help=f"output tree (default {DEFAULT_OUT})")
    p.add_argument("--force", action="store_true", help="rebuild an existing output tree")
    args = p.parse_args(argv)

    src, out = args.src.resolve(), args.out.resolve()
    yml = src / CHALLENGES_YML
    if not yml.is_file():
        raise SystemExit(f"{yml} not found; --src must be the Juice Shop source tree.")
    challenges = read_challenges(yml)
    rename, _ = key_renamer([k for k, _ in challenges])

    _prepare_out(src, out, args.force)
    stats = build(src, out, rename)
    found = audit(out, challenges)

    print(f"Clean source written to {out}")
    print(f"  {stats['text']} text files cleaned, {stats['binary']} binary files copied, "
          f"{stats['removed']} answer-key paths removed, {len(challenges)} challenge keys renamed")
    for w in stats["warnings"]:
        print(f"  warning: {w}")
    print(f"  residual: {found['solve_hooks']} solve-check call sites remain (now anonymous: "
          "they no longer name the vulnerability, but each still marks graded code)")

    leaks = {k: v for k, v in found.items() if k != "solve_hooks" and v}
    if leaks:
        print("\nAUDIT FAILED -- answer-key content survived:")
        for kind, files in leaks.items():
            print(f"  {kind}: {', '.join(sorted(files)[:10])}{' ...' if len(files) > 10 else ''}")
        return 1
    print("Audit passed: no challenge keys, descriptions, or marker comments remain.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
