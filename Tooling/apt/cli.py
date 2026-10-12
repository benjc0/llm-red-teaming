"""Command-line entrypoint for the APT pipeline.

Examples:
  # recon + enumeration (the default) against a local target, dry-run first:
  python3 -m apt --target http://127.0.0.1:3000 --dry-run

  # run them for real, unattended, inside your sandbox VM:
  python3 -m apt --target http://127.0.0.1:3000 --unattended

  # the full chain, white-box, with a chosen model:
  python3 -m apt --target http://127.0.0.1:3000 --phases all \\
      --mode white-box --source ./clean-source --unattended --model claude-opus-4-8
"""
from __future__ import annotations

import argparse
import sys

from . import phases as phase_defs
from .runner import RunConfig, run_pipeline
from .schema import Phase


def _parse_phases(value: str) -> list[Phase]:
    if value.strip().lower() == "all":
        return list(phase_defs.ORDER)
    out: list[Phase] = []
    for name in value.split(","):
        name = name.strip()
        if not name:
            continue
        try:
            out.append(Phase(name))
        except ValueError:
            valid = ", ".join(p.value for p in phase_defs.ORDER)
            raise SystemExit(f"Unknown phase '{name}'. Valid: {valid}, or 'all'.")
    # Keep canonical order so handoffs are consistent regardless of input order.
    return [p for p in phase_defs.ORDER if p in out]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="apt", description="APT autonomous pentest pipeline.")
    p.add_argument("--target", required=True, help="Authorized target URL, e.g. http://127.0.0.1:3000")
    p.add_argument("--phases", type=_parse_phases, default=list(phase_defs.DEFAULT_PHASES),
                   help="Comma-separated phases, or 'all'. Default: recon,enumeration.")
    p.add_argument("--mode", choices=["black-box", "white-box"], default="black-box")
    p.add_argument("--source", dest="source_dir", default=None,
                   help="Cleaned source tree to expose in white-box mode.")
    p.add_argument("--out", dest="out_root", default="runs", help="Output root directory.")
    p.add_argument("--model", default=None, help="Model id for Claude Code (default: its default).")
    p.add_argument("--run-id", default="", help="Override the generated run id.")
    p.add_argument("--retries", type=int, default=1, help="Validation retries per phase.")
    p.add_argument("--unattended", action="store_true",
                   help="Run tools without approval prompts (--dangerously-skip-permissions). SANDBOX ONLY.")
    p.add_argument("--dry-run", action="store_true",
                   help="Print what each phase would run, without invoking Claude Code.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.mode == "white-box" and not args.source_dir:
        print("white-box mode needs --source pointing at a cleaned source tree.", file=sys.stderr)
        return 2
    if args.unattended and not args.dry_run:
        print("Running UNATTENDED: the agent will execute tools without approval. "
              "Make sure you are inside an isolated sandbox whose network reaches only the target.",
              file=sys.stderr)

    cfg = RunConfig(
        target=args.target,
        mode=args.mode,
        source_dir=args.source_dir,
        out_root=args.out_root,
        model=args.model,
        run_id=args.run_id,
        phases=args.phases,
        retries=args.retries,
        unattended=args.unattended,
        dry_run=args.dry_run,
    )

    print(f"APT run {cfg.run_id} | target {cfg.target} | mode {cfg.mode} | "
          f"phases: {', '.join(p.value for p in cfg.phases)}")
    results = run_pipeline(cfg)

    failed = [r for r in results if not r.ok and not cfg.dry_run]
    if failed:
        print(f"\nDone with {len(failed)} failed phase(s). See {cfg.out_root / cfg.run_id}/run.json")
        return 1
    print(f"\nDone. Output in {cfg.out_root / cfg.run_id}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
