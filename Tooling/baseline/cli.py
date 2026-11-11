"""Command-line entrypoint for the deterministic baseline pipeline.

Examples:
  # see exactly which tools each phase would run, without executing them:
  python3 -m baseline --target http://127.0.0.1:3000 --phases all --dry-run

  # run recon+enumeration for real (needs Docker; nmap native if present):
  python3 -m baseline --target http://127.0.0.1:3000

  # full chain, white-box (adds Semgrep over the cleaned source), with the oracle:
  python3 -m baseline --target http://127.0.0.1:3000 --phases all \
      --mode white-box --source ./clean-source --grading-token "$APT_GRADING_TOKEN"

Output lands in runs/<id>/ in the SAME layout as an AI run, so
vuln-list/score_run.py and the GUI treat it identically.
"""
from __future__ import annotations

import argparse
import sys

from apt import phases as phase_defs
from apt.schema import Phase

from .runner import BaselineConfig, run_pipeline


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
    return [p for p in phase_defs.ORDER if p in out]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="baseline",
                                description="Deterministic-tooling baseline for the APT pipeline.")
    p.add_argument("--target", required=True, help="Authorized target URL, e.g. http://127.0.0.1:3000")
    p.add_argument("--phases", type=_parse_phases, default=list(phase_defs.DEFAULT_PHASES),
                   help="Comma-separated phases, or 'all'. Default: recon,enumeration.")
    p.add_argument("--mode", choices=["black-box", "white-box"], default="black-box")
    p.add_argument("--source", dest="source_dir", default=None,
                   help="Cleaned source tree for Semgrep in white-box mode.")
    p.add_argument("--out", dest="out_root", default="runs", help="Output root directory.")
    p.add_argument("--run-id", default="", help="Override the generated run id.")
    p.add_argument("--grading-token", default=None,
                   help="Token for the solve oracle (/grading/solves). Defaults to APT_GRADING_TOKEN.")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the tool command for each phase without executing it.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.mode == "white-box" and not args.source_dir:
        print("white-box mode needs --source pointing at a cleaned source tree.", file=sys.stderr)
        return 2

    cfg = BaselineConfig(
        target=args.target, mode=args.mode, source_dir=args.source_dir,
        out_root=args.out_root, run_id=args.run_id, phases=args.phases,
        grading_token=args.grading_token, dry_run=args.dry_run,
    )
    print(f"Baseline run {cfg.run_id} | target {cfg.target} | mode {cfg.mode} | "
          f"phases: {', '.join(p.value for p in cfg.phases)}")
    run_pipeline(cfg)
    print(f"\nDone. Output in {cfg.out_root / cfg.run_id}/")
    print(f"Score it: python3 vuln-list/score_run.py {cfg.out_root / cfg.run_id} --mode {cfg.mode}")
    return 0
