"""Entry point for the APT GUI: ``python3 -m apt_gui``.

Starts the local web server, prints the URL, and (unless told not to) opens a
browser tab. The server only reads the run directory and launches the existing
orchestrator; see server.py for the routes.
"""
from __future__ import annotations

import argparse
import threading
import webbrowser
from pathlib import Path

from .server import make_server


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apt_gui", description="Local web GUI for the APT pentest pipeline.")
    p.add_argument("--host", default="127.0.0.1",
                   help="Bind address (default 127.0.0.1 -- local only).")
    p.add_argument("--port", type=int, default=8787, help="Port (default 8787).")
    p.add_argument("--runs", default=None,
                   help="Run directory to read (default: <tooling>/runs).")
    p.add_argument("--no-browser", action="store_true",
                   help="Do not open a browser tab automatically.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # Tooling dir is the parent of this package; runs/ lives under it by default.
    tooling_dir = Path(__file__).resolve().parent.parent
    runs_root = Path(args.runs).resolve() if args.runs else (tooling_dir / "runs")
    runs_root.mkdir(parents=True, exist_ok=True)

    httpd = make_server(args.host, args.port, tooling_dir, runs_root)
    url = f"http://{args.host}:{args.port}/"
    print(f"APT GUI serving {runs_root}")
    print(f"  -> {url}")
    print("  (Ctrl-C to stop)")

    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
