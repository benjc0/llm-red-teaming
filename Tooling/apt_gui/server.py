"""Standard-library HTTP server for the APT GUI.

Zero third-party dependencies: a ThreadingHTTPServer plus a small router. It
serves a JSON API over the run directory (via RunStore) and the run launcher
(via Launcher), and the static single-page frontend from ./static.

Routes
  GET  /                                  -> static index.html
  GET  /static/<file>                     -> static asset
  GET  /api/runs                          -> list of run summaries
  GET  /api/runs/<id>                      -> one run's full detail
  GET  /api/runs/<id>/activity?phase=&after=  -> parsed stream-json activity
  GET  /api/runs/<id>/report               -> reporting/report.md (text)
  GET  /api/runs/<id>/raw?path=<rel>       -> a raw artifact file
  GET  /api/phases                         -> canonical phase order + titles
  GET  /api/launches                       -> GUI-started runs and their status
  POST /api/launches                       -> start a run {target, phases, ...}
  POST /api/launches/<lid>/stop            -> terminate a running launch
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .launcher import Launcher, LaunchError
from .runstore import PHASE_ORDER, PHASE_TITLES, RunStore

STATIC_DIR = Path(__file__).resolve().parent / "static"


class Context:
    """Shared services handed to every request (set on the server instance)."""

    def __init__(self, store: RunStore, launcher: Launcher):
        self.store = store
        self.launcher = launcher


class Handler(BaseHTTPRequestHandler):
    server_version = "APT-GUI/0.1"

    # Quieter logging than the default one-line-per-request to stderr.
    def log_message(self, fmt: str, *args) -> None:  # noqa: A002
        return

    @property
    def ctx(self) -> Context:
        return self.server.ctx  # type: ignore[attr-defined]

    # -- dispatch -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        try:
            if path == "/" or path == "/index.html":
                return self._serve_static("index.html")
            if path.startswith("/static/"):
                return self._serve_static(path[len("/static/"):])
            if path == "/api/phases":
                return self._json(200, {
                    "order": PHASE_ORDER,
                    "titles": PHASE_TITLES,
                })
            if path == "/api/runs":
                return self._json(200, {"runs": self._runs_with_live_status()})
            if path == "/api/launches":
                return self._json(200, {"launches": self.ctx.launcher.active()})
            if path.startswith("/api/runs/"):
                return self._get_run_subresource(path, qs)
            return self._json(404, {"error": "not found"})
        except BrokenPipeError:
            return
        except Exception as exc:  # noqa: BLE001 - never let the server die
            return self._json(500, {"error": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/launches":
                body = self._read_json_body()
                try:
                    result = self.ctx.launcher.start(body)
                except LaunchError as exc:
                    return self._json(400, {"error": str(exc)})
                return self._json(201, result)
            if path.startswith("/api/launches/") and path.endswith("/stop"):
                lid = path[len("/api/launches/"):-len("/stop")]
                ok = self.ctx.launcher.stop(lid)
                return self._json(200 if ok else 404, {"stopped": ok})
            return self._json(404, {"error": "not found"})
        except BrokenPipeError:
            return
        except Exception as exc:  # noqa: BLE001
            return self._json(500, {"error": str(exc)})

    # -- run subresources ---------------------------------------------------

    def _get_run_subresource(self, path: str, qs: dict) -> None:
        rest = path[len("/api/runs/"):]
        parts = rest.split("/", 1)
        run_id = parts[0]
        sub = parts[1] if len(parts) > 1 else ""

        if sub == "":
            detail = self.ctx.store.run_detail(run_id)
            if detail is None:
                return self._json(404, {"error": "run not found"})
            live = self.ctx.launcher.status_for_run(run_id)
            if live == "running":
                detail["status"] = "running"
            return self._json(200, detail)

        if sub == "activity":
            phase = (qs.get("phase") or [""])[0]
            after = _int(qs.get("after"), 0)
            data = self.ctx.store.activity(run_id, phase, after=after)
            return self._json(200, data)

        if sub == "report":
            md = self.ctx.store.report_markdown(run_id)
            if md is None:
                return self._json(404, {"error": "no report"})
            return self._raw(200, md.encode("utf-8"), "text/plain; charset=utf-8")

        if sub == "raw":
            rel = (qs.get("path") or [""])[0]
            got = self.ctx.store.raw_file(run_id, rel)
            if got is None:
                return self._json(404, {"error": "artifact not found"})
            data, ctype = got
            return self._raw(200, data, ctype)

        return self._json(404, {"error": "not found"})

    def _runs_with_live_status(self) -> list[dict]:
        runs = self.ctx.store.list_runs()
        for r in runs:
            live = self.ctx.launcher.status_for_run(r["run_id"])
            if live == "running":
                r["status"] = "running"
            elif live == "failed" and r["status"] == "partial":
                r["status"] = "failed"
        return runs

    # -- io helpers ---------------------------------------------------------

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def _json(self, status: int, obj) -> None:
        self._raw(status, json.dumps(obj).encode("utf-8"),
                  "application/json; charset=utf-8")

    def _raw(self, status: int, data: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _serve_static(self, rel: str) -> None:
        # Confine to STATIC_DIR; reject traversal.
        target = (STATIC_DIR / rel).resolve()
        try:
            target.relative_to(STATIC_DIR)
        except ValueError:
            return self._json(403, {"error": "forbidden"})
        if not target.is_file():
            return self._json(404, {"error": "not found"})
        ctype = _static_type(target.name)
        self._raw(200, target.read_bytes(), ctype)


def _int(values, default: int) -> int:
    try:
        return int((values or [default])[0])
    except (ValueError, TypeError):
        return default


def _static_type(name: str) -> str:
    if name.endswith(".html"):
        return "text/html; charset=utf-8"
    if name.endswith(".js"):
        return "text/javascript; charset=utf-8"
    if name.endswith(".css"):
        return "text/css; charset=utf-8"
    if name.endswith(".svg"):
        return "image/svg+xml"
    return "application/octet-stream"


def make_server(host: str, port: int, tooling_dir: Path,
                runs_root: Path) -> ThreadingHTTPServer:
    store = RunStore(runs_root)
    launcher = Launcher(tooling_dir, runs_root)
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.ctx = Context(store, launcher)  # type: ignore[attr-defined]
    return httpd
