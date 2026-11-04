"""Launch and track APT orchestrator runs started from the GUI.

The GUI is read-only over the run directory with exactly one exception: it can
start a run. It does that by shelling out to the existing orchestrator
(``python -m apt ...``) -- it does not re-implement any pipeline logic. We track
the child process so the UI can show "running / finished / failed" and surface
the run id the moment it is known.

Safety: ``--unattended`` (which passes ``--dangerously-skip-permissions`` to
Claude Code) is only forwarded when the caller explicitly opts in, mirroring the
CLI. The grading token is passed through the child environment, never on the
command line, exactly as the CLI expects (``APT_GRADING_TOKEN``).
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Reuse the orchestrator's own phase vocabulary for validation if available.
try:  # pragma: no cover
    from apt.phases import ORDER as _ORDER  # type: ignore
    VALID_PHASES = [p.value for p in _ORDER]
except Exception:  # noqa: BLE001
    VALID_PHASES = [
        "recon", "enumeration", "vuln_assessment", "exploitation",
        "post_exploitation", "reporting", "mitigation",
    ]


@dataclass
class Launch:
    launch_id: str
    run_id: Optional[str]
    cmd: list[str]
    cwd: str
    started_at: float
    proc: subprocess.Popen = field(repr=False)
    returncode: Optional[int] = None
    error: Optional[str] = None

    def status(self) -> str:
        if self.proc.poll() is None:
            return "running"
        if self.returncode == 0:
            return "finished"
        return "failed"

    def to_dict(self) -> dict:
        return {
            "launch_id": self.launch_id,
            "run_id": self.run_id,
            "status": self.status(),
            "returncode": self.returncode,
            "started_at": self.started_at,
            "error": self.error,
            "cmd": self.cmd,
        }


class LaunchError(ValueError):
    """Raised when launch parameters are invalid (surface as HTTP 400)."""


class Launcher:
    """Owns the set of GUI-started runs. Thread-safe for the HTTP server."""

    def __init__(self, tooling_dir: Path, runs_root: Path):
        self.tooling_dir = Path(tooling_dir)
        self.runs_root = Path(runs_root)
        self._launches: dict[str, Launch] = {}
        self._lock = threading.Lock()

    # -- building the command ----------------------------------------------

    def _build_cmd(self, params: dict) -> tuple[list[str], str]:
        """Validate GUI params and return (argv, run_id). Raises LaunchError."""
        target = (params.get("target") or "").strip()
        if not target:
            raise LaunchError("A target URL is required.")
        if not (target.startswith("http://") or target.startswith("https://")):
            raise LaunchError("Target must be an http(s) URL.")

        run_id = (params.get("run_id") or "").strip()
        if not run_id:
            run_id = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        if "/" in run_id or "\\" in run_id:
            raise LaunchError("run_id must not contain path separators.")

        mode = params.get("mode") or "black-box"
        if mode not in ("black-box", "white-box"):
            raise LaunchError("mode must be black-box or white-box.")

        phases = params.get("phases") or "recon,enumeration"
        if phases != "all":
            requested = [p.strip() for p in phases.split(",") if p.strip()]
            bad = [p for p in requested if p not in VALID_PHASES]
            if bad:
                raise LaunchError(f"Unknown phase(s): {', '.join(bad)}")
            phases = ",".join(requested)

        # python -m apt, run from the Tooling dir so runs/ lands where the GUI reads.
        cmd = [
            sys.executable, "-m", "apt",
            "--target", target,
            "--phases", phases,
            "--mode", mode,
            "--out", str(self.runs_root),
            "--run-id", run_id,
        ]
        if params.get("model"):
            cmd += ["--model", str(params["model"]).strip()]
        if mode == "white-box":
            source = (params.get("source") or "").strip()
            if not source:
                raise LaunchError("white-box mode needs a source directory.")
            cmd += ["--source", source]
        if params.get("retries") is not None:
            cmd += ["--retries", str(int(params["retries"]))]
        if params.get("unattended"):
            cmd += ["--unattended"]
        return cmd, run_id

    # -- launching ----------------------------------------------------------

    def start(self, params: dict) -> dict:
        cmd, run_id = self._build_cmd(params)
        env = dict(os.environ)
        token = (params.get("grading_token") or "").strip()
        if token:
            env["APT_GRADING_TOKEN"] = token  # passed via env, never argv

        launch_id = f"L-{int(time.time() * 1000)}"
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(self.tooling_dir), env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise LaunchError(f"Could not start orchestrator: {exc}") from exc

        launch = Launch(
            launch_id=launch_id, run_id=run_id, cmd=cmd,
            cwd=str(self.tooling_dir), started_at=time.time(), proc=proc,
        )
        with self._lock:
            self._launches[launch_id] = launch
        threading.Thread(target=self._reap, args=(launch,), daemon=True).start()
        return launch.to_dict()

    def _reap(self, launch: Launch) -> None:
        launch.proc.wait()
        launch.returncode = launch.proc.returncode

    # -- querying -----------------------------------------------------------

    def active(self) -> list[dict]:
        with self._lock:
            return [l.to_dict() for l in self._launches.values()]

    def status_for_run(self, run_id: str) -> Optional[str]:
        """The live launcher status for a given run id, if the GUI started it."""
        with self._lock:
            for l in self._launches.values():
                if l.run_id == run_id:
                    return l.status()
        return None

    def stop(self, launch_id: str) -> bool:
        with self._lock:
            launch = self._launches.get(launch_id)
        if launch is None:
            return False
        if launch.proc.poll() is None:
            launch.proc.terminate()
        return True
