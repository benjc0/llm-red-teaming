"""The deterministic-tool registry: one ToolSpec per tool, grouped by phase.

This is the baseline counterpart to apt/phases.py. Where the AI gets a PhaseSpec
(objective + allowed tools), the baseline gets, per phase, a list of ToolSpecs:
how to invoke the tool, where it writes output, and which adapter normalizes
that output into the phase's schema payload.

Tools run as pinned Docker images with `--network host` so the only prerequisite
is Docker (nmap is run natively if present). `argv()` returns the exact command;
nothing is passed through a shell, so the target URL is never interpolated into
a shell string.
"""
from __future__ import annotations

import itertools
import os
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

from apt.schema import Phase

from .adapters import (arjun, ffuf, katana, nikto, nmap, nuclei, retirejs, semgrep, sqlmap,
                       whatweb, zap, zap_active)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    phase: Phase
    # Builds the argv list. Gets a ToolContext; returns the command to run.
    argv: Callable[["ToolContext"], list[str]]
    # The file (relative to the phase's raw dir) the tool writes and we parse.
    output_file: str
    # adapter(raw_text) -> {payload_field: value}. sqlmap also takes target_url.
    adapter: Callable
    timeout_s: int = 600
    white_box_only: bool = False
    # Whether the tool reads stdout (we capture it) vs. writes output_file itself.
    reads_stdout: bool = False
    native: bool = False  # run directly (not via docker) if on PATH


@dataclass
class ToolContext:
    target: str
    workdir: str          # the phase raw dir, mounted at /work in the container
    output_file: str
    source_dir: str | None = None   # white-box source, mounted at /src
    routes: list[str] = field(default_factory=list)  # from enumeration, for scanners

    @property
    def host(self) -> str:
        return urlsplit(self.target).hostname or "127.0.0.1"

    @property
    def port(self) -> int:
        u = urlsplit(self.target)
        return u.port or (443 if u.scheme == "https" else 80)


# Hard memory cap per tool container. If a tool exceeds it, Docker's cgroup kills
# just that container (the runner logs the tool as failed and moves on) instead
# of the whole VM thrashing. Swap is pinned to the same value so a capped tool
# can't spill into swap either. Override every cap at once with
# APT_TOOL_MEMORY=<size> (e.g. 2g) on a bigger machine.
DEFAULT_MEMORY = "768m"
TOOL_MEMORY = {
    "zap": "1536m",         # Java; the heap is sized from this cap (JAVA_TOOL_OPTIONS below)
    "zap_active": "1536m",
    "nuclei": "1g",         # template engine; concurrency also lowered in its argv
    "semgrep": "1536m",
}


_SEQ = itertools.count(1)


def _mem(tool: str) -> str:
    return os.environ.get("APT_TOOL_MEMORY") or TOOL_MEMORY.get(tool, DEFAULT_MEMORY)


def _docker(tool: str) -> list[str]:
    m = _mem(tool)
    # A unique name lets the runner `docker kill` the container on timeout:
    # killing the docker CLI alone leaves the container running.
    name = f"apt-{tool.replace('_', '-')}-{os.getpid()}-{next(_SEQ)}"
    return ["docker", "run", "--rm", "--name", name, "--network", "host",
            "--memory", m, "--memory-swap", m, "-v"]


# The JVM sizes its heap from the container cap. 60% leaves room for ZAP's
# off-heap memory while still giving it ~900 MB of heap at the 1536m cap.
_ZAP_JAVA = ["-e", "JAVA_TOOL_OPTIONS=-XX:MaxRAMPercentage=60"]


def _mount(ctx: ToolContext) -> str:
    return f"{ctx.workdir}:/work"


# --- recon -----------------------------------------------------------------

def _nmap_argv(ctx: ToolContext) -> list[str]:
    # Light, versioned service scan on the target port only. Native if present.
    return ["nmap", "-sV", "-Pn", "-p", str(ctx.port), "-oX", f"{ctx.workdir}/{ctx.output_file}", ctx.host]


def _whatweb_argv(ctx: ToolContext) -> list[str]:
    return [*_docker("whatweb"), _mount(ctx), "guardicore/whatweb",
            "--log-json=/work/" + ctx.output_file, ctx.target]


# --- enumeration -----------------------------------------------------------

def _katana_argv(ctx: ToolContext) -> list[str]:
    return [*_docker("katana"), _mount(ctx), "projectdiscovery/katana",
            "-u", ctx.target, "-jc", "-jsonl", "-o", "/work/" + ctx.output_file]


def _ffuf_argv(ctx: ToolContext) -> list[str]:
    # SecLists common wordlist ships in the ffuf image under /wordlists.
    return [*_docker("ffuf"), _mount(ctx), "secsi/ffuf",
            "-u", ctx.target.rstrip("/") + "/FUZZ",
            "-w", "/wordlists/common.txt", "-mc", "200,201,204,301,302,307,401,403",
            "-of", "json", "-o", "/work/" + ctx.output_file]


# Written by the runner after Katana runs: same-origin URLs worth probing for
# hidden parameters. Arjun falls back to the target root if it's absent.
ARJUN_TARGETS = "arjun-targets.txt"


def _arjun_argv(ctx: ToolContext) -> list[str]:
    # Arjun is a pip package (pip install arjun); run natively.
    targets = os.path.join(ctx.workdir, ARJUN_TARGETS)
    src = ["-i", targets] if os.path.isfile(targets) else ["-u", ctx.target]
    return ["arjun", *src, "-t", "4", "--stable", "-oJ", f"{ctx.workdir}/{ctx.output_file}"]


# --- vulnerability assessment ----------------------------------------------

def _zap_argv(ctx: ToolContext) -> list[str]:
    # Baseline passive+spider scan. zap-baseline.py writes its report into the
    # container's work dir (/zap/wrk), so we mount the phase raw dir there (not
    # /work) and read back output_file. -I = don't fail the process on warnings.
    return [*_docker("zap"), f"{ctx.workdir}:/zap/wrk/:rw", *_ZAP_JAVA, "zaproxy/zap-stable",
            "zap-baseline.py", "-t", ctx.target, "-J", ctx.output_file, "-I"]


def _nuclei_argv(ctx: ToolContext) -> list[str]:
    return [*_docker("nuclei"), _mount(ctx), "projectdiscovery/nuclei",
            "-u", ctx.target, "-jsonl", "-o", "/work/" + ctx.output_file,
            # Lower than nuclei's defaults (25/25/150): less memory and less load
            # on the target, at the cost of a slower scan.
            "-c", "10", "-bs", "10", "-rl", "50"]


def _nikto_argv(ctx: ToolContext) -> list[str]:
    return [*_docker("nikto"), _mount(ctx), "sullo/nikto",
            "-h", ctx.target, "-Format", "json", "-output", "/work/" + ctx.output_file]


def _semgrep_argv(ctx: ToolContext) -> list[str]:
    return [*_docker("semgrep"), f"{ctx.source_dir}:/src", "returntocorp/semgrep", "semgrep",
            "--config", "p/owasp-top-ten", "--config", "p/javascript",
            "--json", "--output", "/work/" + ctx.output_file, "/src"]


# The runner downloads the target's same-origin JS bundles here before Retire.js
# runs. Retire.js scans files, not URLs.
JS_DIRNAME = "js"


def _retirejs_argv(ctx: ToolContext) -> list[str]:
    # Retire.js is an npm package (npm install -g retire); run natively.
    return ["retire", "--path", os.path.join(ctx.workdir, JS_DIRNAME),
            "--outputformat", "json", "--outputpath", f"{ctx.workdir}/{ctx.output_file}",
            "--exitwith", "0"]


# --- exploitation ----------------------------------------------------------

def _sqlmap_argv(ctx: ToolContext) -> list[str]:
    # Target the login endpoint by default; the runner can point it at any route
    # enumeration surfaced. --batch = non-interactive, safe defaults.
    url = ctx.routes[0] if ctx.routes else ctx.target.rstrip("/") + "/rest/user/login"
    return [*_docker("sqlmap"), _mount(ctx), "googlesky/sqlmap", "sqlmap",
            "-u", url, "--batch", "--level", "2", "--risk", "1",
            "--flush-session", "-o", "/work/" + ctx.output_file]


def _zap_active_argv(ctx: ToolContext) -> list[str]:
    # Full scan = spider + ACTIVE scan (fires attack payloads). -m caps spider
    # minutes; -I keeps warnings from failing the process. Same JSON as baseline.
    return [*_docker("zap_active"), f"{ctx.workdir}:/zap/wrk/:rw", *_ZAP_JAVA, "zaproxy/zap-stable",
            "zap-full-scan.py", "-t", ctx.target, "-m", "3", "-J", ctx.output_file, "-I"]


REGISTRY: dict[Phase, list[ToolSpec]] = {
    Phase.recon: [
        ToolSpec("nmap", Phase.recon, _nmap_argv, "nmap.xml", nmap.parse, 300, native=True),
        ToolSpec("whatweb", Phase.recon, _whatweb_argv, "whatweb.json", whatweb.parse, 180),
    ],
    Phase.enumeration: [
        ToolSpec("katana", Phase.enumeration, _katana_argv, "katana.jsonl", katana.parse, 300),
        ToolSpec("ffuf", Phase.enumeration, _ffuf_argv, "ffuf.json", ffuf.parse, 300),
        ToolSpec("arjun", Phase.enumeration, _arjun_argv, "arjun.json", arjun.parse, 600,
                 native=True),
    ],
    Phase.vuln_assessment: [
        ToolSpec("zap", Phase.vuln_assessment, _zap_argv, "zap.json", zap.parse, 900),
        ToolSpec("nuclei", Phase.vuln_assessment, _nuclei_argv, "nuclei.jsonl", nuclei.parse, 600),
        ToolSpec("nikto", Phase.vuln_assessment, _nikto_argv, "nikto.json", nikto.parse, 600),
        ToolSpec("retirejs", Phase.vuln_assessment, _retirejs_argv, "retire.json",
                 retirejs.parse, 300, native=True),
        ToolSpec("semgrep", Phase.vuln_assessment, _semgrep_argv, "semgrep.json",
                 semgrep.parse, 600, white_box_only=True),
    ],
    Phase.exploitation: [
        ToolSpec("sqlmap", Phase.exploitation, _sqlmap_argv, "sqlmap.txt",
                 sqlmap.parse, 900, reads_stdout=True),
        ToolSpec("zap_active", Phase.exploitation, _zap_active_argv, "zap-active.json",
                 zap_active.parse, 2400),
    ],
    # post_exploitation / reporting / mitigation are assembled by the runner from
    # earlier phases' output (see runner.py); they have no scanner of their own.
}


def tools_for(phase: Phase, mode: str) -> list[ToolSpec]:
    specs = REGISTRY.get(phase, [])
    if mode != "white-box":
        specs = [s for s in specs if not s.white_box_only]
    return specs
