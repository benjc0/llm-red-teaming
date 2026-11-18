"""Dynamic phase prompts.

By default the agent runs with the built-in objective/guidance baked into
`phases.py`. A run may instead supply its own prompts: pass a prompt file
(`--prompts FILE`, or the GUI field) and, for any phase it lists, its
`objective` and/or `guidance` replace the defaults. Phases the file omits keep
the defaults, so a file can override one phase or all seven.

`dump_template()` writes the current defaults as a starting point to edit.

File format (YAML if PyYAML is installed, else JSON), keyed by phase name:

    recon:
      objective: "Map the attack surface ..."
      guidance:
        - "Use only light, non-destructive probes."
    exploitation:
      guidance:
        - "..."            # objective omitted -> keep the default objective
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from . import phases as phase_defs
from .schema import Phase

PHASE_NAMES = [p.value for p in Phase]


class PromptError(ValueError):
    """A prompt override file is missing, malformed, or names unknown phases."""


def default_prompts() -> dict[str, dict]:
    """The built-in objective/guidance for every phase, as plain dicts."""
    return {
        spec.phase.value: {"objective": spec.objective, "guidance": list(spec.guidance)}
        for spec in phase_defs.PHASES.values()
    }


def _parse(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yml", ".yaml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise PromptError(
                f"{path} is YAML but PyYAML isn't installed; use a .json file or `pip install pyyaml`."
            ) from exc
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise PromptError(f"{path}: top level must be a mapping of phase -> {{objective, guidance}}.")
    return data


def load_overrides(path: str | Path) -> dict[str, dict]:
    """Read and validate a prompt override file into {phase: {objective?, guidance?}}."""
    p = Path(path)
    if not p.is_file():
        raise PromptError(f"Prompt file not found: {p}")
    data = _parse(p)

    overrides: dict[str, dict] = {}
    for phase, body in data.items():
        if phase not in PHASE_NAMES:
            raise PromptError(
                f"{p}: unknown phase '{phase}'. Valid phases: {', '.join(PHASE_NAMES)}.")
        if not isinstance(body, dict):
            raise PromptError(f"{p}: phase '{phase}' must map to objective/guidance, got {type(body).__name__}.")
        entry: dict = {}
        if "objective" in body:
            obj = body["objective"]
            if not isinstance(obj, str) or not obj.strip():
                raise PromptError(f"{p}: '{phase}.objective' must be a non-empty string.")
            entry["objective"] = obj.strip()
        if "guidance" in body:
            g = body["guidance"]
            if not isinstance(g, list) or not all(isinstance(x, str) for x in g):
                raise PromptError(f"{p}: '{phase}.guidance' must be a list of strings.")
            cleaned = [x.strip() for x in g if x.strip()]
            if not cleaned:
                raise PromptError(f"{p}: '{phase}.guidance' is empty.")
            entry["guidance"] = cleaned
        unknown = set(body) - {"objective", "guidance"}
        if unknown:
            raise PromptError(f"{p}: '{phase}' has unsupported field(s): {', '.join(sorted(unknown))}.")
        if not entry:
            raise PromptError(f"{p}: '{phase}' sets neither objective nor guidance.")
        overrides[phase] = entry
    return overrides


def effective(spec: phase_defs.PhaseSpec,
              overrides: Optional[dict[str, dict]]) -> tuple[str, list[str]]:
    """The (objective, guidance) to use for a phase: its override, else defaults."""
    entry = (overrides or {}).get(spec.phase.value, {})
    objective = entry.get("objective", spec.objective)
    guidance = entry.get("guidance", spec.guidance)
    return objective, list(guidance)


def dump_template(path: str | Path) -> Path:
    """Write the current defaults to `path` as an editable prompt file."""
    p = Path(path)
    defaults = default_prompts()
    header = (
        "# APT phase prompts. Edit any phase's objective/guidance and pass this\n"
        "# file with `--prompts %s` (or the GUI 'Custom prompts' field).\n"
        "# Delete phases you don't want to change; omitted phases use the defaults.\n"
    ) % p.name
    if p.suffix.lower() in (".yml", ".yaml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise PromptError("PyYAML isn't installed; dump to a .json file instead.") from exc
        body = yaml.safe_dump(defaults, sort_keys=False, default_flow_style=False, width=100)
        p.write_text(header + body, encoding="utf-8")
    else:
        p.write_text(json.dumps(defaults, indent=2) + "\n", encoding="utf-8")
    return p
