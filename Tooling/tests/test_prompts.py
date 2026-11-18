"""Dynamic phase prompts: load/validate an override file, apply it over the
defaults, and round-trip a dumped template.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apt import phases as phase_defs  # noqa: E402
from apt import prompts  # noqa: E402
from apt.schema import Phase  # noqa: E402


def test_defaults_cover_every_phase():
    d = prompts.default_prompts()
    assert set(d) == {p.value for p in Phase}
    assert d["recon"]["objective"]
    assert isinstance(d["recon"]["guidance"], list)


def test_effective_returns_default_when_no_override():
    spec = phase_defs.PHASES[Phase.recon]
    obj, guide = prompts.effective(spec, None)
    assert obj == spec.objective
    assert guide == list(spec.guidance)


def test_override_replaces_only_listed_fields_and_phases(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps({
        "recon": {"objective": "CUSTOM recon", "guidance": ["only this"]},
        "exploitation": {"guidance": ["smallest safe payload"]},  # objective omitted
    }))
    ov = prompts.load_overrides(f)

    obj, guide = prompts.effective(phase_defs.PHASES[Phase.recon], ov)
    assert obj == "CUSTOM recon" and guide == ["only this"]

    # exploitation keeps its default objective, overrides guidance
    obj, guide = prompts.effective(phase_defs.PHASES[Phase.exploitation], ov)
    assert obj == phase_defs.PHASES[Phase.exploitation].objective
    assert guide == ["smallest safe payload"]

    # enumeration untouched
    obj, guide = prompts.effective(phase_defs.PHASES[Phase.enumeration], ov)
    assert obj == phase_defs.PHASES[Phase.enumeration].objective


@pytest.mark.parametrize("body, msg", [
    ({"notaphase": {"objective": "x"}}, "unknown phase"),
    ({"recon": "a string"}, "must map to"),
    ({"recon": {"objective": ""}}, "non-empty string"),
    ({"recon": {"guidance": "not a list"}}, "list of strings"),
    ({"recon": {"guidance": [1, 2]}}, "list of strings"),
    ({"recon": {"nonsense": "x"}}, "unsupported field"),
    ({"recon": {}}, "neither objective nor guidance"),
])
def test_invalid_files_raise_clear_errors(tmp_path, body, msg):
    f = tmp_path / "p.json"
    f.write_text(json.dumps(body))
    with pytest.raises(prompts.PromptError) as exc:
        prompts.load_overrides(f)
    assert msg in str(exc.value)


def test_missing_file_raises():
    with pytest.raises(prompts.PromptError):
        prompts.load_overrides("/no/such/file.json")


def test_empty_file_is_no_overrides(tmp_path):
    f = tmp_path / "p.json"
    f.write_text("{}")
    assert prompts.load_overrides(f) == {}


def test_dump_template_round_trips(tmp_path):
    f = tmp_path / "out.json"
    prompts.dump_template(f)
    loaded = prompts.load_overrides(f)        # a full dump must be valid input
    assert loaded == prompts.default_prompts()
