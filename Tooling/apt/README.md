# APT pipeline

Drives Claude Code headless through a penetration-test phase outline, passing a
schema-validated `findings.json` between phases. Each phase runs as a separate
`claude -p` invocation with a clean context, so no single session drowns in tool
output; only the distilled, validated findings cross the boundary.

## Layout

| File | Role |
|---|---|
| `schema.py` | The `findings.json` contract: one pydantic model per phase (the handoff). |
| `phases.py` | The phase outline: objective, guidance, allowed tools, and output model per phase. |
| `runner.py` | The orchestrator: build prompt → run `claude` → log → validate → hand off. |
| `cli.py` | Command-line entrypoint (`python3 -m apt`). |

## Install

```bash
pip install -r ../requirements.txt   # pydantic>=2.6; Claude Code must be on PATH
```

## Use

```bash
# See exactly what each phase would run, without calling Claude:
python3 -m apt --target http://127.0.0.1:3000 --dry-run

# Run recon + enumeration (the default) unattended, INSIDE A SANDBOX:
python3 -m apt --target http://127.0.0.1:3000 --unattended

# Full chain, white-box, specific model:
python3 -m apt --target http://127.0.0.1:3000 --phases all \
    --mode white-box --source ./clean-source --unattended --model claude-opus-4-8
```

Output lands in `runs/<run-id>/`: one directory per phase (with its
`findings.json` and raw tool output), a `logs/<phase>.jsonl` stream log per
phase, and a `run.json` manifest.

## Safety

- `--unattended` passes `--dangerously-skip-permissions` so the agent runs tools
  without approval. **Only run it inside an isolated sandbox (VM/container) whose
  network can reach the target and nothing else.**
- Web tools (`WebFetch`, `WebSearch`) are denied in every phase, so the agent
  cannot look up the target's known solutions online — results reflect its own
  testing, not recall.
- The prompt scopes every phase to the single authorized target and forbids
  destructive or denial-of-service actions.

## Notes

- The exact Claude Code flag names can vary by version. They are centralized in
  `runner.py` (`OUTPUT_FORMAT`, `build_cmd`); check `claude --help` and adjust if
  a flag is rejected. `--dry-run` prints the composed command for inspection.
- Exploitation records a `challenge_key` per attempt where it can; confirm actual
  success out-of-band with `../vuln-list/check_live_app.py`, which reads the
  target's server-side solve state.
