"""WhatWeb -> schema (recon tech stack).

WhatWeb (`--log-json`) emits one JSON object per target with a `plugins` map
(Apache, Express, AngularJS, JQuery, ...). We turn the plugin names into the
recon payload's tech_stack.
"""
from __future__ import annotations

import json


def parse(raw: str | list | dict) -> dict:
    if isinstance(raw, (list, dict)):
        records = raw if isinstance(raw, list) else [raw]
    else:
        records = []
        for line in (raw or "").splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
    tech: set[str] = set()
    for rec in records:
        for name, detail in (rec.get("plugins") or {}).items():
            version = ""
            if isinstance(detail, dict):
                v = detail.get("version")
                if isinstance(v, list) and v:
                    version = str(v[0])
                elif v:
                    version = str(v)
            tech.add(f"{name} {version}".strip())
    return {"tech_stack": sorted(tech)}
