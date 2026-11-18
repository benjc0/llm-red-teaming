"""ffuf -> schema (enumeration content discovery).

ffuf (`-o out.json -of json`) writes a `results[]` list of hits, each with the
fuzzed `url`/`input` and the response `status`. Hits become hidden_paths and
routes.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from apt.schema import Endpoint

# Status codes worth keeping as a "found" hit.
_INTERESTING = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405}


def parse(raw: str | dict) -> dict:
    report = raw if isinstance(raw, dict) else json.loads(raw)
    routes: list[Endpoint] = []
    hidden: list[str] = []
    for r in report.get("results", []) or []:
        status = r.get("status")
        url = r.get("url") or ""
        path = urlsplit(url).path or ("/" + (r.get("input", {}) or {}).get("FUZZ", ""))
        if status in _INTERESTING:
            routes.append(Endpoint(method="GET", path=path, status=status))
            if path not in hidden:
                hidden.append(path)
    return {"routes": routes, "hidden_paths": hidden}
