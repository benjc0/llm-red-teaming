"""Arjun -> schema (enumeration: hidden HTTP parameters).

Arjun brute-forces parameter names against each URL and reports the ones the
server reacts to. Its JSON report (`-oJ`) maps each tested URL to the method and
the parameters it found:

    {"http://t/rest/products/search": {"method": "GET", "params": ["q"], "headers": {...}}}

Each found parameter becomes a schema Param; the URL's path also lands in
api_surface so later phases (sqlmap, ZAP active scan) can target it.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from apt.schema import Param

_METHOD_TO_LOCATION = {"GET": "query", "POST": "body", "JSON": "body", "XML": "body"}


def parse(raw: str | dict) -> dict:
    """Return {"params": [Param, ...], "api_surface": [path, ...]}."""
    if not raw:
        return {"params": [], "api_surface": []}
    report = raw if isinstance(raw, dict) else json.loads(raw)
    params: list[Param] = []
    surface: list[str] = []
    for url, info in (report or {}).items():
        if not isinstance(info, dict):
            continue
        path = urlsplit(url).path or "/"
        method = str(info.get("method") or "GET").upper()
        found = info.get("params") or []
        if found:
            surface.append(path)
        for name in found:
            params.append(Param(endpoint=f"{method if method in ('GET', 'POST') else 'POST'} {path}",
                                name=str(name),
                                location=_METHOD_TO_LOCATION.get(method, "query")))
    return {"params": params, "api_surface": surface}
