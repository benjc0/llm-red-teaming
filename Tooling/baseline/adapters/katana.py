"""Katana -> schema (enumeration crawl).

Katana (`-jsonl`) crawls the app, including JavaScript, and emits one JSON
object per URL discovered (`{"request": {"endpoint": "...", "method": "..."}}`
or a flat `{"url": ...}` in older output). We fold these into enumeration
routes and the API surface.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from apt.schema import Endpoint


def _records(raw):
    if isinstance(raw, list):
        return raw
    out = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def parse(raw: str | list) -> dict:
    routes: list[Endpoint] = []
    api: set[str] = set()
    seen: set[tuple[str, str]] = set()
    for rec in _records(raw):
        req = rec.get("request", rec)
        url = req.get("endpoint") or req.get("url") or rec.get("url")
        if not url:
            continue
        method = (req.get("method") or "GET").upper()
        path = urlsplit(url).path or "/"
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        routes.append(Endpoint(method=method, path=path))
        if "/api/" in path or "/rest/" in path:
            api.add(path)
    return {"routes": routes, "api_surface": sorted(api)}
