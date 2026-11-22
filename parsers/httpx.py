"""parsers.httpx — ProjectDiscovery httpx JSON / JSONL -> ParseResult.

httpx is the standard "is this host HTTP?" probe in AppSec recon chains.
Its `-json` / `-jsonl` output is one JSON object per URL probed; we care
about `.url`, `.host`, `.status_code`, `.title`, `.tech`, `.webserver`.

Each probed URL becomes a `new_urls` entry, which the autopilot v2 loop
treats as an app_target for `modules.dispatch_apps`.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

from .base import ParseResult


def parse(stdout, stderr="", exit_code=0):
    r = ParseResult(source_tool="httpx")
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        url = e.get("url") or e.get("input") or ""
        if not url:
            continue
        host = ""
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            host = ""
        host = host or e.get("host", "") or ""
        if host and host not in r.new_hosts:
            r.new_hosts.append(host)
        tech = e.get("tech") or e.get("technologies") or []
        if isinstance(tech, str):
            tech = [tech]
        r.new_urls.append({
            "url": url,
            "status": e.get("status_code") or e.get("status"),
            "tech": ", ".join(tech) if tech else "",
            "title": (e.get("title") or "").strip(),
            "webserver": e.get("webserver") or "",
            "content_type": e.get("content_type") or "",
        })
    return r
