"""parsers.feroxbuster — content-discovery output -> ParseResult.

feroxbuster, gobuster, dirsearch and ffuf share a rough shape when scanned
in human mode: one line per discovered URL with a status code. We parse
both the plain-text form (feroxbuster default) and the JSON form (ffuf
-of json and feroxbuster -o json).

Each discovered URL becomes a `new_urls` entry; autopilot v2 may re-probe
it with the web_app module's methodology.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from .base import ParseResult


# feroxbuster default: "200       GET      123l   456w   7890c https://host/path"
# gobuster  default:   "/admin                (Status: 200) [Size: 1234]"
# dirsearch default:   "[12:34:56] 200 -    123B  - /admin"
_FEROX_RE = re.compile(
    r"^(?P<status>\d{3})\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<url>https?://\S+)",
    re.M)
_GOBUSTER_RE = re.compile(
    r"^(?P<path>/\S+)\s+\(Status:\s*(?P<status>\d{3})\)", re.M)
_DIRSEARCH_RE = re.compile(
    r"^\[[^\]]+\]\s+(?P<status>\d{3})\s+-\s+\S+\s+-\s+(?P<path>/\S+)",
    re.M)


def _add_url(r, url, status):
    if not url or url in {u["url"] for u in r.new_urls}:
        return
    host = ""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    r.new_urls.append({"url": url, "status": int(status) if status else None,
                       "tech": "", "title": "", "webserver": "",
                       "content_type": ""})
    if host and host not in r.new_hosts:
        r.new_hosts.append(host)


def parse(stdout, stderr="", exit_code=0):
    r = ParseResult(source_tool="feroxbuster")
    text = stdout or ""

    # JSON mode (ffuf / feroxbuster -o json).
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        # ffuf shape: {"results":[{"url":..., "status":...}]}
        if "results" in e and isinstance(e["results"], list):
            for item in e["results"]:
                _add_url(r, item.get("url"), item.get("status"))
            continue
        # feroxbuster json-lines shape: {"type":"response","url":..., "status":...}
        if e.get("type") == "response":
            _add_url(r, e.get("url"), e.get("status"))
            continue
        # generic
        _add_url(r, e.get("url"), e.get("status") or e.get("status_code"))

    # Text mode — try all three common shapes.
    for m in _FEROX_RE.finditer(text):
        _add_url(r, m.group("url"), m.group("status"))
    for m in _GOBUSTER_RE.finditer(text):
        # gobuster lines are paths; they need a base URL. Try to lift one
        # from the first URL in stdout if we already have one.
        base = ""
        for u in r.new_urls:
            if u.get("url"):
                base = u["url"].rsplit("/", 1)[0]; break
        if not base:
            continue
        _add_url(r, base + m.group("path"), m.group("status"))
    for m in _DIRSEARCH_RE.finditer(text):
        base = ""
        for u in r.new_urls:
            if u.get("url"):
                base = u["url"].rsplit("/", 1)[0]; break
        if not base:
            continue
        _add_url(r, base + m.group("path"), m.group("status"))

    return r
