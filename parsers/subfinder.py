"""parsers.subfinder — subdomain-per-line output -> ParseResult.

subfinder / assetfinder / amass -passive default output is one subdomain
per line. We treat each as both a `new_subdomain` AND a `new_host` so the
autopilot v2 loop can pick it up for re-dispatch (new host -> probe,
new subdomain -> AppSec surface).
"""
from __future__ import annotations

import re

from .base import ParseResult


_HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def parse(stdout, stderr="", exit_code=0):
    r = ParseResult(source_tool="subfinder")
    seen = set()
    for raw in (stdout or "").splitlines():
        line = raw.strip().lower().rstrip(".")
        if not line or line.startswith(("#", "[")):
            continue
        # Strip URL scheme if present.
        if "://" in line:
            try:
                from urllib.parse import urlparse
                line = urlparse(line).hostname or ""
            except Exception:
                continue
        if not line or line in seen:
            continue
        if not _HOSTNAME_RE.match(line):
            continue
        seen.add(line)
        r.new_subdomains.append(line)
        if line not in r.new_hosts:
            r.new_hosts.append(line)
    return r
