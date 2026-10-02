#!/usr/bin/env python3
"""
enrich.py — live threat-intel enrichment for risk scoring (cached, offline-safe).

Authorized / lab / CTF use only.

Pulls the CISA KEV catalog (known-exploited CVEs) and FIRST EPSS scores
(exploit-probability) and caches them under the per-OS data dir, so composite
risk scoring can use CURRENT signals instead of a static --kev file. These are
PUBLIC vulnerability feeds — no target is contacted. Network egress is opt-in
(assess --enrich); offline or without it, the engine uses a fresh-enough cache,
falls back to a stale cache, or degrades gracefully to its offline behavior.
"""
from __future__ import annotations

import csv
import gzip
import json
import os
import time

from config import app_path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_TTL = 24 * 3600                      # refresh the feeds at most once a day


def _cache_file(name):
    base = app_path("cache")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, name)


def _fresh(path, ttl):
    try:
        return (os.path.isfile(path) and os.path.getsize(path) > 0
                and (time.time() - os.path.getmtime(path)) < ttl)
    except Exception:
        return False


_UA = "vantage-enrich/1.0 (+authorized pentest tooling; public vuln feeds only)"


def _stale(dest):
    return dest if (os.path.isfile(dest) and os.path.getsize(dest) > 0) else None


def _fetch(url, dest, ttl, offline, timeout=30):
    """Return dest if a fresh cache exists, a download succeeds, or (when a refresh
    is impossible) any non-empty stale cache exists; else None. Never raises.

    Writes atomically (temp + os.replace) and refuses to cache an empty body, so a
    truncated/empty/interrupted download can never poison the cache for a TTL window
    (a default User-Agent is sent — some CDNs 403 the bare python-requests UA)."""
    if _fresh(dest, ttl):
        return dest
    if offline:
        return _stale(dest)
    try:
        import requests
        r = requests.get(url, timeout=timeout, headers={"User-Agent": _UA})
        r.raise_for_status()
        if not r.content:
            return _stale(dest)                              # empty 200 -> keep good cache
        tmp = dest + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(r.content)
        os.replace(tmp, dest)                                # atomic on Windows + POSIX
        return dest
    except Exception:
        return _stale(dest)                                  # fall back to a good stale cache


def parse_kev(path):
    """Set of KEV CVE ids (upper-case) from a CISA KEV JSON file."""
    with open(path, "rb") as fh:
        data = json.load(fh)
    return {v.get("cveID", "").upper()
            for v in data.get("vulnerabilities", []) if v.get("cveID")}


def parse_epss(path):
    """Dict CVE-id(upper) -> EPSS probability (0..1) from a FIRST EPSS csv.gz."""
    out = {}
    with open(path, "rb") as fh:
        gz = fh.read(2) == b"\x1f\x8b"             # detect gzip by content, not filename
    opener = gzip.open if gz else open
    with opener(path, "rt", encoding="utf-8", errors="ignore") as fh:
        for row in csv.reader(fh):
            if not row or not row[0] or row[0].startswith("#") or row[0].lower() == "cve":
                continue
            try:
                out[row[0].upper()] = float(row[1])
            except (IndexError, ValueError):
                continue
    return out


def load_kev(offline=False, ttl=_TTL):
    """Set of KEV CVE ids (upper). Empty set if unavailable."""
    path = _fetch(KEV_URL, _cache_file("kev.json"), ttl, offline)
    if not path:
        return set()
    try:
        return parse_kev(path)
    except Exception:
        return set()


def load_epss(offline=False, ttl=_TTL):
    """Dict CVE-id(upper) -> EPSS probability. Empty dict if unavailable."""
    path = _fetch(EPSS_URL, _cache_file("epss.csv.gz"), ttl, offline)
    if not path:
        return {}
    try:
        return parse_epss(path)
    except Exception:
        return {}


def enrich(offline=False, ttl=_TTL):
    """(kev_set, epss_map) for risk scoring. Both empty if no data is available."""
    return load_kev(offline, ttl), load_epss(offline, ttl)


if __name__ == "__main__":
    import sys
    off = "--offline" in sys.argv
    kev, epss = enrich(offline=off)
    print(f"KEV: {len(kev)} CVEs | EPSS: {len(epss)} CVEs | cache dir: {app_path('cache')}")
    if epss:
        print("EPSS sample:", list(epss.items())[:3])
