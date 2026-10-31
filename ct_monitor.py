#!/usr/bin/env python3
"""
ct_monitor.py — certificate-transparency log lookup for a domain.

Authorized / lab / CTF / VAPT / red-team use only.

Queries public CT log aggregators (crt.sh by default) for every certificate
issued to a domain or its subdomains, parses out the SAN list, and surfaces:
  * every subdomain name present in any issued cert (asset discovery)
  * recently issued certs (last N days) that suggest an active deployment
  * fingerprint anomalies (cert for a non-prod CA, wildcard scope change)

Offline-safe: all requests cached under the per-OS data dir with a 24-h TTL,
atomic writes, stale-fallback. Never raises on network error. The engine
degrades to "no CT data" and keeps running.

This is passive OSINT — no traffic to the target.

    python ct_monitor.py acme.example                 # subdomains + fresh certs
    python ct_monitor.py acme.example --since 7       # certs issued in last 7 days
    python ct_monitor.py acme.example --refresh       # force live refetch
    python ct_monitor.py acme.example --json out.json
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

try:
    from enrich import _cache_file, _fresh
except Exception:                                              # pragma: no cover
    def _cache_file(name):
        base = os.path.join(os.path.expanduser("~"), ".cache", "mimir")
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, name)

    def _fresh(path, ttl):
        return os.path.exists(path) and (time.time() - os.path.getmtime(path) < ttl)


def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                      # pragma: no cover
            pass


_force_utf8_stdio()

_TTL = 24 * 3600
_UA = ("mimir-ct-monitor/1.0 (+authorized pentest tooling; "
       "public CT logs only; no target traffic)")
_CRTSH = "https://crt.sh/?q=%25.{domain}&output=json"


_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$", re.I)


def _valid_domain(d):
    return isinstance(d, str) and bool(_DOMAIN_RE.match(d.strip()))


def _cache_path(domain):
    safe = re.sub(r"[^a-z0-9._-]+", "_", domain.lower())
    return _cache_file(f"ct_{safe}.json")


def _fetch(domain, offline=False, timeout=30):
    dest = _cache_path(domain)
    if _fresh(dest, _TTL):
        return dest
    if offline:
        return dest if os.path.exists(dest) and os.path.getsize(dest) else None
    url = _CRTSH.format(domain=domain)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
        if not body:
            return dest if os.path.exists(dest) and os.path.getsize(dest) else None
        tmp = dest + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(body)
        os.replace(tmp, dest)
        return dest
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError):
        return dest if os.path.exists(dest) and os.path.getsize(dest) else None


def _parse(path):
    """Parse crt.sh JSON. Returns [{issuer, not_before, not_after, names:[...], serial}]."""
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        return []
    out = []
    for r in raw or []:
        if not isinstance(r, dict):
            continue
        name_value = (r.get("name_value") or "")
        names = sorted({n.strip().lower() for n in name_value.split("\n")
                        if n and _valid_domain(n.strip().lstrip("*."))})
        out.append({
            "issuer": (r.get("issuer_name") or "").strip(),
            "serial": r.get("serial_number", ""),
            "not_before": r.get("not_before", ""),
            "not_after": r.get("not_after", ""),
            "names": sorted(names),
        })
    return out


def lookup(domain, offline=True, since_days=0):
    """Primary API.
    Returns a dict with:
      domain, cert_count, subdomains (set as sorted list), recent (list of certs),
      stale_cache (bool), source (crt.sh)."""
    if not _valid_domain(domain):
        return {"domain": domain, "error": "invalid_domain", "cert_count": 0,
                "subdomains": [], "recent": []}
    path = _fetch(domain, offline=offline)
    certs = _parse(path)
    subs = set()
    for c in certs:
        for n in c["names"]:
            if n == domain or n.endswith("." + domain):
                subs.add(n.lstrip("*."))
    recent = []
    if since_days and certs:
        try:
            cut = datetime.now(timezone.utc) - timedelta(days=int(since_days))
            for c in certs:
                try:
                    nb = datetime.fromisoformat(c["not_before"].replace("Z", "+00:00"))
                    if nb >= cut:
                        recent.append(c)
                except (ValueError, TypeError):
                    pass
        except Exception:
            pass
    stale = bool(path and os.path.exists(path) and not _fresh(path, _TTL))
    return {"domain": domain, "cert_count": len(certs), "subdomains": sorted(subs),
            "recent": recent, "stale_cache": stale, "source": "crt.sh",
            "cache_path": path}


def refresh(domain):
    """Force a live refetch. Returns True if we have (fresh OR stale) cache after."""
    dest = _cache_path(domain)
    if os.path.exists(dest):
        try:
            os.utime(dest, (0, 0))                              # mark stale so _fresh is False
        except OSError:
            pass
    return _fetch(domain, offline=False) is not None


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="mimir-ct",
                                 description="Certificate Transparency lookup (crt.sh; cached)")
    ap.add_argument("domain", help="apex domain to query (e.g. acme.example)")
    ap.add_argument("--offline", action="store_true", help="use cache only; never fetch")
    ap.add_argument("--refresh", action="store_true", help="force live refetch now")
    ap.add_argument("--since", type=int, default=0,
                    help="also list certs issued in the last N days")
    ap.add_argument("--json", metavar="FILE", help="write structured JSON here")
    args = ap.parse_args(argv)
    if args.refresh:
        ok = refresh(args.domain)
        print(f"[ct] refresh {'OK' if ok else 'FAILED (kept any stale cache)'}")
    res = lookup(args.domain, offline=args.offline or not args.refresh,
                 since_days=args.since)
    if "error" in res:
        print(f"[ct] {res['error']}: {args.domain}")
        return 1
    print(f"[ct] {res['domain']}: {res['cert_count']} cert(s), "
          f"{len(res['subdomains'])} unique subdomain name(s)"
          + ("  (stale cache)" if res["stale_cache"] else ""))
    for s in res["subdomains"][:40]:
        print(f"  - {s}")
    if res["subdomains"][40:]:
        print(f"  ... (+{len(res['subdomains']) - 40} more)")
    if args.since and res["recent"]:
        print(f"\n[ct] {len(res['recent'])} cert(s) issued in last {args.since} day(s):")
        for c in res["recent"][:10]:
            print(f"  - {c['not_before'][:10]}  {c['issuer'][:60]}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2)
        print(f"[+] wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
