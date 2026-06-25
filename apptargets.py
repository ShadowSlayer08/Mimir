#!/usr/bin/env python3
"""
apptargets.py — application-layer assessment targets (web apps now; APIs /
mobile / thick clients later).

Authorized / lab / CTF use only.

Infra assessment is service-driven (port -> module). AppSec is target-driven: a
web app is a URL, not just a port. This derives application targets from the
inventory (auto-promoting discovered http/https services) and from explicit
operator input (`assess --web URL`), so the AppSec modules assess them in
parallel with the host modules. Methodology + staging only.
"""
from __future__ import annotations

import re

_WEB_SERVICES = ("http", "https", "http-alt", "http-proxy", "www", "soap")


def _label(h):
    return (h["hostnames"][0] if h.get("hostnames") else h.get("ip")) or h.get("ipv6") or "?"


def web_targets_from_report(report):
    """Auto-promote discovered http/https services in the inventory to web targets."""
    out = []
    for h in report.get("hosts", []):
        label = _label(h)
        ip = h.get("ip") or label
        for p in h.get("ports", []):
            svc = p.get("service", {})
            name = (svc.get("name") or "").lower()
            if not any(name == s or name.startswith(s) for s in _WEB_SERVICES):
                continue
            port = p.get("port", 0)
            tls = (svc.get("tunnel", "").lower() == "ssl" or name == "https"
                   or port in (443, 8443))
            scheme = "https" if tls else "http"
            host_for_url = label if h.get("hostnames") else ip
            default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
            ref = f"{scheme}://{host_for_url}" + ("" if default_port else f":{port}")
            out.append({"kind": "web", "ref": ref, "label": label, "host": label,
                        "ip": ip, "port": port, "scheme": scheme, "tls": tls, "source": "auto"})
    return out


def parse_web(values):
    """Operator-supplied web targets: `--web URL` (repeatable; comma/space-separated ok)."""
    out = []
    for v in (values or []):
        for url in re.split(r"[,\s]+", str(v).strip()):
            if not url:
                continue
            if not re.match(r"^https?://", url, re.I):
                url = "http://" + url
            m = re.match(r"^(https?)://(?:\[([^\]]+)\]|([^/:]+))(?::(\d+))?", url, re.I)
            scheme = (m.group(1).lower() if m else "http")
            host = (m.group(2) or m.group(3)) if m else url        # group(2) = IPv6 literal
            port = int(m.group(4)) if (m and m.group(4)) else (443 if scheme == "https" else 80)
            out.append({"kind": "web", "ref": url.rstrip("/"), "label": host, "host": host,
                        "ip": host, "port": port, "scheme": scheme,
                        "tls": scheme == "https", "source": "operator"})
    return out


def app_targets(report, web=()):
    """Combined, de-duplicated application targets (auto-promoted + operator-supplied)."""
    seen, out = set(), []
    for t in web_targets_from_report(report) + parse_web(web):
        key = (t["kind"], t["scheme"], t["host"].lower(), t["port"])   # normalised identity
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out


if __name__ == "__main__":
    import sys
    from nmap_analyzer import load_scan, analyze, build_report
    hosts, meta, _ = load_scan(sys.argv[1])
    rep = build_report(hosts, meta, analyze(hosts))
    for t in app_targets(rep, web=sys.argv[2:]):
        print(f"  [{t['source']:8}] {t['kind']:5} {t['ref']}  (host={t['host']} port={t['port']})")
