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

import os
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


def parse_api(values):
    """Operator-supplied API targets (`--api URL`) — same URL parsing as web, kind=api."""
    return [dict(t, kind="api") for t in parse_web(values)]


def _thick_platform(p):
    """Infer the desktop platform from a thick-client binary's extension."""
    lp = p.lower()
    if lp.endswith((".dmg", ".app", ".pkg", ".macho", ".dylib")):
        return "macos"
    if lp.endswith((".elf", ".so", ".bin", ".run", ".appimage", ".out")):
        return "linux"
    return "windows"                                          # .exe/.dll/.msi/.jar + default


def _file_targets(values, kind):
    """Operator-supplied FILE targets: mobile (APK/IPA) or thick-client binary."""
    out = []
    for v in (values or []):
        for p in re.split(r"[,\s]+", str(v).strip()):
            if not p:
                continue
            base = os.path.basename(p.rstrip("/\\")) or p
            t = {"kind": kind, "ref": p, "label": base, "host": base, "app": p, "source": "operator"}
            if kind == "mobile":
                t["platform"] = "ios" if p.lower().endswith(".ipa") else "android"
            elif kind == "thick":
                t["platform"] = _thick_platform(p)
            out.append(t)
    return out


def parse_mobile(values):
    return _file_targets(values, "mobile")


def parse_thick(values):
    return _file_targets(values, "thick")


def parse_cloud(values):
    """Operator cloud targets: --cloud aws|azure|gcp[:account]."""
    out = []
    for v in (values or []):
        for tok in re.split(r"[,\s]+", str(v).strip()):
            if not tok:
                continue
            prov, _, ident = tok.partition(":")
            prov = prov.lower()
            if prov not in ("aws", "azure", "gcp"):
                continue
            out.append({"kind": "cloud", "provider": prov, "ref": tok, "label": tok,
                        "host": ident or prov, "account": ident, "source": "operator"})
    return out


_WIFI_BANDS = ("wifi", "ble", "zigbee", "rf")


def parse_wireless(values):
    """Operator wireless targets: --wireless [wifi|ble|zigbee|rf|<ssid>]."""
    out = []
    for v in (values or []):
        for tok in re.split(r"[,\s]+", str(v).strip()):
            if not tok:
                continue
            low = tok.lower()
            t = {"kind": "wireless", "ref": tok, "label": tok, "host": tok, "source": "operator"}
            if low in _WIFI_BANDS:
                t["band"] = low
            else:
                t["ssid"] = tok
            out.append(t)
    return out


def parse_k8s(values):
    """Operator Kubernetes targets: --k8s <cluster|kubeconfig|context>."""
    out = []
    for v in (values or []):
        for tok in re.split(r"[,\s]+", str(v).strip()):
            if tok:
                out.append({"kind": "k8s", "ref": tok, "label": tok, "host": tok,
                            "source": "operator"})
    return out


def parse_source(values):
    """Operator source/supply-chain targets: --source <path|repo-url>."""
    out = []
    for v in (values or []):
        for tok in re.split(r"[,\s]+", str(v).strip()):
            if not tok:
                continue
            base = os.path.basename(tok.rstrip("/\\")) or tok
            out.append({"kind": "source", "ref": tok, "label": base, "host": base,
                        "source": "operator"})
    return out


def parse_identity(values):
    """Operator SaaS-identity targets: --identity entra|m365|okta|gworkspace|adfs[:tenant]."""
    out = []
    for v in (values or []):
        for tok in re.split(r"[,\s]+", str(v).strip()):
            if not tok:
                continue
            prov, _, ident = tok.partition(":")
            out.append({"kind": "identity", "provider": prov.lower(), "ref": tok, "label": tok,
                        "tenant": ident, "domain": ident, "host": ident or prov.lower(),
                        "source": "operator"})
    return out


def parse_hypervisor(values):
    """Operator hypervisor targets: --hypervisor esxi|vcenter|proxmox|xen|hyperv[:host]."""
    out = []
    for v in (values or []):
        for tok in re.split(r"[,\s]+", str(v).strip()):
            if not tok:
                continue
            prov, _, ident = tok.partition(":")
            out.append({"kind": "hypervisor", "provider": prov.lower(), "ref": tok, "label": tok,
                        "host": ident or prov.lower(), "source": "operator"})
    return out


def app_targets(report, web=(), api=(), mobile=(), thick=(), cloud=(),
                wireless=(), k8s=(), source=(), identity=(), hypervisor=()):
    """Combined, de-duplicated application targets (auto-promoted web + operator inputs)."""
    seen, out = set(), []
    for t in (web_targets_from_report(report) + parse_web(web) + parse_api(api)
              + parse_mobile(mobile) + parse_thick(thick) + parse_cloud(cloud)
              + parse_wireless(wireless) + parse_k8s(k8s) + parse_source(source)
              + parse_identity(identity) + parse_hypervisor(hypervisor)):
        if t["kind"] in ("web", "api"):
            key = (t["kind"], t["scheme"], t["host"].lower(), t["port"])
        else:
            key = (t["kind"], t.get("ref", "").lower())                 # distinct by path/provider/token
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
