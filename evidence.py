#!/usr/bin/env python3
"""
evidence.py — ingest an engagement evidence folder into one consolidated inventory.

Authorized / lab / CTF use only.

Walks a directory recursively, classifies every file, and merges all recon into a
single host/service inventory the rest of the engine can analyse:

  * nmap XML        (-oX)            -> parsed via nmap_analyzer.parse_nmap_xml
  * nmap normal     (.nmap / .txt)   -> parsed via nmap_analyzer.parse_nmap_text
  * nmap grepable   (.gnmap)         -> parsed here (parse_gnmap)
  * other text evidence              -> scanned for indicators (CVEs, VULNERABLE
                                        markers, credentials/hashes, private keys)

Hosts seen in multiple files are merged (union of ports, merged service detail and
NSE script output). Text indicators become extra findings — recovered credential
material in particular feeds the attack-path engine (valid-accounts -> lateral).

This is ANALYSIS only. Ingested findings still drive the per-service methodology
(what to test next) and STAGED attack paths for a human operator.
"""
from __future__ import annotations

import glob
import os
import re

from nmap_analyzer import parse_nmap_xml, parse_nmap_text

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Files we never try to read as text.
_BINARY_EXT = {".pcap", ".pcapng", ".cap", ".png", ".jpg", ".jpeg", ".gif", ".pdf",
               ".zip", ".gz", ".7z", ".rar", ".bin", ".exe", ".dll", ".jar", ".kdbx"}


def _blank_host():
    return {"ip": "", "ipv6": "", "mac": "", "vendor": "", "hostnames": [], "os": [],
            "distance": "", "uptime": "", "ports": [], "host_scripts": {}}


# --------------------------------------------------------------------------- #
# nmap grepable (-oG) parser
# --------------------------------------------------------------------------- #
def parse_gnmap(text):
    hosts = []
    host_rx = re.compile(r"Host:\s+(\S+)\s+\(([^)]*)\)\s+Ports:\s+(.*)")
    for ln in text.splitlines():
        m = host_rx.search(ln)
        if not m:
            continue
        ip, name, ports_blob = m.group(1), m.group(2).strip(), m.group(3)
        h = _blank_host()
        h["ip"] = ip
        if name and name != ip:
            h["hostnames"] = [name]
        for chunk in ports_blob.split(","):
            f = [x.strip() for x in chunk.split("/")]
            # portid/state/proto/owner/service/rpc/version/
            if len(f) < 3 or not f[0].isdigit() or f[1] != "open":
                continue
            svc = f[4] if len(f) > 4 else ""
            ver = f[6] if len(f) > 6 else ""
            h["ports"].append({
                "port": int(f[0]), "protocol": f[2] or "tcp", "state": "open", "reason": "",
                "service": {"name": svc, "product": ver, "version": "", "extrainfo": "",
                            "tunnel": "", "ostype": "", "cpe": []},
                "scripts": {}, "ssl_enum": None, "least_strength": None, "cert": None})
        if h["ports"]:
            hosts.append(h)
    return hosts


# --------------------------------------------------------------------------- #
# Inventory merge
# --------------------------------------------------------------------------- #
def _merge_service(dst, src):
    for k in ("name", "product", "version", "extrainfo", "tunnel", "ostype"):
        if not dst.get(k) and src.get(k):
            dst[k] = src[k]
    cpe = dst.setdefault("cpe", [])
    for c in src.get("cpe", []):
        if c not in cpe:
            cpe.append(c)


def merge_inventories(host_lists):
    """Merge hosts from many scans by ip/ipv6/hostname: union ports, merge detail."""
    merged, order = {}, []
    for hosts in host_lists:
        for h in hosts:
            key = h.get("ip") or h.get("ipv6") or (h["hostnames"][0] if h.get("hostnames") else None)
            if not key:
                continue
            if key not in merged:
                nh = _blank_host()
                nh.update({k: h.get(k, nh[k]) for k in
                           ("ip", "ipv6", "mac", "vendor", "distance", "uptime")})
                nh["hostnames"] = list(h.get("hostnames", []))
                nh["os"] = list(h.get("os", []))
                nh["host_scripts"] = dict(h.get("host_scripts", {}))
                nh["_ports"] = {p["port"]: p for p in h.get("ports", [])}
                merged[key] = nh
                order.append(key)
                continue
            m = merged[key]
            if not m["ip"] and h.get("ip"):
                m["ip"] = h["ip"]
            for hn in h.get("hostnames", []):
                if hn not in m["hostnames"]:
                    m["hostnames"].append(hn)
            if not m["os"] and h.get("os"):
                m["os"] = list(h["os"])
            for p in h.get("ports", []):
                ep = m["_ports"].get(p["port"])
                if not ep:
                    m["_ports"][p["port"]] = p
                else:
                    _merge_service(ep["service"], p["service"])
                    ep["scripts"].update(p.get("scripts", {}))
                    if p.get("ssl_enum") and not ep.get("ssl_enum"):
                        ep["ssl_enum"], ep["least_strength"] = p["ssl_enum"], p.get("least_strength")
                    if p.get("cert") and not ep.get("cert"):
                        ep["cert"] = p["cert"]
    out = []
    for key in order:
        m = merged[key]
        m["ports"] = [m["_ports"][k] for k in sorted(m["_ports"])]
        del m["_ports"]
        out.append(m)
    return out


# --------------------------------------------------------------------------- #
# Text-evidence indicator extraction
# --------------------------------------------------------------------------- #
_IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_NTLM_RX = re.compile(r"\b[a-f0-9]{32}:[a-f0-9]{32}\b", re.I)
_PMKEY_RX = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")
_CRED_LINE_RX = re.compile(r"(?i)\b(password|passwd|pwd|credential|login\s+success|"
                           r"valid\s+credentials|secretsdump|hashdump)\b")


from findings import finding as _finding   # canonical finding schema (findings.py)


def scan_text_indicators(text, source):
    """Conservative indicator scan over a non-nmap text artifact -> findings."""
    out = []
    host_hint = (_IP_RX.search(text).group(0) if _IP_RX.search(text) else source)

    cves = sorted(set(m.group(0).upper() for m in _CVE_RX.finditer(text)))
    if cves:
        out.append(_finding(source, 0, "Evidence", "info",
                            f"{len(cves)} CVE reference(s) in {source}", cve=cves,
                            detail=", ".join(cves[:12]), fix="Confirm applicability against the live target."))

    if _PMKEY_RX.search(text):
        out.append(_finding(host_hint, 0, "Evidence", "high",
                            f"Private key material in {source}",
                            detail="A PRIVATE KEY block was found — test it against SSH/TLS services.",
                            fix="Rotate the exposed key; treat as compromised."))

    hashes = _NTLM_RX.findall(text)
    if hashes:
        out.append(_finding(host_hint, 0, "Evidence", "high",
                            f"Credential hashes in {source}",
                            detail=f"{len(hashes)} NTLM-style hash(es) — crack or pass-the-hash against reachable hosts.",
                            fix="Force password resets for affected accounts."))

    cred_hits = sum(1 for _ in _CRED_LINE_RX.finditer(text))
    if cred_hits and not hashes:
        out.append(_finding(host_hint, 0, "Evidence", "high",
                            f"Credential material referenced in {source}",
                            detail=f"{cred_hits} credential-related line(s) — test reuse against reachable services.",
                            fix="Rotate any exposed credentials."))

    if "VULNERABLE" in text.upper() and "NOT VULNERABLE" not in text.upper():
        out.append(_finding(host_hint, 0, "Evidence", "medium",
                            f"'VULNERABLE' marker in {source}", cve=cves,
                            detail="A tool flagged a vulnerable state — validate and stage exploitation manually.",
                            fix="Patch the affected service."))
    return out


# --------------------------------------------------------------------------- #
# Directory ingestion
# --------------------------------------------------------------------------- #
def _classify(path, head):
    if "\x00" in head:
        return "binary"
    ext = os.path.splitext(path)[1].lower()
    if ext in _BINARY_EXT:
        return "binary"
    if "<nmaprun" in head or (ext == ".xml" and "<?xml" in head and "nmap" in head.lower()):
        return "nmap-xml"
    if re.search(r"^Host:\s+\S+.*Ports:", head, re.M) or ext == ".gnmap":
        return "gnmap"
    if "Nmap scan report for" in head:
        return "nmap-text"
    return "evidence"


def ingest_dir(root):
    """Walk `root`; return (hosts, meta, evidence_findings, manifest)."""
    host_lists, evidence, manifest = [], [], []
    files = sorted(p for p in glob.glob(os.path.join(root, "**", "*"), recursive=True)
                   if os.path.isfile(p))
    for path in files:
        rel = os.path.relpath(path, root)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                head = fh.read(8192)
        except Exception:
            manifest.append((rel, "unreadable", 0)); continue
        kind = _classify(path, head)
        try:
            if kind == "nmap-xml":
                hosts, _ = parse_nmap_xml(path)
                host_lists.append(hosts); manifest.append((rel, "nmap-xml", len(hosts)))
            elif kind == "gnmap":
                text = head + open(path, "r", encoding="utf-8", errors="ignore").read()
                hosts = parse_gnmap(text)
                host_lists.append(hosts); manifest.append((rel, "nmap-gnmap", len(hosts)))
            elif kind == "nmap-text":
                text = open(path, "r", encoding="utf-8", errors="ignore").read()
                hosts, _ = parse_nmap_text(text)
                host_lists.append(hosts); manifest.append((rel, "nmap-text", len(hosts)))
            elif kind == "evidence":
                text = open(path, "r", encoding="utf-8", errors="ignore").read()
                ind = scan_text_indicators(text, rel)
                evidence += ind; manifest.append((rel, "evidence", len(ind)))
            else:
                manifest.append((rel, "skipped(binary)", 0))
        except Exception as e:                                       # pragma: no cover
            manifest.append((rel, f"error:{type(e).__name__}", 0))
    hosts = merge_inventories(host_lists)
    meta = {"scanner": "evidence-ingest", "version": "",
            "args": f"{root} — {len(files)} file(s), {len(hosts)} merged host(s)", "start": ""}
    evidence.sort(key=lambda f: SEV_RANK.get(f["severity"], 9))
    return hosts, meta, evidence, manifest


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python evidence.py <evidence_dir>"); sys.exit(1)
    hosts, meta, ev, manifest = ingest_dir(sys.argv[1])
    print(f"[+] {meta['args']}")
    for rel, kind, n in manifest:
        print(f"    {kind:18} {rel}  ({n})")
    print(f"[+] {len(hosts)} merged host(s), {len(ev)} evidence finding(s)")
