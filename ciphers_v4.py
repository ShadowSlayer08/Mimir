#!/usr/bin/env python3
"""
ciphers_v4.py  —  nmap SSL/TLS Vulnerability Analyzer (native desktop GUI).

Authorized / lab / CTF use only.

v4 changes vs v3
----------------
 * Native windowed GUI (Tkinter) — opens in its own OS window, no browser,
   no local web server.
 * Ingests nmap output (XML from `-oX`, or normal .nmap/.txt) and analyzes
   EVERY SSL/TLS aspect nmap can report:
       - Protocol versions enabled (SSLv2/DROWN, SSLv3/POODLE, TLS1.0/1.1)
       - Per-cipher weaknesses + CVEs (reuses the v3 engine: SWEET32, RC4,
         BEAST, Lucky13, FREAK, Logjam, ROBOT, NULL, anon, ...)
       - nmap's own cipher grades / warnings (ssl-enum-ciphers)
       - Key exchange / Diffie-Hellman params (ssl-dh-params / Logjam)
       - X.509 certificate issues (expiry, weak key, weak signature, self-signed)
       - Named vuln scripts: ssl-heartbleed, ssl-poodle, ssl-ccs-injection,
         sslv2-drown, tls-ticketbleed, ssl-known-key, rsa/ROBOT, fallback-SCSV
 * Per-host risk grade, severity dashboard, sortable/filterable findings,
   and JSON / CSV / HTML report export.

Run:
    python3 ciphers_v4.py                 # opens the GUI window
    python3 ciphers_v4.py scan.xml        # opens GUI and loads the file
    python3 ciphers_v4.py scan.xml --no-gui --json out.json   # headless
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import os
import queue
import re
import sys
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

__version__ = "4.0"

# --------------------------------------------------------------------------- #
# Analysis engine (reuse v3 ciphers.py; fall back to a compact built-in)
# --------------------------------------------------------------------------- #
try:
    from ciphers import (cipher_vulnerabilities, check_mozilla, check_nist,
                          check_bsi, heuristic_security_from_name,
                          aggregate_security, vulns_floor_level)
    _ENGINE = "ciphers.py"
except Exception:                                                   # pragma: no cover
    _ENGINE = "built-in (place ciphers.py next to this file for full ratings)"

    def cipher_vulnerabilities(cn, tls_versions=None):
        cn = cn.upper()
        out = []

        def add(name, cve, sev, desc):
            out.append({"id": name, "name": name, "cve": list(cve),
                        "severity": sev, "description": desc})
        if "NULL" in cn:
            add("NULL cipher (no encryption)", [], "critical", "Cleartext.")
        if "ANON" in cn:
            add("Anonymous key exchange (no auth)", [], "critical", "MITM.")
        if "EXPORT" in cn or "_EXP" in cn:
            add("Export-grade RSA (FREAK)", ["CVE-2015-0204"], "high", "Weak export crypto.")
        if "RC4" in cn:
            add("RC4 (Bar Mitzvah/NOMORE)", ["CVE-2015-2808"], "high", "Keystream bias.")
        if "3DES" in cn or "DES_EDE" in cn:
            add("3DES SWEET32", ["CVE-2016-2183"], "medium", "64-bit block.")
        elif re.search(r"(?:^|_)DES(?:_|$)", cn):
            add("Single DES", [], "high", "56-bit key.")
        if "MD5" in cn:
            add("MD5 MAC", [], "medium", "Broken hash.")
        if "CBC" in cn:
            add("CBC (Lucky13)", ["CVE-2013-0169"], "medium", "Padding oracle.")
        if re.search(r"_SHA(?![0-9])", cn):
            add("SHA-1 MAC", ["CVE-2015-7575"], "low", "Deprecated.")
        if cn.startswith("TLS_RSA_WITH") or cn.startswith("TLS_RSA_EXPORT"):
            add("Static RSA (no PFS)", [], "low", "No forward secrecy.")
            add("RSA kex (ROBOT)", ["CVE-2017-13099"], "medium", "Bleichenbacher.")
        return out

    def heuristic_security_from_name(cn):
        cn = cn.upper()
        if any(k in cn for k in ("RC4", "DES", "NULL", "ANON", "EXPORT", "IDEA", "SEED")):
            return "insecure"
        if "CBC" in cn or "MD5" in cn or cn.startswith("TLS_RSA_WITH"):
            return "weak"
        if "GCM" in cn or "CHACHA20" in cn:
            return "recommended"
        return "secure" if ("ECDHE" in cn or "DHE" in cn) else "unknown"

    def check_mozilla(cn):
        return "not_listed"

    def check_nist(cn):
        return "not_approved"

    def check_bsi(cn):
        return "not_approved"

    def aggregate_security(ratings):
        vals = list(ratings.values())
        for lvl in ("insecure", "weak"):
            if lvl in vals:
                return lvl
        for lvl in ("recommended", "secure"):
            if lvl in vals:
                return lvl
        return "unknown"

    _LO = {"insecure": 0, "weak": 1, "unknown": 2, "secure": 3, "recommended": 4}

    def vulns_floor_level(level, vulns):
        floor = {"critical": 0, "high": 0, "medium": 1, "low": 1}
        cur = _LO.get(level, 2)
        for v in vulns:
            f = floor.get(v["severity"])
            if f is not None and f < cur:
                cur = f
        return {n: k for k, n in _LO.items()}[cur]


SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}


def rate_cipher(name, protocols=None):
    vulns = cipher_vulnerabilities(name, protocols)
    ratings = {"mozilla": check_mozilla(name), "nist": check_nist(name),
               "bsi": check_bsi(name), "heuristic": heuristic_security_from_name(name)}
    level = vulns_floor_level(aggregate_security(ratings), vulns)
    cves = sorted({c for v in vulns for c in v["cve"]})
    return level, vulns, cves


# --------------------------------------------------------------------------- #
# Protocol risk table
# --------------------------------------------------------------------------- #
PROTOCOL_RISK = {
    "SSLV2": ("critical", ["CVE-2016-0800"],
              "SSLv2 is fundamentally broken and enables the DROWN attack."),
    "SSLV3": ("high", ["CVE-2014-3566"],
              "SSLv3 is obsolete and vulnerable to POODLE."),
    "TLSV1.0": ("medium", ["CVE-2011-3389"],
                "TLS 1.0 is deprecated (BEAST; disallowed by PCI-DSS)."),
    "TLSV1.1": ("medium", [],
                "TLS 1.1 is deprecated (RFC 8996); disable in favour of 1.2/1.3."),
}

# Named nmap vuln scripts -> friendly metadata.
SCRIPT_VULN_META = {
    "ssl-heartbleed":    ("Heartbleed memory disclosure", ["CVE-2014-0160"], "critical"),
    "ssl-poodle":        ("POODLE (SSLv3 CBC)", ["CVE-2014-3566"], "high"),
    "ssl-ccs-injection": ("OpenSSL CCS Injection", ["CVE-2014-0224"], "high"),
    "sslv2-drown":       ("DROWN (SSLv2)", ["CVE-2016-0800"], "critical"),
    "tls-ticketbleed":   ("Ticketbleed memory disclosure", ["CVE-2016-9244"], "high"),
    "ssl-dh-params":     ("Weak Diffie-Hellman / Logjam", ["CVE-2015-4000"], "high"),
    "ssl-known-key":     ("Known/Debian weak private key", [], "critical"),
    "tls-fallback-scsv": ("Missing TLS_FALLBACK_SCSV (downgrade)", [], "medium"),
    "rsa-bleichenbacher":("ROBOT (Bleichenbacher RSA)", ["CVE-2017-13099"], "high"),
    "ssl-rsa-bleichenbacher": ("ROBOT (Bleichenbacher RSA)", ["CVE-2017-13099"], "high"),
}


# --------------------------------------------------------------------------- #
# nmap XML parsing
# --------------------------------------------------------------------------- #
def _elem_map(table):
    """Collect direct <elem key=..> children of a table into a dict."""
    return {e.get("key"): (e.text or "") for e in table if e.tag == "elem" and e.get("key")}


def _parse_ssl_enum(script):
    """Parse ssl-enum-ciphers -> ({proto: {ciphers:[...], warnings:[...]}}, least)."""
    protocols, least = {}, None
    for child in script:
        if child.tag == "elem" and (child.get("key") or "").lower() == "least strength":
            least = (child.text or "").strip()
        if child.tag != "table":
            continue
        key = (child.get("key") or "").strip()
        if not re.match(r"(?i)(SSL|TLS)v?\d", key):
            continue
        entry = {"ciphers": [], "warnings": []}
        for sub in child:
            sk = (sub.get("key") or "").lower()
            if sub.tag == "table" and sk == "ciphers":
                for ci in sub:
                    c, warns = {}, []
                    for e in ci:
                        if e.tag == "elem":
                            c[e.get("key")] = (e.text or "").strip()
                        elif e.tag == "table" and (e.get("key") or "").lower() == "warnings":
                            warns += [(w.text or "").strip() for w in e if (w.text or "").strip()]
                    if c.get("name"):
                        c["warnings"] = warns
                        entry["ciphers"].append(c)
            elif sub.tag == "table" and sk == "warnings":
                entry["warnings"] += [(w.text or "").strip() for w in sub if (w.text or "").strip()]
            elif sub.tag == "elem" and sk == "warnings":
                entry["warnings"].append((sub.text or "").strip())
        protocols[key] = entry
    return protocols, least


def _parse_ssl_cert(script):
    """Parse ssl-cert into a flat summary dict (best-effort)."""
    info = {"subject": "", "issuer": "", "key_type": "", "key_bits": "",
            "sig_algo": "", "not_before": "", "not_after": ""}
    for child in script:
        key = (child.get("key") or "").lower()
        if child.tag == "table" and key in ("subject", "issuer"):
            m = _elem_map(child)
            cn = m.get("commonName") or m.get("organizationName") or ""
            info[key] = cn
        elif child.tag == "table" and key == "pubkey":
            m = _elem_map(child)
            info["key_type"] = m.get("type", "")
            info["key_bits"] = m.get("bits", "")
        elif child.tag == "table" and key == "validity":
            m = _elem_map(child)
            info["not_before"] = m.get("notBefore", "")
            info["not_after"] = m.get("notAfter", "")
        elif child.tag == "elem" and key == "sig_algo":
            info["sig_algo"] = (child.text or "").strip()
    # text fallback for fields not captured structurally
    out = script.get("output", "") or ""
    if not info["not_after"]:
        m = re.search(r"Not valid after:\s*([0-9T:\-\sZ]+)", out)
        if m:
            info["not_after"] = m.group(1).strip()
    if not info["sig_algo"]:
        m = re.search(r"Signature Algorithm:\s*(\S+)", out)
        if m:
            info["sig_algo"] = m.group(1).strip()
    return info


def _parse_vuln_tables(script):
    """Parse vulns-library output -> list of {title, cves, state}."""
    found = []
    for child in script:
        if child.tag != "table":
            continue
        title, state, cves = (child.get("key") or ""), "", []
        for e in child.iter():
            if e.tag == "elem" and (e.get("key") or "") == "title":
                title = (e.text or title).strip()
            if e.tag == "elem" and (e.get("key") or "") == "state":
                state = (e.text or "").strip()
            if e.tag == "elem" and (e.get("key") or "") == "value" and (e.text or "").startswith("CVE"):
                cves.append(e.text.strip())
        cves += [c for c in re.findall(r"CVE-\d{4}-\d+", child.get("key") or "")]
        if state:
            found.append({"title": title, "state": state, "cves": sorted(set(cves))})
    # fallback: scan output attribute
    if not found:
        out = script.get("output", "") or ""
        if "VULNERABLE" in out.upper() and "NOT VULNERABLE" not in out.upper():
            found.append({"title": out.strip().splitlines()[0] if out.strip() else "VULNERABLE",
                          "state": "VULNERABLE", "cves": sorted(set(re.findall(r"CVE-\d{4}-\d+", out)))})
    return found


def parse_nmap_xml(path):
    root = ET.parse(path).getroot()
    hosts = []
    for h in root.iter("host"):
        if (h.find("status") is not None and h.find("status").get("state") == "down"):
            continue
        ip = ""
        for a in h.iter("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                ip = a.get("addr")
                break
        hostname = ""
        hn = h.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        ports = []
        for p in h.iter("port"):
            state = p.find("state")
            if state is not None and state.get("state") != "open":
                continue
            svc = p.find("service")
            port = {
                "port": int(p.get("portid")),
                "protocol": p.get("protocol", "tcp"),
                "service": (svc.get("name") if svc is not None else "") or "",
                "ssl_enum": None, "least_strength": None,
                "cert": None, "scripts": {},
            }
            for sc in p.iter("script"):
                sid = sc.get("id", "")
                if sid == "ssl-enum-ciphers":
                    port["ssl_enum"], port["least_strength"] = _parse_ssl_enum(sc)
                elif sid == "ssl-cert":
                    port["cert"] = _parse_ssl_cert(sc)
                else:
                    port["scripts"][sid] = {"output": sc.get("output", ""),
                                            "vulns": _parse_vuln_tables(sc)}
            ports.append(port)
        if ports:
            hosts.append({"ip": ip, "hostname": hostname, "ports": ports})
    return hosts


# --------------------------------------------------------------------------- #
# nmap normal-text parsing (fallback)
# --------------------------------------------------------------------------- #
def parse_nmap_text(text):
    hosts, cur_host, cur_port = [], None, None
    cur_proto, in_ciphers = None, False
    host_rx = re.compile(r"Nmap scan report for (\S+)(?:\s+\(([\d\.:a-fA-F]+)\))?")
    port_rx = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)")
    proto_rx = re.compile(r"^\|\s+((?:SSL|TLS)v[\d\.]+):")
    cipher_rx = re.compile(r"(TLS_[A-Z0-9_]+)")

    def flush_port():
        if cur_host is not None and cur_port is not None:
            cur_host["ports"].append(cur_port)

    for raw in text.splitlines():
        line = raw.rstrip()
        m = host_rx.search(line)
        if m:
            flush_port()
            cur_port = None
            name, ip = m.group(1), m.group(2) or m.group(1)
            cur_host = {"ip": ip, "hostname": name if name != ip else "", "ports": []}
            hosts.append(cur_host)
            continue
        m = port_rx.match(line)
        if m and cur_host is not None:
            flush_port()
            cur_port = {"port": int(m.group(1)), "protocol": m.group(2),
                        "service": m.group(3), "ssl_enum": {}, "least_strength": None,
                        "cert": None, "scripts": {}}
            cur_proto, in_ciphers = None, False
            continue
        if cur_port is None:
            continue
        pm = proto_rx.match(line)
        if pm:
            cur_proto = pm.group(1)
            cur_port["ssl_enum"][cur_proto] = {"ciphers": [], "warnings": []}
            in_ciphers = False
            continue
        if re.match(r"^\|\s+ciphers:", line):
            in_ciphers = True
            continue
        if re.match(r"^\|\s+warnings:", line):
            in_ciphers = False
            continue
        lm = re.search(r"least strength:\s*(\S+)", line)
        if lm:
            cur_port["least_strength"] = lm.group(1)
        cm = cipher_rx.search(line)
        if cm and cur_proto and in_ciphers:
            grade = ""
            gm = re.search(r"-\s*([A-F])\s*$", line)
            if gm:
                grade = gm.group(1)
            cur_port["ssl_enum"][cur_proto]["ciphers"].append(
                {"name": cm.group(1), "strength": grade, "warnings": []})
        elif cur_proto and not in_ciphers and line.startswith("|") and "least strength" not in line:
            w = line.lstrip("|_ ").strip()
            if w and not re.match(r"(?i)(SSL|TLS)v", w) and ":" not in w[:8]:
                cur_port["ssl_enum"][cur_proto]["warnings"].append(w)
    flush_port()
    return [h for h in hosts if h["ports"]]


# --------------------------------------------------------------------------- #
# Analysis: build findings for every SSL/TLS aspect
# --------------------------------------------------------------------------- #
def _finding(host, port, category, severity, title, cve=None, detail=""):
    return {"host": host, "port": port, "category": category, "severity": severity,
            "title": title, "cve": sorted(set(cve or [])), "detail": detail}


def _cert_issues(cert):
    issues, sev = [], "info"
    if not cert:
        return issues, sev
    na = cert.get("not_after", "")
    if na:
        dt = _parse_dt(na)
        if dt:
            days = (dt - datetime.now(timezone.utc)).days
            if days < 0:
                issues.append(("high", f"Certificate EXPIRED ({-days} days ago)"))
            elif days < 30:
                issues.append(("medium", f"Certificate expires in {days} days"))
    bits = cert.get("key_bits", "")
    if cert.get("key_type", "").lower() in ("rsa", "") and bits.isdigit() and int(bits) < 2048:
        issues.append(("high", f"Weak RSA key ({bits}-bit < 2048)"))
    sig = cert.get("sig_algo", "").lower()
    if "md5" in sig or "sha1" in sig:
        issues.append(("medium", f"Weak signature algorithm ({cert.get('sig_algo')})"))
    if cert.get("subject") and cert.get("subject") == cert.get("issuer"):
        issues.append(("low", "Self-signed certificate"))
    if issues:
        sev = min((s for s, _ in issues), key=lambda s: SEV_RANK[s])
    return issues, sev


def _parse_dt(s):
    s = s.strip().replace("Z", "+00:00")
    for fmt in (None,):  # try fromisoformat first
        try:
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            break
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:19], fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def analyze_hosts(hosts, online=False):
    """Walk parsed hosts and produce findings + per-cipher ratings."""
    all_findings, cipher_rows, cert_rows = [], [], []

    # Optionally enrich ciphers via the live API (kept off by default).
    api_query = None
    if online and _ENGINE == "ciphers.py":
        try:
            from ciphers import query_api as api_query  # noqa
        except Exception:
            api_query = None

    for h in hosts:
        label = h.get("hostname") or h.get("ip") or "?"
        for p in h["ports"]:
            hp_port = p["port"]
            enum = p.get("ssl_enum") or {}

            # ---- Protocol-level findings ----
            for proto in enum:
                pu = proto.upper().replace("V", "V").replace(" ", "")
                pu = proto.upper()
                risk = PROTOCOL_RISK.get(pu.replace(" ", ""))
                if risk:
                    sev, cve, desc = risk
                    all_findings.append(_finding(
                        label, hp_port, "Protocol", sev,
                        f"Insecure protocol enabled: {proto}", cve, desc))

            # ---- nmap overall grade ----
            least = p.get("least_strength")
            if least and least.upper() in ("C", "D", "E", "F"):
                all_findings.append(_finding(
                    label, hp_port, "Grade", "medium" if least.upper() == "C" else "high",
                    f"Weak overall cipher grade: {least}", [],
                    "nmap rates the weakest negotiated cipher poorly."))

            # ---- Per-cipher findings ----
            for proto, data in enum.items():
                for c in data.get("ciphers", []):
                    name = c.get("name", "")
                    if not name:
                        continue
                    level, vulns, cves = rate_cipher(name, [proto])
                    grade = c.get("strength", "")
                    if api_query:
                        try:
                            r = api_query(name, ["ciphersuite", "mozilla", "nist", "bsi", "heuristic"])
                            level = r.get("security_level", level)
                            cves = sorted(set(cves) | set(r.get("cves", [])))
                        except Exception:
                            pass
                    cipher_rows.append({
                        "host": label, "port": hp_port, "protocol": proto,
                        "cipher": name, "grade": grade, "level": level, "cves": cves,
                    })
                    for v in vulns:
                        all_findings.append(_finding(
                            label, hp_port, "Cipher", v["severity"],
                            f"{name}: {v['name']}", v["cve"],
                            f"[{proto}] {v['description']}"))
                    # nmap's own per-cipher warnings
                    for w in c.get("warnings", []):
                        all_findings.append(_finding(
                            label, hp_port, "Cipher", "medium",
                            f"{name}: {w}", sorted(set(re.findall(r'CVE-\d{4}-\d+', w))),
                            f"[{proto}] nmap warning"))
                # protocol-level warnings
                for w in data.get("warnings", []):
                    all_findings.append(_finding(
                        label, hp_port, "Cipher", "medium", w,
                        sorted(set(re.findall(r"CVE-\d{4}-\d+", w))), f"[{proto}] nmap warning"))

            # ---- Certificate findings ----
            cert = p.get("cert")
            if cert:
                issues, _ = _cert_issues(cert)
                cert_rows.append({"host": label, "port": hp_port, "cert": cert,
                                  "issues": [t for _, t in issues]})
                for sev, txt in issues:
                    all_findings.append(_finding(
                        label, hp_port, "Certificate", sev, txt, [],
                        f"Subject: {cert.get('subject','-')} | Issuer: {cert.get('issuer','-')}"))

            # ---- Named vuln scripts ----
            for sid, sc in (p.get("scripts") or {}).items():
                meta = SCRIPT_VULN_META.get(sid)
                for v in sc.get("vulns", []):
                    if "NOT VULNERABLE" in v["state"].upper():
                        continue
                    if "VULNERABLE" not in v["state"].upper():
                        continue
                    name, mcve, sev = meta if meta else (v["title"], [], "high")
                    cves = sorted(set(v["cves"]) | set(mcve))
                    all_findings.append(_finding(
                        label, hp_port, "Vuln scan", sev, name or v["title"], cves,
                        v["title"]))

    all_findings.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f["host"], f["port"]))
    cipher_rows.sort(key=lambda r: ({"insecure": 0, "weak": 1, "unknown": 2,
                                     "secure": 3, "recommended": 4}.get(r["level"], 2),
                                    r["host"], r["port"]))
    return {"findings": all_findings, "ciphers": cipher_rows, "certificates": cert_rows}


def host_grade(findings):
    score = sum(SEV_WEIGHT.get(f["severity"], 0) for f in findings)
    if any(f["severity"] == "critical" for f in findings):
        return "F", score
    if score >= 40:
        return "F", score
    if score >= 20:
        return "D", score
    if score >= 8:
        return "C", score
    if score > 0:
        return "B", score
    return "A", score


def build_report(hosts, analysis):
    findings = analysis["findings"]
    sev_counts = {s: 0 for s in SEV_RANK}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    per_host = {}
    for f in findings:
        per_host.setdefault(f["host"], []).append(f)
    host_summary = []
    for h in hosts:
        label = h.get("hostname") or h.get("ip") or "?"
        g, score = host_grade(per_host.get(label, []))
        host_summary.append({"host": label, "ip": h.get("ip"),
                             "grade": g, "score": score,
                             "findings": len(per_host.get(label, []))})
    return {
        "tool_version": __version__, "engine": _ENGINE,
        "generated": datetime.now(timezone.utc).isoformat(),
        "host_summary": host_summary,
        "severity_counts": sev_counts,
        "unique_cves": sorted({c for f in findings for c in f["cve"]}),
        "findings": findings, "ciphers": analysis["ciphers"],
        "certificates": analysis["certificates"],
    }


# --------------------------------------------------------------------------- #
# Report export
# --------------------------------------------------------------------------- #
def export_json(report, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)


def export_csv(report, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["host", "port", "category", "severity",
                                           "title", "cve", "detail"])
        w.writeheader()
        for f in report["findings"]:
            row = dict(f)
            row["cve"] = "; ".join(f["cve"])
            w.writerow(row)


def export_html(report, path):
    sev_css = {"critical": "#b00020", "high": "#e8590c", "medium": "#f08c00",
               "low": "#868e96", "info": "#1971c2"}
    sc = report["severity_counts"]
    rows = []
    for f in report["findings"]:
        color = sev_css.get(f["severity"], "#888")
        cves = " ".join(f'<span class="cve">{html.escape(c)}</span>' for c in f["cve"])
        rows.append(
            f"<tr><td>{html.escape(f['host'])}:{f['port']}</td>"
            f"<td>{html.escape(f['category'])}</td>"
            f"<td><span class='sev' style='background:{color}'>{f['severity'].upper()}</span></td>"
            f"<td>{html.escape(f['title'])}</td><td>{cves}</td>"
            f"<td>{html.escape(f['detail'])}</td></tr>")
    hs = "".join(
        f"<tr><td>{html.escape(h['host'])}</td><td>{html.escape(h.get('ip') or '')}</td>"
        f"<td><b>{h['grade']}</b></td><td>{h['findings']}</td></tr>"
        for h in report["host_summary"])
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>nmap SSL/TLS Report</title><style>
body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:2rem;background:#0f1115;color:#e6e6e6}}
h1,h2{{color:#fff}} table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{border:1px solid #2a2f3a;padding:7px 9px;text-align:left;font-size:14px;vertical-align:top}}
th{{background:#1a1e26}} tr:nth-child(even){{background:#161a21}}
.sev{{color:#fff;padding:2px 8px;border-radius:9px;font-size:12px;font-weight:600}}
.cve{{background:#343a40;padding:1px 6px;border-radius:7px;font-size:11px;margin-right:4px}}
.cards{{display:flex;gap:10px;flex-wrap:wrap}} .card{{background:#1a1e26;border-radius:10px;padding:12px 18px}}
.card .n{{font-size:1.6rem;font-weight:700}}</style></head><body>
<h1>nmap SSL/TLS Vulnerability Report</h1>
<p>Generated {html.escape(report['generated'])} · engine: {html.escape(report['engine'])} · v{report['tool_version']}</p>
<div class="cards">
<div class="card"><div class="n" style="color:{sev_css['critical']}">{sc.get('critical',0)}</div>Critical</div>
<div class="card"><div class="n" style="color:{sev_css['high']}">{sc.get('high',0)}</div>High</div>
<div class="card"><div class="n" style="color:{sev_css['medium']}">{sc.get('medium',0)}</div>Medium</div>
<div class="card"><div class="n" style="color:{sev_css['low']}">{sc.get('low',0)}</div>Low</div>
<div class="card"><div class="n">{len(report['unique_cves'])}</div>Unique CVEs</div>
</div>
<h2>Host summary</h2><table><tr><th>Host</th><th>IP</th><th>Grade</th><th>Findings</th></tr>{hs}</table>
<h2>Findings ({len(report['findings'])})</h2>
<table><tr><th>Target</th><th>Category</th><th>Severity</th><th>Issue</th><th>CVEs</th><th>Detail</th></tr>
{''.join(rows)}</table></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


# --------------------------------------------------------------------------- #
# Loader
# --------------------------------------------------------------------------- #
def load_scan(path):
    with open(path, "r", errors="ignore") as fh:
        head = fh.read(4096)
    if "<?xml" in head or "<nmaprun" in head:
        return parse_nmap_xml(path), "xml"
    return parse_nmap_text(open(path, "r", errors="ignore").read()), "text"


# --------------------------------------------------------------------------- #
# Tkinter desktop GUI
# --------------------------------------------------------------------------- #
def launch_gui(preload=None, selftest=False):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    SEV_FG = {"critical": "#ff5b6e", "high": "#ff9f43", "medium": "#ffd24a",
              "low": "#9aa4b2", "info": "#5aacff"}
    LEVEL_FG = {"insecure": "#ff5b6e", "weak": "#ff9f43", "unknown": "#9aa4b2",
                "secure": "#7bd88f", "recommended": "#5aacff"}

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(f"nmap SSL/TLS Vulnerability Analyzer  v{__version__}")
            self.geometry("1160x740")
            self.minsize(900, 560)
            self.configure(bg="#0f1115")
            self.report = None
            self.scan_path = None
            self._q = queue.Queue()
            self._setup_style()
            self._build_topbar()
            self._build_tabs()
            self._build_statusbar()
            if preload and os.path.isfile(preload):
                self.after(150, lambda: self.analyze(preload))
            if selftest:
                self.after(3000, self._selftest_check)

        def _selftest_check(self):
            n_find = len(self.find_tree.get_children())
            n_ciph = len(self.cipher_tree.get_children())
            n_host = len(self.host_tree.get_children())
            ok = self.report is not None and n_find > 0
            print(f"SELFTEST {'OK' if ok else 'FAIL'} | hosts={n_host} "
                  f"findings_rows={n_find} cipher_rows={n_ciph} "
                  f"report_findings={len(self.report['findings']) if self.report else 0}")
            self.destroy()
            sys.exit(0 if ok else 2)

        # ---------- style ----------
        def _setup_style(self):
            s = ttk.Style(self)
            try:
                s.theme_use("clam")
            except Exception:
                pass
            bg, panel, fg = "#0f1115", "#1a1e26", "#e6e6e6"
            s.configure(".", background=bg, foreground=fg, fieldbackground=panel)
            s.configure("TFrame", background=bg)
            s.configure("TLabel", background=bg, foreground=fg)
            s.configure("TButton", background="#2a2f3a", foreground=fg, padding=6)
            s.map("TButton", background=[("active", "#3a4150")])
            s.configure("TNotebook", background=bg, borderwidth=0)
            s.configure("TNotebook.Tab", background=panel, foreground=fg, padding=(14, 7))
            s.map("TNotebook.Tab", background=[("selected", "#2a2f3a")])
            s.configure("Treeview", background=panel, fieldbackground=panel,
                        foreground=fg, rowheight=24, borderwidth=0)
            s.configure("Treeview.Heading", background="#222732", foreground=fg)
            s.configure("TCheckbutton", background=bg, foreground=fg)
            s.configure("Status.TLabel", background="#222732", foreground="#9aa4b2")

        # ---------- top bar ----------
        def _build_topbar(self):
            bar = ttk.Frame(self, padding=(10, 8))
            bar.pack(fill="x")
            ttk.Button(bar, text="📂  Open nmap file", command=self.open_file).pack(side="left")
            self.online_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(bar, text="Query ciphersuite.info (online)",
                            variable=self.online_var).pack(side="left", padx=10)
            ttk.Button(bar, text="↻ Re-analyze", command=self.reanalyze).pack(side="left")
            for text, cmd in (("⬇ JSON", self.save_json), ("⬇ CSV", self.save_csv),
                              ("⬇ HTML report", self.save_html)):
                ttk.Button(bar, text=text, command=cmd).pack(side="right", padx=3)

        # ---------- tabs ----------
        def _build_tabs(self):
            self.nb = ttk.Notebook(self)
            self.nb.pack(fill="both", expand=True, padx=8, pady=4)
            self._build_summary_tab()
            self._build_findings_tab()
            self._build_ciphers_tab()
            self._build_cert_tab()
            self._build_raw_tab()

        def _build_summary_tab(self):
            f = ttk.Frame(self.nb, padding=10)
            self.nb.add(f, text="Summary")
            self.metrics = ttk.Frame(f)
            self.metrics.pack(fill="x", pady=(0, 10))
            self.metric_labels = {}
            for i, key in enumerate(["Hosts", "Critical", "High", "Medium", "Low", "CVEs"]):
                card = ttk.Frame(self.metrics)
                card.grid(row=0, column=i, padx=6, sticky="w")
                num = ttk.Label(card, text="–", font=("TkDefaultFont", 20, "bold"))
                num.pack()
                ttk.Label(card, text=key).pack()
                self.metric_labels[key] = num
            ttk.Label(f, text="Per-host risk", font=("TkDefaultFont", 11, "bold")).pack(anchor="w")
            self.host_tree = ttk.Treeview(f, columns=("ip", "grade", "findings"),
                                          show="tree headings", height=14)
            self.host_tree.heading("#0", text="Host")
            for c, t, w in (("ip", "IP", 180), ("grade", "Grade", 80),
                            ("findings", "Findings", 100)):
                self.host_tree.heading(c, text=t)
                self.host_tree.column(c, width=w, anchor="center")
            self.host_tree.column("#0", width=320)
            self.host_tree.pack(fill="both", expand=True)
            for sev, col in SEV_FG.items():
                self.host_tree.tag_configure(sev, foreground=col)

        def _build_findings_tab(self):
            f = ttk.Frame(self.nb, padding=8)
            self.nb.add(f, text="Findings")
            ctrl = ttk.Frame(f)
            ctrl.pack(fill="x", pady=(0, 6))
            ttk.Label(ctrl, text="Severity:").pack(side="left")
            self.sev_filter = tk.StringVar(value="all")
            ttk.Combobox(ctrl, textvariable=self.sev_filter, width=10, state="readonly",
                         values=["all", "critical", "high", "medium", "low", "info"]
                         ).pack(side="left", padx=6)
            ttk.Label(ctrl, text="Search:").pack(side="left")
            self.search_var = tk.StringVar()
            ent = ttk.Entry(ctrl, textvariable=self.search_var, width=32)
            ent.pack(side="left", padx=6)
            self.sev_filter.trace_add("write", lambda *_: self._render_findings())
            self.search_var.trace_add("write", lambda *_: self._render_findings())

            pane = ttk.Panedwindow(f, orient="vertical")
            pane.pack(fill="both", expand=True)
            top = ttk.Frame(pane)
            self.find_tree = ttk.Treeview(
                top, columns=("target", "cat", "sev", "title", "cve"),
                show="headings", height=16)
            for c, t, w in (("target", "Target", 150), ("cat", "Category", 100),
                            ("sev", "Severity", 90), ("title", "Issue", 460),
                            ("cve", "CVEs", 200)):
                self.find_tree.heading(c, text=t)
                self.find_tree.column(c, width=w, anchor="w")
            vs = ttk.Scrollbar(top, orient="vertical", command=self.find_tree.yview)
            self.find_tree.configure(yscrollcommand=vs.set)
            self.find_tree.pack(side="left", fill="both", expand=True)
            vs.pack(side="right", fill="y")
            for sev, col in SEV_FG.items():
                self.find_tree.tag_configure(sev, foreground=col)
            self.find_tree.bind("<<TreeviewSelect>>", self._show_detail)
            pane.add(top, weight=3)
            self.detail = tk.Text(pane, height=6, bg="#1a1e26", fg="#e6e6e6",
                                  wrap="word", relief="flat", padx=8, pady=6)
            pane.add(self.detail, weight=1)

        def _build_ciphers_tab(self):
            f = ttk.Frame(self.nb, padding=8)
            self.nb.add(f, text="Ciphers")
            self.cipher_tree = ttk.Treeview(
                f, columns=("target", "proto", "cipher", "grade", "level", "cve"),
                show="headings")
            for c, t, w in (("target", "Target", 150), ("proto", "Protocol", 90),
                            ("cipher", "Cipher", 420), ("grade", "nmap", 60),
                            ("level", "Verdict", 110), ("cve", "CVEs", 200)):
                self.cipher_tree.heading(c, text=t)
                self.cipher_tree.column(c, width=w, anchor="w")
            vs = ttk.Scrollbar(f, orient="vertical", command=self.cipher_tree.yview)
            self.cipher_tree.configure(yscrollcommand=vs.set)
            self.cipher_tree.pack(side="left", fill="both", expand=True)
            vs.pack(side="right", fill="y")
            for lvl, col in LEVEL_FG.items():
                self.cipher_tree.tag_configure(lvl, foreground=col)

        def _build_cert_tab(self):
            f = ttk.Frame(self.nb, padding=8)
            self.nb.add(f, text="Certificates")
            self.cert_text = tk.Text(f, bg="#1a1e26", fg="#e6e6e6", wrap="word",
                                     relief="flat", padx=10, pady=8)
            self.cert_text.pack(fill="both", expand=True)

        def _build_raw_tab(self):
            f = ttk.Frame(self.nb, padding=8)
            self.nb.add(f, text="Raw")
            self.raw_text = tk.Text(f, bg="#1a1e26", fg="#cfd6e0", wrap="none",
                                    relief="flat", padx=8, pady=6)
            self.raw_text.pack(fill="both", expand=True)

        def _build_statusbar(self):
            self.status = tk.StringVar(value=f"Ready · engine: {_ENGINE}")
            ttk.Label(self, textvariable=self.status, style="Status.TLabel",
                      anchor="w", padding=(8, 4)).pack(fill="x", side="bottom")

        # ---------- actions ----------
        def open_file(self):
            path = filedialog.askopenfilename(
                title="Open nmap output",
                filetypes=[("nmap files", "*.xml *.nmap *.txt *.out *.log"),
                           ("All files", "*.*")])
            if path:
                self.analyze(path)

        def reanalyze(self):
            if self.scan_path:
                self.analyze(self.scan_path)
            else:
                self.status.set("Open an nmap file first.")

        def analyze(self, path):
            self.scan_path = path
            self.status.set(f"Analyzing {os.path.basename(path)} …")
            self.update_idletasks()
            online = self.online_var.get()

            def worker():
                try:
                    hosts, kind = load_scan(path)
                    if not hosts:
                        self._q.put(("error", "No hosts/SSL data found in file."))
                        return
                    analysis = analyze_hosts(hosts, online=online)
                    report = build_report(hosts, analysis)
                    raw = open(path, "r", errors="ignore").read()
                    self._q.put(("done", (report, kind, raw)))
                except Exception as e:
                    self._q.put(("error", str(e)))

            threading.Thread(target=worker, daemon=True).start()
            self.after(100, self._poll)

        def _poll(self):
            try:
                kind, payload = self._q.get_nowait()
            except queue.Empty:
                self.after(100, self._poll)
                return
            if kind == "error":
                self.status.set("Error: " + payload)
                messagebox.showerror("Analysis error", payload)
                return
            report, ftype, raw = payload
            self.report = report
            self._populate(report, ftype, raw)

        def _populate(self, report, ftype, raw):
            sc = report["severity_counts"]
            self.metric_labels["Hosts"].config(text=str(len(report["host_summary"])))
            self.metric_labels["Critical"].config(text=str(sc.get("critical", 0)))
            self.metric_labels["High"].config(text=str(sc.get("high", 0)))
            self.metric_labels["Medium"].config(text=str(sc.get("medium", 0)))
            self.metric_labels["Low"].config(text=str(sc.get("low", 0)))
            self.metric_labels["CVEs"].config(text=str(len(report["unique_cves"])))

            self.host_tree.delete(*self.host_tree.get_children())
            for h in report["host_summary"]:
                tag = "critical" if h["grade"] == "F" else (
                    "high" if h["grade"] == "D" else (
                        "medium" if h["grade"] == "C" else "low"))
                self.host_tree.insert("", "end", text=h["host"],
                                      values=(h.get("ip") or "", h["grade"], h["findings"]),
                                      tags=(tag,))
            self._render_findings()

            self.cipher_tree.delete(*self.cipher_tree.get_children())
            for r in report["ciphers"]:
                self.cipher_tree.insert(
                    "", "end", tags=(r["level"],),
                    values=(f"{r['host']}:{r['port']}", r["protocol"], r["cipher"],
                            r["grade"] or "-", r["level"].upper(), ", ".join(r["cves"])))

            self.cert_text.delete("1.0", "end")
            if report["certificates"]:
                for c in report["certificates"]:
                    cert = c["cert"]
                    self.cert_text.insert("end", f"● {c['host']}:{c['port']}\n")
                    self.cert_text.insert("end",
                        f"    Subject : {cert.get('subject','-')}\n"
                        f"    Issuer  : {cert.get('issuer','-')}\n"
                        f"    Key     : {cert.get('key_type','-')} {cert.get('key_bits','-')}\n"
                        f"    SigAlgo : {cert.get('sig_algo','-')}\n"
                        f"    Valid   : {cert.get('not_before','-')} → {cert.get('not_after','-')}\n")
                    if c["issues"]:
                        self.cert_text.insert("end", "    Issues  : " +
                                              "; ".join(c["issues"]) + "\n")
                    self.cert_text.insert("end", "\n")
            else:
                self.cert_text.insert("end", "No certificate data found in scan "
                                              "(run nmap with --script ssl-cert).")

            self.raw_text.delete("1.0", "end")
            self.raw_text.insert("end", raw[:200000])

            self.status.set(
                f"Loaded {os.path.basename(self.scan_path)} ({ftype}) · "
                f"{len(report['host_summary'])} host(s) · "
                f"{len(report['findings'])} findings · "
                f"{len(report['unique_cves'])} CVEs")

        def _render_findings(self):
            if not self.report:
                return
            self.find_tree.delete(*self.find_tree.get_children())
            sev = self.sev_filter.get()
            term = self.search_var.get().lower().strip()
            for i, f in enumerate(self.report["findings"]):
                if sev != "all" and f["severity"] != sev:
                    continue
                blob = (f["title"] + " " + f["detail"] + " " +
                        " ".join(f["cve"]) + " " + f["host"]).lower()
                if term and term not in blob:
                    continue
                self.find_tree.insert(
                    "", "end", iid=str(i), tags=(f["severity"],),
                    values=(f"{f['host']}:{f['port']}", f["category"],
                            f["severity"].upper(), f["title"], ", ".join(f["cve"])))

        def _show_detail(self, _evt):
            sel = self.find_tree.selection()
            if not sel:
                return
            f = self.report["findings"][int(sel[0])]
            self.detail.delete("1.0", "end")
            self.detail.insert("end",
                f"{f['title']}\n\nTarget   : {f['host']}:{f['port']}\n"
                f"Category : {f['category']}\nSeverity : {f['severity'].upper()}\n"
                f"CVEs     : {', '.join(f['cve']) or '-'}\n\n{f['detail']}")

        # ---------- exports ----------
        def _need_report(self):
            if not self.report:
                messagebox.showinfo("No data", "Open and analyze an nmap file first.")
                return False
            return True

        def save_json(self):
            if not self._need_report():
                return
            p = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("JSON", "*.json")])
            if p:
                export_json(self.report, p)
                self.status.set("Saved " + p)

        def save_csv(self):
            if not self._need_report():
                return
            p = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV", "*.csv")])
            if p:
                export_csv(self.report, p)
                self.status.set("Saved " + p)

        def save_html(self):
            if not self._need_report():
                return
            p = filedialog.asksaveasfilename(defaultextension=".html",
                                             filetypes=[("HTML", "*.html")])
            if p:
                export_html(self.report, p)
                self.status.set("Saved " + p)

    App().mainloop()


# --------------------------------------------------------------------------- #
# CLI entry
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="nmap SSL/TLS vulnerability analyzer (GUI + headless).")
    ap.add_argument("file", nargs="?", help="nmap XML or normal-text output to load")
    ap.add_argument("--no-gui", action="store_true", help="Run headless and write a report")
    ap.add_argument("--online", action="store_true", help="Also query ciphersuite.info")
    ap.add_argument("--json", dest="json_out", help="Headless: write JSON report")
    ap.add_argument("--csv", dest="csv_out", help="Headless: write CSV report")
    ap.add_argument("--html", dest="html_out", help="Headless: write HTML report")
    ap.add_argument("--selftest", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--version", action="version", version=f"ciphers_v4 {__version__}")
    args = ap.parse_args()

    if args.no_gui:
        if not args.file:
            ap.error("--no-gui requires a file argument")
        hosts, kind = load_scan(args.file)
        report = build_report(hosts, analyze_hosts(hosts, online=args.online))
        if args.json_out:
            export_json(report, args.json_out)
            print(f"[+] JSON: {args.json_out}")
        if args.csv_out:
            export_csv(report, args.csv_out)
            print(f"[+] CSV : {args.csv_out}")
        if args.html_out:
            export_html(report, args.html_out)
            print(f"[+] HTML: {args.html_out}")
        sc = report["severity_counts"]
        print(f"[+] {len(report['host_summary'])} host(s), {len(report['findings'])} findings "
              f"(crit={sc.get('critical',0)} high={sc.get('high',0)} "
              f"med={sc.get('medium',0)} low={sc.get('low',0)}), "
              f"{len(report['unique_cves'])} CVEs.")
        if not any([args.json_out, args.csv_out, args.html_out]):
            print(json.dumps(report["host_summary"], indent=2))
        return

    launch_gui(preload=args.file, selftest=args.selftest)


if __name__ == "__main__":
    main()
