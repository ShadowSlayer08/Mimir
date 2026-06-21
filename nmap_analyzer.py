#!/usr/bin/env python3
"""
nmap_analyzer.py  —  Full-spectrum nmap result analyzer with a native GUI.

Authorized / lab / CTF use only.

Analyzes an nmap scan (XML from `-oX`, or normal .nmap/.txt) across EVERY aspect:

  Hosts        : up/down, IPv4/IPv6/MAC + vendor, hostnames, distance, uptime, OS match
  Ports        : open/filtered states with reasons, protocol, service, product/version, CPE
  Services     : risk-aware categorisation of 50+ services (web, remote-access,
                 file-sharing, databases, mail, directory, container, ICS, ...)
  Protocols    : cleartext/legacy protocol detection (telnet, ftp, snmp v1/2c, http, ...)
  Vulnerabilities:
                 - `vulners` CPE->CVE lists (CVSS-scored, exploit-flagged, summarised)
                 - any NSE `vuln`-library script reporting state=VULNERABLE
                   (smb-vuln-ms17-010/EternalBlue, http-vuln-*, ssl-*, ...)
                 - full TLS cipher / certificate / protocol analysis (SWEET32, RC4,
                   POODLE, Heartbleed, Logjam, weak cert, expired, ...)
  Recommendations: each finding carries a remediation hint, severity and CVEs.

Per-host risk grade (A-F), severity dashboard, service distribution, global
findings with live filtering, NSE script browser, and JSON/CSV/HTML export.

Run:
    python3 nmap_analyzer.py                  # open the GUI window
    python3 nmap_analyzer.py scan.xml         # open + load
    python3 nmap_analyzer.py scan.xml --no-gui --html report.html   # headless
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
from collections import Counter, defaultdict
from datetime import datetime, timezone

__version__ = "5.0"


# --------------------------------------------------------------------------- #
# Force UTF-8 stdio. CLI output uses box-drawing, arrows, '·' and '—'; on a
# legacy Windows code page (cp1252) writing those raises UnicodeEncodeError and
# aborts the whole pipeline. Reconfiguring here — before ciphers.py runs
# colorama.init() and wraps the stream — fixes every tool that imports this
# module (assess, attack_path_engine, modules). Harmless on POSIX.
# --------------------------------------------------------------------------- #
def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                          # pragma: no cover
            pass


_force_utf8_stdio()


# --------------------------------------------------------------------------- #
# Optional cipher-CVE engine (from ciphers.py); lite fallback otherwise.
# --------------------------------------------------------------------------- #
try:
    from ciphers import (cipher_vulnerabilities, check_mozilla, check_nist,
                          check_bsi, heuristic_security_from_name,
                          aggregate_security, vulns_floor_level)
    _ENGINE = "ciphers.py"
except Exception:                                                   # pragma: no cover
    _ENGINE = "built-in"

    def cipher_vulnerabilities(cn, tls_versions=None):
        cn, out = cn.upper(), []

        def add(n, c, s, d):
            out.append({"name": n, "cve": list(c), "severity": s, "description": d})
        if "NULL" in cn: add("NULL cipher (no encryption)", [], "critical", "Cleartext.")
        if "ANON" in cn: add("Anonymous key exchange", [], "critical", "MITM.")
        if "EXPORT" in cn or "_EXP" in cn: add("Export-grade (FREAK)", ["CVE-2015-0204"], "high", "Weak.")
        if "RC4" in cn: add("RC4 (NOMORE)", ["CVE-2015-2808"], "high", "Keystream bias.")
        if "3DES" in cn or "DES_EDE" in cn: add("3DES SWEET32", ["CVE-2016-2183"], "medium", "64-bit block.")
        elif re.search(r"(?:^|_)DES(?:_|$)", cn): add("Single DES", [], "high", "56-bit.")
        if "MD5" in cn: add("MD5 MAC", [], "medium", "Broken hash.")
        if "CBC" in cn: add("CBC (Lucky13)", ["CVE-2013-0169"], "medium", "Padding oracle.")
        if re.search(r"_SHA(?![0-9])", cn): add("SHA-1 MAC", ["CVE-2015-7575"], "low", "Deprecated.")
        if cn.startswith("TLS_RSA_WITH") or cn.startswith("TLS_RSA_EXPORT"):
            add("Static RSA (no PFS)", [], "low", "No forward secrecy.")
            add("RSA kex (ROBOT)", ["CVE-2017-13099"], "medium", "Bleichenbacher.")
        return out

    def heuristic_security_from_name(cn):
        cn = cn.upper()
        if any(k in cn for k in ("RC4", "DES", "NULL", "ANON", "EXPORT", "IDEA", "SEED")): return "insecure"
        if "CBC" in cn or "MD5" in cn or cn.startswith("TLS_RSA_WITH"): return "weak"
        if "GCM" in cn or "CHACHA20" in cn: return "recommended"
        return "secure" if ("ECDHE" in cn or "DHE" in cn) else "unknown"

    def check_mozilla(c): return "not_listed"
    def check_nist(c): return "not_approved"
    def check_bsi(c): return "not_approved"

    def aggregate_security(r):
        v = list(r.values())
        for l in ("insecure", "weak"):
            if l in v: return l
        for l in ("recommended", "secure"):
            if l in v: return l
        return "unknown"

    _LO = {"insecure": 0, "weak": 1, "unknown": 2, "secure": 3, "recommended": 4}

    def vulns_floor_level(level, vulns):
        fl = {"critical": 0, "high": 0, "medium": 1, "low": 1}
        cur = _LO.get(level, 2)
        for x in vulns:
            f = fl.get(x["severity"])
            if f is not None and f < cur: cur = f
        return {n: k for k, n in _LO.items()}[cur]


def rate_cipher(name, protocols=None):
    vulns = cipher_vulnerabilities(name, protocols)
    ratings = {"mozilla": check_mozilla(name), "nist": check_nist(name),
               "bsi": check_bsi(name), "heuristic": heuristic_security_from_name(name)}
    level = vulns_floor_level(aggregate_security(ratings), vulns)
    return level, vulns, sorted({c for v in vulns for c in v["cve"]})


# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def cvss_severity(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "info"
    if s >= 9: return "critical"
    if s >= 7: return "high"
    if s >= 4: return "medium"
    if s > 0:  return "low"
    return "info"


# --------------------------------------------------------------------------- #
# Composite risk model (docs/risk_scoring.md): CVSS + EPSS + Exposure + Business
# normalised to 0-100, with CISA-KEV and public-exploit overrides. Config is
# loaded from the knowledge base; falls back to these embedded defaults.
# --------------------------------------------------------------------------- #
RISK_DEFAULT = {
    "weights": {"cvss": 0.30, "epss": 0.30, "exposure": 0.25, "business": 0.15},
    "bands": {"critical": 80, "high": 60, "medium": 35, "low": 1},
    "overrides": {"kev": "critical", "public_exploit": "high"},
    "default_exposure": 0.5,
    "default_business": 0.5,
}
EXPOSURE_LEVELS = {"internet": 1.0, "internal": 0.5, "isolated": 0.2}
BUSINESS_LEVELS = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}


def get_risk_config():
    cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in RISK_DEFAULT.items()}
    try:
        from knowledge_loader import load_knowledge
        for k, v in (load_knowledge().risk or {}).items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    except Exception:                                                  # pragma: no cover
        pass
    return cfg


def _risk_band(score, bands):
    if score >= bands.get("critical", 80): return "critical"
    if score >= bands.get("high", 60):     return "high"
    if score >= bands.get("medium", 35):   return "medium"
    if score >= bands.get("low", 1):       return "low"
    return "info"


def composite_risk(cvss10, epss=None, exposure=None, business=None,
                   kev=False, public_exploit=False, cfg=None):
    """Return (score_0_100, severity_band) per docs/risk_scoring.md.

    Components with no signal (e.g. EPSS, which we don't have offline) are
    dropped and the remaining weights renormalised, so partial data still yields
    a sane score. KEV is a hard override to critical; a public exploit floors the
    band at high. exposure/business are 0-1 (default from config when None).
    """
    cfg = cfg or get_risk_config()
    w, bands = cfg["weights"], cfg["bands"]
    if kev:
        return 100, "critical"
    comps = {"cvss": max(0.0, min(1.0, (cvss10 or 0) / 10.0))}
    if epss is not None:
        comps["epss"] = max(0.0, min(1.0, float(epss)))
    comps["exposure"] = max(0.0, min(1.0, cfg["default_exposure"] if exposure is None else exposure))
    comps["business"] = max(0.0, min(1.0, cfg.get("default_business", 0.5) if business is None else business))
    den = sum(w.get(k, 0) for k in comps)
    score = round(sum(w.get(k, 0) * v for k, v in comps.items()) / den * 100) if den else 0
    band = _risk_band(score, bands)
    if public_exploit and SEV_RANK.get(band, 9) > SEV_RANK["high"]:
        band, score = "high", max(score, bands.get("high", 60))
    return score, band


# --------------------------------------------------------------------------- #
# Service risk knowledge base
# --------------------------------------------------------------------------- #
SERVICE_RISK = {
    "telnet":       ("high", "Remote Access", "Telnet exposes credentials in cleartext", "Replace with SSH; block 23."),
    "rlogin":       ("high", "Remote Access", "Berkeley r-login (cleartext, host-trust auth)", "Disable r-services."),
    "rsh":          ("high", "Remote Access", "Berkeley r-shell (cleartext, host-trust auth)", "Disable r-services."),
    "exec":         ("high", "Remote Access", "rexec (cleartext remote execution)", "Disable."),
    "shell":        ("high", "Remote Access", "rsh/shell service (cleartext)", "Disable."),
    "vnc":          ("high", "Remote Access", "VNC exposed (often weak/no auth)", "Tunnel via SSH/VPN; strong auth."),
    "ms-wbt-server":("medium", "Remote Access", "RDP exposed to the network", "Restrict to VPN; enforce NLA."),
    "x11":          ("high", "Display", "X11 server reachable (possible unauthenticated access)", "Bind to localhost; disable TCP."),
    "ftp":          ("medium", "File Transfer", "FTP is cleartext; verify anonymous access", "Use SFTP/FTPS."),
    "tftp":         ("medium", "File Transfer", "TFTP has no authentication (UDP)", "Restrict or disable."),
    "microsoft-ds": ("medium", "File Sharing", "SMB (445) exposed", "Restrict; disable SMBv1; patch."),
    "netbios-ssn":  ("medium", "File Sharing", "NetBIOS/SMB (139) exposed", "Restrict; disable SMBv1/NetBIOS."),
    "nfs":          ("medium", "File Sharing", "NFS export reachable", "Restrict exports & source IPs."),
    "rpcbind":      ("low", "RPC", "rpcbind/portmapper exposed (host enumeration)", "Firewall 111."),
    "snmp":         ("medium", "Management", "SNMP v1/v2c sends community strings in cleartext", "Use SNMPv3; restrict."),
    "mysql":        ("medium", "Database", "MySQL/MariaDB reachable from network", "Bind to localhost/firewall."),
    "ms-sql-s":     ("medium", "Database", "MSSQL reachable from network", "Firewall; strong auth."),
    "postgresql":   ("medium", "Database", "PostgreSQL reachable from network", "Restrict pg_hba; firewall."),
    "mongodb":      ("high", "Database", "MongoDB exposed (frequently unauthenticated)", "Enable auth; bind localhost."),
    "mongod":       ("high", "Database", "MongoDB exposed (frequently unauthenticated)", "Enable auth; bind localhost."),
    "redis":        ("high", "Database", "Redis exposed (often no auth -> RCE)", "requirepass + bind; firewall."),
    "memcache":     ("high", "Database", "Memcached exposed (no auth; DDoS amplifier)", "Bind localhost; disable UDP."),
    "elasticsearch":("high", "Database", "Elasticsearch exposed (often no auth)", "Enable security; firewall."),
    "couchdb":      ("high", "Database", "CouchDB exposed", "Enable auth; firewall."),
    "cassandra":    ("medium", "Database", "Cassandra reachable", "Enable auth; firewall."),
    "ldap":         ("low", "Directory", "LDAP exposed (cleartext unless LDAPS)", "Prefer LDAPS; restrict."),
    "kerberos":     ("info", "Directory", "Kerberos KDC reachable", "Expected on DCs; monitor."),
    "http":         ("info", "Web", "Plain HTTP (cleartext)", "Redirect to HTTPS/HSTS."),
    "http-proxy":   ("medium", "Web", "Open HTTP proxy may allow relaying", "Restrict/authenticate."),
    "pop3":         ("low", "Mail", "POP3 cleartext (unless STARTTLS/POP3S)", "Enforce TLS."),
    "imap":         ("low", "Mail", "IMAP cleartext (unless STARTTLS/IMAPS)", "Enforce TLS."),
    "smtp":         ("info", "Mail", "SMTP reachable; check open relay & STARTTLS", "Enforce TLS; deny relay."),
    "finger":       ("low", "Info Leak", "finger discloses user info", "Disable."),
    "docker":       ("critical", "Container", "Docker API exposed (unauth -> host RCE)", "Never expose; mTLS only."),
    "kubernetes":   ("high", "Container", "Kubernetes API/kubelet exposed", "Restrict; RBAC; auth."),
    "irc":          ("low", "Chat", "IRC service exposed", "Verify intent."),
    "upnp":         ("medium", "IoT", "UPnP exposed (NAT/abuse risk)", "Disable on WAN."),
    "modbus":       ("high", "ICS", "Modbus (ICS) exposed with no auth", "Isolate OT network."),
    "s7":           ("high", "ICS", "Siemens S7 (ICS) exposed", "Isolate OT network."),
    "bacnet":       ("medium", "ICS", "BACnet (building automation) exposed", "Isolate."),
    "dnp3":         ("high", "ICS", "DNP3 (ICS) exposed", "Isolate OT network."),
    "ethernet-ip":  ("high", "ICS", "EtherNet/IP (ICS) exposed", "Isolate OT network."),
    "iec-104":      ("high", "ICS", "IEC 60870-5-104 (ICS) exposed", "Isolate OT network."),
    "fox":          ("medium", "ICS", "Tridium Fox (building automation) exposed", "Isolate."),
    "ssh":          ("info", "Remote Access", "SSH exposed", "Restrict source IPs; key auth; disable weak algorithms."),
    "rdp":          ("medium", "Remote Access", "RDP exposed to the network", "Restrict to VPN; enforce NLA + MFA."),
    "winrm":        ("medium", "Remote Access", "WinRM exposed (remote PowerShell)", "Restrict to mgmt subnet; HTTPS + auth."),
    "wsman":        ("medium", "Remote Access", "WinRM/WSMan exposed", "Restrict; require HTTPS + auth."),
    "rsync":        ("medium", "File Transfer", "rsync daemon exposed (often anonymous)", "Require auth; restrict modules."),
    "domain":       ("info", "DNS", "DNS server reachable", "Restrict recursion; disable zone transfers."),
    "ntp":          ("low", "Management", "NTP exposed (monlist amplification/info-leak)", "Patch; disable mode 7/monlist."),
    "ipmi":         ("high", "Management", "IPMI/BMC exposed (default creds, RAKP hash leak)", "Isolate BMC LAN; strong creds; patch."),
    "asf-rmcp":     ("high", "Management", "ASF-RMCP/IPMI BMC exposed", "Isolate BMC LAN; strong creds."),
    "amqp":         ("medium", "Messaging", "AMQP/RabbitMQ broker exposed", "Require auth; change guest creds; restrict."),
    "mqtt":         ("medium", "Messaging", "MQTT broker exposed (often anonymous)", "Require auth/ACLs; enforce TLS."),
    "kafka":        ("medium", "Messaging", "Kafka broker exposed", "Enable SASL auth; restrict."),
    "isakmp":       ("medium", "VPN", "IKE/ISAKMP exposed (aggressive-mode PSK risk)", "Disable aggressive mode; prefer IKEv2."),
    "pptp":         ("medium", "VPN", "PPTP VPN exposed (MS-CHAPv2 weak)", "Migrate to a modern VPN."),
    "sip":          ("low", "VoIP", "SIP service exposed", "Restrict; SIP/TLS; strong extension passwords."),
    "socks":        ("medium", "Proxy", "SOCKS proxy exposed (relay/pivot risk)", "Require auth; ACL; bind internal."),
    "jetdirect":    ("low", "Printing", "Printer raw-print port (9100) exposed", "Restrict to print servers; disable raw print."),
    "ipp":          ("low", "Printing", "IPP print service exposed", "Restrict to print servers."),
    "mountd":       ("low", "File Sharing", "NFS mountd reachable", "Firewall RPC; restrict exports."),
}
CLEARTEXT = {"telnet", "ftp", "http", "pop3", "imap", "snmp", "tftp", "finger", "rlogin", "rsh"}
# nmap often reports the TLS-wrapped variant by its own service name (https,
# imaps, ...) with no tunnel="ssl" attribute (e.g. in normal-text output). These
# must NOT be matched by their cleartext prefix and flagged as cleartext.
SECURE_NAMES = {"https", "ftps", "ftps-data", "imaps", "pop3s", "smtps",
                "ldaps", "nntps", "telnets", "sieve", "dnsovertls"}


def _match_rank(name, frag):
    """0=no match, 1=substring, 2=prefix, 3=exact — to pick the most specific
    service entry (so 'tftp' isn't matched as 'ftp')."""
    if name == frag:
        return 3
    if name.startswith(frag):
        return 2
    if frag in name:
        return 1
    return 0


def service_risk(svc_name, port, product="", tunnel=""):
    name = (svc_name or "").lower()
    tunneled = (tunnel or "").lower() == "ssl" or name in SECURE_NAMES
    best, best_frag, best_key = None, None, (0, 0)
    for frag, meta in SERVICE_RISK.items():
        r = _match_rank(name, frag)
        if r and (r, len(frag)) > best_key:
            best_key, best, best_frag = (r, len(frag)), meta, frag
    if best is None:
        return None
    # The TLS-wrapped variant of a normally-cleartext service (https, ftps,
    # imaps, ...) is not itself a cleartext exposure — the TLS analyser handles
    # those ports separately.
    if tunneled and best_frag in CLEARTEXT:
        return None
    return best


# --------------------------------------------------------------------------- #
# Protocol / named-vuln tables
# --------------------------------------------------------------------------- #
PROTOCOL_RISK = {
    "SSLV2":  ("critical", ["CVE-2016-0800"], "SSLv2 enabled (DROWN)."),
    "SSLV3":  ("high", ["CVE-2014-3566"], "SSLv3 enabled (POODLE)."),
    "TLSV1.0":("medium", ["CVE-2011-3389"], "TLS 1.0 deprecated (BEAST; PCI)."),
    "TLSV1.1":("medium", [], "TLS 1.1 deprecated (RFC 8996)."),
}
SCRIPT_VULN_META = {
    "ssl-heartbleed": ("Heartbleed memory disclosure", ["CVE-2014-0160"], "critical"),
    "ssl-poodle": ("POODLE (SSLv3 CBC)", ["CVE-2014-3566"], "high"),
    "ssl-ccs-injection": ("OpenSSL CCS Injection", ["CVE-2014-0224"], "high"),
    "sslv2-drown": ("DROWN (SSLv2)", ["CVE-2016-0800"], "critical"),
    "tls-ticketbleed": ("Ticketbleed", ["CVE-2016-9244"], "high"),
    "ssl-dh-params": ("Weak Diffie-Hellman / Logjam", ["CVE-2015-4000"], "high"),
    "ssl-known-key": ("Known/Debian weak key", [], "critical"),
    "tls-fallback-scsv": ("Missing TLS_FALLBACK_SCSV (downgrade)", [], "medium"),
    "smb-vuln-ms17-010": ("EternalBlue (MS17-010)", ["CVE-2017-0143", "CVE-2017-0144"], "critical"),
    "smb-vuln-ms08-067": ("MS08-067 RCE", ["CVE-2008-4250"], "critical"),
    "smb-vuln-cve-2017-7494": ("SambaCry", ["CVE-2017-7494"], "critical"),
    "rdp-vuln-ms12-020": ("MS12-020 RDP", ["CVE-2012-0002"], "high"),
}


# --------------------------------------------------------------------------- #
# nmap XML parsing
# --------------------------------------------------------------------------- #
def _elem_map(table):
    return {e.get("key"): (e.text or "") for e in table if e.tag == "elem" and e.get("key")}


def _parse_ssl_enum(script):
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
            elif sub.tag in ("table", "elem") and sk == "warnings":
                src = sub if sub.tag == "table" else [sub]
                entry["warnings"] += [(w.text or "").strip() for w in src if (w.text or "").strip()]
        protocols[key] = entry
    return protocols, least


def _parse_ssl_cert(script):
    info = {"subject": "", "issuer": "", "key_type": "", "key_bits": "",
            "sig_algo": "", "not_before": "", "not_after": ""}
    for child in script:
        key = (child.get("key") or "").lower()
        if child.tag == "table" and key in ("subject", "issuer"):
            m = _elem_map(child)
            info[key] = m.get("commonName") or m.get("organizationName") or ""
        elif child.tag == "table" and key == "pubkey":
            m = _elem_map(child)
            info["key_type"], info["key_bits"] = m.get("type", ""), m.get("bits", "")
        elif child.tag == "table" and key == "validity":
            m = _elem_map(child)
            info["not_before"], info["not_after"] = m.get("notBefore", ""), m.get("notAfter", "")
        elif child.tag == "elem" and key == "sig_algo":
            info["sig_algo"] = (child.text or "").strip()
    out = script.get("output", "") or ""
    if not info["not_after"]:
        m = re.search(r"Not valid after:\s*([0-9T:\-\sZ]+)", out)
        if m: info["not_after"] = m.group(1).strip()
    if not info["sig_algo"]:
        m = re.search(r"Signature Algorithm:\s*(\S+)", out)
        if m: info["sig_algo"] = m.group(1).strip()
    return info


def _parse_vuln_tables(script):
    found = []
    for child in script:
        if child.tag != "table":
            continue
        title, state, cves = (child.get("key") or ""), "", []
        for e in child.iter():
            k = e.get("key") or ""
            if e.tag == "elem" and k == "title":
                title = (e.text or title).strip()
            if e.tag == "elem" and k == "state":
                state = (e.text or "").strip()
            if e.tag == "elem" and k == "value" and (e.text or "").startswith("CVE"):
                cves.append(e.text.strip())
        cves += re.findall(r"CVE-\d{4}-\d+", child.get("key") or "")
        if state:
            found.append({"title": title, "state": state, "cves": sorted(set(cves))})
    if not found:
        out = script.get("output", "") or ""
        if "VULNERABLE" in out.upper() and "NOT VULNERABLE" not in out.upper():
            found.append({"title": (out.strip().splitlines() or ["VULNERABLE"])[0],
                          "state": "VULNERABLE",
                          "cves": sorted(set(re.findall(r"CVE-\d{4}-\d+", out)))})
    return found


def _parse_vulners(script):
    groups = []
    for cpe_tbl in script:
        if cpe_tbl.tag != "table":
            continue
        cpe = cpe_tbl.get("key") or ""
        cves = []
        for row in cpe_tbl:
            m = _elem_map(row) if row.tag == "table" else {}
            cid = m.get("id") or ""
            if cid.startswith(("CVE", "PRION", "1337DAY", "EDB")):
                cves.append({"id": cid, "cvss": m.get("cvss", ""),
                             "exploit": str(m.get("is_exploit", "")).lower() == "true"})
        if cves:
            groups.append({"cpe": cpe, "cves": cves})
    if not groups:
        out = script.get("output", "") or ""
        cur = None
        for ln in out.splitlines():
            cm = re.match(r"\s*(cpe:/\S+)", ln)
            if cm:
                cur = {"cpe": cm.group(1), "cves": []}
                groups.append(cur)
            vm = re.search(r"(CVE-\d{4}-\d+)\s+([\d.]+)(.*)", ln)
            if vm and cur is not None:
                cur["cves"].append({"id": vm.group(1), "cvss": vm.group(2),
                                    "exploit": "*EXPLOIT*" in vm.group(3).upper()})
    return [g for g in groups if g["cves"]]


def _scripts(elem):
    out = {}
    for sc in elem.findall("script"):
        out[sc.get("id", "")] = {"output": sc.get("output", ""), "elem": sc}
    return out


def parse_nmap_xml(path):
    root = ET.parse(path).getroot()
    meta = {"scanner": root.get("scanner", "nmap"), "version": root.get("version", ""),
            "args": root.get("args", ""), "start": root.get("startstr", "")}
    hosts = []
    for h in root.iter("host"):
        st = h.find("status")
        if st is not None and st.get("state") == "down":
            continue
        ip = ipv6 = mac = vendor = ""
        for a in h.iter("address"):
            t = a.get("addrtype")
            if t == "ipv4": ip = a.get("addr")
            elif t == "ipv6": ipv6 = a.get("addr")
            elif t == "mac":
                mac, vendor = a.get("addr"), a.get("vendor", "")
        names = [hn.get("name", "") for hn in h.iter("hostname") if hn.get("name")]
        os_matches = []
        for om in h.iter("osmatch"):
            oc = om.find("osclass")
            os_matches.append({"name": om.get("name", ""), "accuracy": om.get("accuracy", ""),
                               "family": oc.get("osfamily", "") if oc is not None else "",
                               "type": oc.get("type", "") if oc is not None else ""})
        d = h.find("distance")
        distance = d.get("value", "") if d is not None else ""
        up = h.find("uptime")
        uptime = up.get("seconds", "") if up is not None else ""

        ports = []
        ports_el = h.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state = p.find("state")
                stt = state.get("state") if state is not None else ""
                if stt not in ("open", "open|filtered"):
                    continue
                svc = p.find("service")
                service = {"name": "", "product": "", "version": "", "extrainfo": "",
                           "tunnel": "", "ostype": "", "cpe": []}
                if svc is not None:
                    for k in ("name", "product", "version", "extrainfo", "tunnel", "ostype"):
                        service[k] = svc.get(k, "")
                    service["cpe"] = [c.text for c in svc.findall("cpe") if c.text]
                sc = _scripts(p)
                ssl_enum, least, cert = None, None, None
                if "ssl-enum-ciphers" in sc:
                    ssl_enum, least = _parse_ssl_enum(sc["ssl-enum-ciphers"]["elem"])
                if "ssl-cert" in sc:
                    cert = _parse_ssl_cert(sc["ssl-cert"]["elem"])
                ports.append({
                    "port": int(p.get("portid")), "protocol": p.get("protocol", "tcp"),
                    "state": stt, "reason": state.get("reason", "") if state is not None else "",
                    "service": service, "scripts": sc,
                    "ssl_enum": ssl_enum, "least_strength": least, "cert": cert})
        host_scripts = {}
        hs = h.find("hostscript")
        if hs is not None:
            host_scripts = _scripts(hs)
        hosts.append({"ip": ip, "ipv6": ipv6, "mac": mac, "vendor": vendor,
                      "hostnames": names, "os": os_matches, "distance": distance,
                      "uptime": uptime, "ports": ports, "host_scripts": host_scripts})
    return hosts, meta


def parse_nmap_text(text):
    hosts, cur = [], None
    host_rx = re.compile(r"Nmap scan report for (\S+)(?:\s+\(([\d\.:a-fA-F]+)\))?")
    port_rx = re.compile(r"^(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)\s*(.*)$")
    for ln in text.splitlines():
        m = host_rx.search(ln)
        if m:
            name, ip = m.group(1), m.group(2) or m.group(1)
            cur = {"ip": ip, "ipv6": "", "mac": "", "vendor": "",
                   "hostnames": [name] if name != ip else [], "os": [], "distance": "",
                   "uptime": "", "ports": [], "host_scripts": {}}
            hosts.append(cur)
            continue
        pm = port_rx.match(ln.strip())
        if pm and cur is not None:
            cur["ports"].append({
                "port": int(pm.group(1)), "protocol": pm.group(2), "state": pm.group(3),
                "reason": "", "service": {"name": pm.group(4), "product": pm.group(5).strip(),
                "version": "", "extrainfo": "", "tunnel": "", "ostype": "", "cpe": []},
                "scripts": {}, "ssl_enum": None, "least_strength": None, "cert": None})
    return [h for h in hosts if h["ports"]], {"scanner": "nmap", "args": "(text output)"}


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
from findings import finding as _finding   # canonical finding schema (findings.py)


def _parse_dt(s):
    s = (s or "").strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(s[:19], fmt).replace(tzinfo=timezone.utc)
            except Exception:
                continue
    return None


def _cert_issues(cert):
    issues = []
    if not cert:
        return issues
    dt = _parse_dt(cert.get("not_after", ""))
    if dt:
        days = (dt - datetime.now(timezone.utc)).days
        if days < 0: issues.append(("high", f"TLS certificate EXPIRED ({-days} days ago)"))
        elif days < 30: issues.append(("medium", f"TLS certificate expires in {days} days"))
    bits = cert.get("key_bits", "")
    if cert.get("key_type", "").lower() in ("rsa", "") and bits.isdigit() and int(bits) < 2048:
        issues.append(("high", f"Weak TLS key ({bits}-bit RSA < 2048)"))
    if any(x in cert.get("sig_algo", "").lower() for x in ("md5", "sha1")):
        issues.append(("medium", f"Weak certificate signature ({cert.get('sig_algo')})"))
    if cert.get("subject") and cert.get("subject") == cert.get("issuer"):
        issues.append(("low", "Self-signed TLS certificate"))
    return issues


def _num(x):
    try: return float(x)
    except Exception: return 0.0


def analyze(hosts, exposure=None, business=None, kev_cves=None, epss_map=None, asset_cfg=None):
    findings = []
    risk_cfg = get_risk_config()
    kev_set = {c.upper() for c in (kev_cves or ())}
    for h in hosts:
        label = (h["hostnames"][0] if h["hostnames"] else h["ip"]) or h.get("ipv6") or "?"
        # per-asset exposure/business override (falls back to the global values)
        _ov = (asset_cfg.get(label) or asset_cfg.get(h.get("ip")) or {}) if asset_cfg else {}
        hx = _ov.get("exposure", exposure)
        hb = _ov.get("business", business)
        for p in h["ports"]:
            port, svc = p["port"], p["service"]
            sname = svc.get("name", "")

            risk = service_risk(sname, port, svc.get("product", ""), svc.get("tunnel", ""))
            if risk:
                sev, cat, title, fix = risk
                ver = " ".join(x for x in (svc.get("product"), svc.get("version")) if x)
                findings.append(_finding(label, port, cat, sev, title,
                                         detail=f"{sname} {ver}".strip(), fix=fix))
            elif sname in CLEARTEXT and svc.get("tunnel", "").lower() != "ssl":
                findings.append(_finding(label, port, "Protocol", "low",
                                         f"Cleartext service: {sname}", fix="Use an encrypted equivalent."))

            if "vulners" in p["scripts"]:
                for grp in _parse_vulners(p["scripts"]["vulners"]["elem"]):
                    cves = grp["cves"]
                    maxc = max((_num(c["cvss"]) for c in cves), default=0.0)
                    expl = [c["id"] for c in cves if c["exploit"]]
                    cve_ids = [c["id"] for c in cves]
                    is_kev = any(cid.upper() in kev_set for cid in cve_ids)
                    epss = None
                    if epss_map:
                        _e = [epss_map[cid.upper()] for cid in cve_ids if cid.upper() in epss_map]
                        epss = max(_e) if _e else None
                    score, sev = composite_risk(maxc, epss=epss, exposure=hx, business=hb,
                                                kev=is_kev, public_exploit=bool(expl), cfg=risk_cfg)
                    top = sorted(cves, key=lambda c: (-_num(c["cvss"]), c["id"]))[:8]
                    detail = "; ".join(f"{c['id']} ({c['cvss']}{'*EXPLOIT' if c['exploit'] else ''})"
                                       for c in top)
                    if len(cves) > len(top):
                        detail += f"; +{len(cves)-len(top)} more"
                    detail += f"  [risk {score}/100{', KEV' if is_kev else ''}]"
                    title = (f"{svc.get('product','service')} {svc.get('version','')}".strip()
                             + f": {len(cves)} known CVEs (max CVSS {maxc:g}"
                             + (f", {len(expl)} with public exploits" if expl else "") + ")")
                    findings.append(_finding(
                        label, port, "CVE (vulners)", sev,
                        title, cve=cve_ids, detail=detail,
                        fix="Patch/upgrade the affected software."))

            enum = p.get("ssl_enum") or {}
            for proto in enum:
                pr = PROTOCOL_RISK.get(proto.upper().replace(" ", ""))
                if pr:
                    findings.append(_finding(label, port, "TLS Protocol", pr[0],
                                             f"Insecure protocol enabled: {proto}", pr[1], pr[2],
                                             "Disable; require TLS 1.2+."))
            for proto, data in enum.items():
                for c in data.get("ciphers", []):
                    name = c.get("name", "")
                    if not name:
                        continue
                    _, vulns, _ = rate_cipher(name, [proto])
                    for v in vulns:
                        findings.append(_finding(label, port, "TLS Cipher", v["severity"],
                                                 f"{name}: {v['name']}", v["cve"],
                                                 f"[{proto}] {v['description']}",
                                                 "Remove weak cipher suites."))
                    for w in c.get("warnings", []):
                        findings.append(_finding(label, port, "TLS Cipher", "medium",
                                                 f"{name}: {w}",
                                                 re.findall(r"CVE-\d{4}-\d+", w), f"[{proto}] nmap"))
                for w in data.get("warnings", []):
                    findings.append(_finding(label, port, "TLS Cipher", "medium", w,
                                             re.findall(r"CVE-\d{4}-\d+", w), f"[{proto}] nmap"))
            for sev, txt in _cert_issues(p.get("cert")):
                findings.append(_finding(label, port, "TLS Certificate", sev, txt,
                                         fix="Reissue with strong key/sig; renew."))

            for sid, sc in p["scripts"].items():
                if sid in ("ssl-enum-ciphers", "ssl-cert", "vulners"):
                    continue
                meta = SCRIPT_VULN_META.get(sid)
                for v in _parse_vuln_tables(sc["elem"]):
                    s = v["state"].upper()
                    if "VULNERABLE" not in s or "NOT VULNERABLE" in s:
                        continue
                    name, mcve, sev = meta if meta else (v["title"] or sid, [], "high")
                    findings.append(_finding(label, port, "Vuln scan", sev, name,
                                             sorted(set(v["cves"]) | set(mcve)),
                                             v["title"], "Patch the affected service."))
                if sid == "ftp-anon" and "Anonymous FTP login allowed" in sc["output"]:
                    findings.append(_finding(label, port, "Misconfig", "medium",
                                             "Anonymous FTP login allowed", fix="Disable anonymous access."))
                if sid == "http-default-accounts" and sc["output"].strip():
                    findings.append(_finding(label, port, "Misconfig", "high",
                                             "Default credentials detected", detail=sc["output"][:200],
                                             fix="Change default credentials."))

        for sid, sc in h.get("host_scripts", {}).items():
            meta = SCRIPT_VULN_META.get(sid)
            for v in _parse_vuln_tables(sc["elem"]):
                s = v["state"].upper()
                if "VULNERABLE" not in s or "NOT VULNERABLE" in s:
                    continue
                name, mcve, sev = meta if meta else (v["title"] or sid, [], "high")
                findings.append(_finding(label, 0, "Vuln scan", sev, name,
                                         sorted(set(v["cves"]) | set(mcve)),
                                         v["title"], "Patch the affected service."))

    findings.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f["host"], f["port"]))
    return findings


def host_grade(fs):
    score = sum(SEV_WEIGHT.get(f["severity"], 0) for f in fs)
    if any(f["severity"] == "critical" for f in fs) or score >= 40: return "F", score
    if score >= 20: return "D", score
    if score >= 8: return "C", score
    return ("B", score) if score > 0 else ("A", score)


def build_report(hosts, meta, findings):
    per_host = defaultdict(list)
    for f in findings:
        per_host[f["host"]].append(f)
    sev_counts = Counter(f["severity"] for f in findings)
    svc_dist = Counter()
    open_ports = 0
    for h in hosts:
        for p in h["ports"]:
            open_ports += 1
            svc_dist[p["service"].get("name") or "unknown"] += 1
    try:
        from device_profile import device_class as _device_class
    except Exception:                                                  # pragma: no cover
        _device_class = lambda h: ""
    host_summary = []
    for h in hosts:
        label = (h["hostnames"][0] if h["hostnames"] else h["ip"]) or h.get("ipv6") or "?"
        g, sc = host_grade(per_host.get(label, []))
        os_name = h["os"][0]["name"] if h["os"] else ""
        host_summary.append({"host": label, "ip": h["ip"], "os": os_name, "grade": g,
                             "device_class": _device_class(h),
                             "score": sc, "open_ports": len(h["ports"]),
                             "findings": len(per_host.get(label, []))})
    host_summary.sort(key=lambda x: (-x["score"], x["host"]))
    return {
        "tool": "nmap_analyzer", "version": __version__, "engine": _ENGINE,
        "meta": meta, "generated": datetime.now(timezone.utc).isoformat(),
        "totals": {"hosts": len(hosts), "open_ports": open_ports,
                   "findings": len(findings),
                   "exploitable": sum(1 for f in findings if f["category"] == "CVE (vulners)"
                                      and f["severity"] == "critical")},
        "severity_counts": {s: sev_counts.get(s, 0) for s in SEV_ORDER},
        "service_distribution": svc_dist.most_common(),
        "unique_cves": sorted({c for f in findings for c in f["cve"]}),
        "host_summary": host_summary, "findings": findings, "hosts": hosts,
    }


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #
def export_json(report, path):
    safe = {k: v for k, v in report.items() if k != "hosts"}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(safe, fh, indent=2)


def export_csv(report, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["host", "port", "category", "severity",
                                           "title", "cve", "detail", "fix"])
        w.writeheader()
        for f in report["findings"]:
            r = dict(f); r["cve"] = "; ".join(f["cve"]); w.writerow(r)


def export_html(report, path):
    css = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
           "low": "#8b95a5", "info": "#4c8dff"}
    sc = report["severity_counts"]
    cards = "".join(
        f'<div class="card"><div class="n" style="color:{css[s]}">{sc[s]}</div>{s.title()}</div>'
        for s in SEV_ORDER)
    hs = "".join(
        f"<tr><td>{html.escape(h['host'])}</td><td>{html.escape(h['ip'] or '')}</td>"
        f"<td>{html.escape(h['os'])}</td><td><b>{h['grade']}</b></td>"
        f"<td>{h['open_ports']}</td><td>{h['findings']}</td></tr>"
        for h in report["host_summary"])
    rows = "".join(
        f"<tr><td>{html.escape(f['host'])}{(':'+str(f['port'])) if f['port'] else ''}</td>"
        f"<td>{html.escape(f['category'])}</td>"
        f"<td><span class='sev' style='background:{css.get(f['severity'],'#888')}'>{f['severity'].upper()}</span></td>"
        f"<td>{html.escape(f['title'])}</td>"
        f"<td>{' '.join(f'<span class=cve>{html.escape(c)}</span>' for c in f['cve'][:6])}</td>"
        f"<td>{html.escape(f['fix'])}</td></tr>" for f in report["findings"])
    t = report["totals"]
    doc = f"""<!doctype html><html><head><meta charset=utf-8><title>nmap analysis</title><style>
body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:28px;background:#0d1017;color:#d7dde6}}
h1,h2{{color:#fff}}
table{{border-collapse:collapse;width:100%;margin:14px 0;font-size:13.5px}}
th,td{{border:1px solid #262d3a;padding:7px 9px;text-align:left;vertical-align:top}}
th{{background:#1b212c}} tr:nth-child(even){{background:#141922}}
.sev{{color:#0d1017;padding:2px 8px;border-radius:9px;font-size:11.5px;font-weight:700}}
.cve{{background:#1b212c;border:1px solid #2a3140;padding:1px 6px;border-radius:7px;font-size:11px;margin:0 3px 2px 0;display:inline-block}}
.cards{{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0}}
.card{{background:#151a23;border:1px solid #1f2733;border-radius:12px;padding:12px 20px;min-width:90px}}
.card .n{{font-size:1.7rem;font-weight:800}}</style></head><body>
<h1>nmap Analysis Report</h1>
<p>{html.escape(report['generated'])} &middot; engine {html.escape(report['engine'])} &middot; {html.escape(report['meta'].get('args',''))}</p>
<div class=cards>{cards}
<div class=card><div class=n>{t['hosts']}</div>Hosts</div>
<div class=card><div class=n>{t['open_ports']}</div>Open ports</div>
<div class=card><div class=n>{len(report['unique_cves'])}</div>CVEs</div></div>
<h2>Hosts</h2><table><tr><th>Host</th><th>IP</th><th>OS</th><th>Grade</th><th>Ports</th><th>Findings</th></tr>{hs}</table>
<h2>Findings ({len(report['findings'])})</h2>
<table><tr><th>Target</th><th>Category</th><th>Severity</th><th>Issue</th><th>CVEs</th><th>Remediation</th></tr>{rows}</table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def load_scan(path):
    with open(path, "r", errors="ignore") as fh:
        head = fh.read(4096)
    if "<?xml" in head or "<nmaprun" in head:
        hosts, meta = parse_nmap_xml(path)
        return hosts, meta, "xml"
    hosts, meta = parse_nmap_text(open(path, "r", errors="ignore").read())
    return hosts, meta, "text"


# --------------------------------------------------------------------------- #
# Crisp Tkinter GUI (master-detail)
# --------------------------------------------------------------------------- #
def launch_gui(preload=None, selftest=False):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    BG, PANEL, PANEL2, BORDER = "#0d1017", "#151a23", "#1b212c", "#262d3a"
    TXT, MUTED, ACCENT = "#d7dde6", "#8b95a5", "#4c8dff"
    SEV_FG = {"critical": "#ff5b6e", "high": "#ff8a3d", "medium": "#ffc14a",
              "low": "#9aa4b2", "info": "#5aacff"}
    GRADE_FG = {"F": "#ff5b6e", "D": "#ff8a3d", "C": "#ffc14a", "B": "#9aa4b2", "A": "#7bd88f"}

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(f"Nmap Analyzer  v{__version__}")
            self.geometry("1280x800")
            self.minsize(1040, 640)
            self.configure(bg=BG)
            self.report = None
            self.scan_path = None
            self._cur_host = None
            self._q = queue.Queue()
            self._style()
            self._topbar()
            self._tabs()
            self._statusbar()
            if preload and os.path.isfile(preload):
                self.after(150, lambda: self.analyze_path(preload))
            if selftest:
                self.after(3200, self._selftest)

        def _selftest(self):
            ok = self.report is not None and len(self.find_tree.get_children()) > 0
            print(f"SELFTEST {'OK' if ok else 'FAIL'} | hosts={len(self.host_tree.get_children())} "
                  f"findings={len(self.find_tree.get_children())} "
                  f"services={len(self.svc_tree.get_children())}")
            self.destroy(); sys.exit(0 if ok else 2)

        def _style(self):
            s = ttk.Style(self)
            try: s.theme_use("clam")
            except Exception: pass
            s.configure(".", background=BG, foreground=TXT, fieldbackground=PANEL2,
                        bordercolor=BORDER, font=("TkDefaultFont", 10))
            s.configure("TFrame", background=BG)
            s.configure("Card.TFrame", background=PANEL)
            s.configure("TLabel", background=BG, foreground=TXT)
            s.configure("Card.TLabel", background=PANEL, foreground=TXT)
            s.configure("Muted.TLabel", background=BG, foreground=MUTED)
            s.configure("H1.TLabel", background=BG, foreground="#ffffff", font=("TkDefaultFont", 13, "bold"))
            s.configure("Metric.TLabel", background=PANEL, foreground=TXT, font=("TkDefaultFont", 22, "bold"))
            s.configure("TButton", background=PANEL2, foreground=TXT, borderwidth=0, padding=7)
            s.map("TButton", background=[("active", "#2a3342")])
            s.configure("Accent.TButton", background=ACCENT, foreground="#0d1017")
            s.map("Accent.TButton", background=[("active", "#6ba1ff")])
            s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(6, 6, 0, 0))
            s.configure("TNotebook.Tab", background=BG, foreground=MUTED, padding=(16, 8), borderwidth=0)
            s.map("TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", "#ffffff")])
            s.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TXT,
                        rowheight=27, borderwidth=0)
            s.configure("Treeview.Heading", background=PANEL2, foreground=MUTED, relief="flat", padding=4)
            s.map("Treeview.Heading", background=[("active", PANEL2)])
            s.configure("TCombobox", fieldbackground=PANEL2, background=PANEL2)
            s.configure("TEntry", fieldbackground=PANEL2, foreground=TXT)
            s.configure("Status.TLabel", background=PANEL2, foreground=MUTED)

        def _topbar(self):
            bar = ttk.Frame(self, padding=(12, 10)); bar.pack(fill="x")
            ttk.Button(bar, text="  Open scan  ", style="Accent.TButton",
                       command=self.open_file).pack(side="left")
            ttk.Button(bar, text="Re-analyze", command=self.reanalyze).pack(side="left", padx=(8, 16))
            ttk.Label(bar, text="Filter", style="Muted.TLabel").pack(side="left")
            self.sev_filter = tk.StringVar(value="all")
            ttk.Combobox(bar, textvariable=self.sev_filter, width=9, state="readonly",
                         values=["all"] + SEV_ORDER).pack(side="left", padx=6)
            self.search = tk.StringVar()
            ttk.Entry(bar, textvariable=self.search, width=28).pack(side="left", padx=4)
            ttk.Label(bar, text="search findings", style="Muted.TLabel").pack(side="left")
            for txt, cmd in (("HTML", self.save_html), ("CSV", self.save_csv), ("JSON", self.save_json)):
                ttk.Button(bar, text="\u2193 " + txt, command=cmd).pack(side="right", padx=3)
            self.sev_filter.trace_add("write", lambda *_: self._render_findings())
            self.search.trace_add("write", lambda *_: self._render_findings())

        def _tabs(self):
            self.nb = ttk.Notebook(self)
            self.nb.pack(fill="both", expand=True, padx=10, pady=(0, 6))
            self._tab_dashboard(); self._tab_hosts(); self._tab_findings(); self._tab_services()

        def _tab_dashboard(self):
            f = ttk.Frame(self.nb, padding=14); self.nb.add(f, text="Dashboard")
            row = ttk.Frame(f); row.pack(fill="x")
            self.metric_lbls = {}
            for i, key in enumerate(["Hosts", "Open ports", "Critical", "High", "Medium", "Low", "CVEs"]):
                card = ttk.Frame(row, style="Card.TFrame", padding=(16, 12))
                card.grid(row=0, column=i, padx=5, sticky="nsew")
                n = ttk.Label(card, text="\u2013", style="Metric.TLabel"); n.pack(anchor="w")
                ttk.Label(card, text=key, style="Card.TLabel").pack(anchor="w")
                self.metric_lbls[key] = n
            body = ttk.Frame(f); body.pack(fill="both", expand=True, pady=(14, 0))
            left = ttk.Frame(body); left.pack(side="left", fill="both", expand=True, padx=(0, 7))
            ttk.Label(left, text="Highest-risk hosts", style="H1.TLabel").pack(anchor="w")
            self.top_tree = ttk.Treeview(left, columns=("ip", "os", "grade", "f"),
                                         show="tree headings", height=12)
            self.top_tree.heading("#0", text="Host"); self.top_tree.column("#0", width=190)
            for c, t, w in (("ip", "IP", 120), ("os", "OS", 170), ("grade", "Grade", 60), ("f", "Findings", 70)):
                self.top_tree.heading(c, text=t); self.top_tree.column(c, width=w, anchor="center")
            self.top_tree.pack(fill="both", expand=True)
            for g, col in GRADE_FG.items(): self.top_tree.tag_configure(g, foreground=col)
            right = ttk.Frame(body); right.pack(side="left", fill="both", expand=True, padx=(7, 0))
            ttk.Label(right, text="Service distribution", style="H1.TLabel").pack(anchor="w")
            self.svc_dist = ttk.Treeview(right, columns=("n",), show="tree headings", height=12)
            self.svc_dist.heading("#0", text="Service"); self.svc_dist.column("#0", width=220)
            self.svc_dist.heading("n", text="Open ports"); self.svc_dist.column("n", width=90, anchor="center")
            self.svc_dist.pack(fill="both", expand=True)

        def _tab_hosts(self):
            f = ttk.Frame(self.nb, padding=8); self.nb.add(f, text="Hosts")
            pane = ttk.Panedwindow(f, orient="horizontal"); pane.pack(fill="both", expand=True)
            left = ttk.Frame(pane)
            self.host_tree = ttk.Treeview(left, columns=("grade", "ports"), show="tree headings")
            self.host_tree.heading("#0", text="Host"); self.host_tree.column("#0", width=190)
            self.host_tree.heading("grade", text="Grade"); self.host_tree.column("grade", width=55, anchor="center")
            self.host_tree.heading("ports", text="Ports"); self.host_tree.column("ports", width=55, anchor="center")
            self.host_tree.pack(fill="both", expand=True)
            for g, col in GRADE_FG.items(): self.host_tree.tag_configure(g, foreground=col)
            self.host_tree.bind("<<TreeviewSelect>>", self._on_host_select)
            pane.add(left, weight=1)
            right = ttk.Frame(pane); pane.add(right, weight=3)
            self.host_info = tk.Text(right, height=6, bg=PANEL, fg=TXT, relief="flat",
                                     wrap="word", padx=10, pady=8, insertbackground=TXT)
            self.host_info.pack(fill="x")
            ttk.Label(right, text="Ports & services", style="H1.TLabel").pack(anchor="w", pady=(8, 2))
            self.port_tree = ttk.Treeview(right, columns=("proto", "state", "svc", "ver", "f"),
                                          show="headings", height=9)
            for c, t, w in (("proto", "Proto", 60), ("state", "State", 90), ("svc", "Service", 130),
                            ("ver", "Product / version", 320), ("f", "Findings", 70)):
                self.port_tree.heading(c, text=t); self.port_tree.column(c, width=w, anchor="w")
            self.port_tree.pack(fill="both", expand=True)
            self.port_tree.bind("<<TreeviewSelect>>", self._on_port_select)
            ttk.Label(right, text="NSE script output", style="H1.TLabel").pack(anchor="w", pady=(8, 2))
            self.script_text = tk.Text(right, height=8, bg=PANEL, fg="#cfd6e0", relief="flat",
                                       wrap="word", padx=10, pady=6)
            self.script_text.pack(fill="both", expand=True)

        def _tab_findings(self):
            f = ttk.Frame(self.nb, padding=8); self.nb.add(f, text="Findings")
            pane = ttk.Panedwindow(f, orient="vertical"); pane.pack(fill="both", expand=True)
            top = ttk.Frame(pane)
            self.find_tree = ttk.Treeview(top, columns=("t", "cat", "sev", "title", "cve"), show="headings")
            for c, t, w in (("t", "Target", 150), ("cat", "Category", 130), ("sev", "Sev", 80),
                            ("title", "Issue", 540), ("cve", "CVEs", 180)):
                self.find_tree.heading(c, text=t); self.find_tree.column(c, width=w, anchor="w")
            vs = ttk.Scrollbar(top, orient="vertical", command=self.find_tree.yview)
            self.find_tree.configure(yscrollcommand=vs.set)
            self.find_tree.pack(side="left", fill="both", expand=True); vs.pack(side="right", fill="y")
            for sev, col in SEV_FG.items(): self.find_tree.tag_configure(sev, foreground=col)
            self.find_tree.tag_configure("odd", background=PANEL2)
            self.find_tree.bind("<<TreeviewSelect>>", self._on_finding_select)
            pane.add(top, weight=3)
            self.find_detail = tk.Text(pane, height=7, bg=PANEL, fg=TXT, relief="flat",
                                       wrap="word", padx=10, pady=8)
            pane.add(self.find_detail, weight=1)

        def _tab_services(self):
            f = ttk.Frame(self.nb, padding=8); self.nb.add(f, text="Services")
            self.svc_tree = ttk.Treeview(f, columns=("host", "proto", "svc", "prod", "ver", "cpe"),
                                         show="headings")
            for c, t, w in (("host", "Target", 160), ("proto", "Proto", 60), ("svc", "Service", 130),
                            ("prod", "Product", 200), ("ver", "Version", 130), ("cpe", "CPE", 320)):
                self.svc_tree.heading(c, text=t); self.svc_tree.column(c, width=w, anchor="w")
            vs = ttk.Scrollbar(f, orient="vertical", command=self.svc_tree.yview)
            self.svc_tree.configure(yscrollcommand=vs.set)
            self.svc_tree.pack(side="left", fill="both", expand=True); vs.pack(side="right", fill="y")
            self.svc_tree.tag_configure("odd", background=PANEL2)

        def _statusbar(self):
            self.status = tk.StringVar(value=f"Ready \u00b7 cipher engine: {_ENGINE}")
            ttk.Label(self, textvariable=self.status, style="Status.TLabel",
                      anchor="w", padding=(10, 5)).pack(fill="x", side="bottom")

        # actions
        def open_file(self):
            p = filedialog.askopenfilename(title="Open nmap output",
                filetypes=[("nmap", "*.xml *.nmap *.txt *.out *.gnmap"), ("All", "*.*")])
            if p: self.analyze_path(p)

        def reanalyze(self):
            if self.scan_path: self.analyze_path(self.scan_path)

        def analyze_path(self, path):
            self.scan_path = path
            self.status.set(f"Analyzing {os.path.basename(path)} ...")
            self.update_idletasks()

            def work():
                try:
                    hosts, meta, kind = load_scan(path)
                    if not hosts:
                        self._q.put(("err", "No hosts found in file.")); return
                    rep = build_report(hosts, meta, analyze(hosts))
                    self._q.put(("ok", (rep, kind)))
                except Exception as e:
                    self._q.put(("err", str(e)))
            threading.Thread(target=work, daemon=True).start()
            self.after(80, self._poll)

        def _poll(self):
            try:
                tag, payload = self._q.get_nowait()
            except queue.Empty:
                self.after(80, self._poll); return
            if tag == "err":
                self.status.set("Error: " + payload)
                messagebox.showerror("Error", payload); return
            self.report, self._kind = payload
            self._populate()

        def _populate(self):
            r = self.report; sc = r["severity_counts"]; t = r["totals"]
            for k, v in (("Hosts", t["hosts"]), ("Open ports", t["open_ports"]),
                         ("Critical", sc["critical"]), ("High", sc["high"]),
                         ("Medium", sc["medium"]), ("Low", sc["low"]), ("CVEs", len(r["unique_cves"]))):
                self.metric_lbls[k].config(text=str(v))
            self.top_tree.delete(*self.top_tree.get_children())
            for h in r["host_summary"][:30]:
                self.top_tree.insert("", "end", text=h["host"], tags=(h["grade"],),
                                     values=(h["ip"] or "", h["os"][:40], h["grade"], h["findings"]))
            self.svc_dist.delete(*self.svc_dist.get_children())
            for name, n in r["service_distribution"]:
                self.svc_dist.insert("", "end", text=name, values=(n,))
            self.host_tree.delete(*self.host_tree.get_children())
            for h in r["host_summary"]:
                self.host_tree.insert("", "end", iid=h["host"], text=h["host"], tags=(h["grade"],),
                                      values=(h["grade"], h["open_ports"]))
            self.svc_tree.delete(*self.svc_tree.get_children())
            for i, h in enumerate(r["hosts"]):
                label = (h["hostnames"][0] if h["hostnames"] else h["ip"]) or "?"
                for p in h["ports"]:
                    s = p["service"]
                    self.svc_tree.insert("", "end", tags=("odd" if i % 2 else "even",),
                        values=(f"{label}:{p['port']}", p["protocol"], s.get("name", ""),
                                s.get("product", ""), s.get("version", ""), ", ".join(s.get("cpe", []))))
            self._render_findings()
            if r["host_summary"]:
                self.host_tree.selection_set(r["host_summary"][0]["host"])
                self._on_host_select(None)
            self.status.set(
                f"{os.path.basename(self.scan_path)} ({self._kind}) \u00b7 {t['hosts']} hosts \u00b7 "
                f"{t['open_ports']} open ports \u00b7 {t['findings']} findings \u00b7 "
                f"{len(r['unique_cves'])} CVEs")

        def _render_findings(self):
            if not self.report: return
            self.find_tree.delete(*self.find_tree.get_children())
            sev = self.sev_filter.get(); term = self.search.get().lower().strip()
            i = 0
            for idx, f in enumerate(self.report["findings"]):
                if sev != "all" and f["severity"] != sev: continue
                blob = (f["title"] + f["detail"] + f["host"] + " ".join(f["cve"]) + f["category"]).lower()
                if term and term not in blob: continue
                tags = (f["severity"],) + (("odd",) if i % 2 else ())
                tgt = f"{f['host']}:{f['port']}" if f["port"] else f["host"]
                self.find_tree.insert("", "end", iid=str(idx), tags=tags,
                    values=(tgt, f["category"], f["severity"].upper(), f["title"], ", ".join(f["cve"][:5])))
                i += 1

        def _on_finding_select(self, _):
            sel = self.find_tree.selection()
            if not sel: return
            f = self.report["findings"][int(sel[0])]
            self.find_detail.delete("1.0", "end")
            self.find_detail.insert("end",
                f"{f['title']}\n\nTarget   : {f['host']}{(':'+str(f['port'])) if f['port'] else ''}\n"
                f"Category : {f['category']}\nSeverity : {f['severity'].upper()}\n"
                f"CVEs     : {', '.join(f['cve']) or '-'}\n"
                f"Detail   : {f['detail'] or '-'}\nFix      : {f['fix'] or '-'}")

        def _on_host_select(self, _):
            sel = self.host_tree.selection()
            if not sel or not self.report: return
            label = sel[0]
            host = next((h for h in self.report["hosts"]
                         if ((h["hostnames"][0] if h["hostnames"] else h["ip"]) or "?") == label), None)
            if not host: return
            self._cur_host = host
            self.host_info.delete("1.0", "end")
            os_s = ", ".join(f"{o['name']} ({o['accuracy']}%)" for o in host["os"][:2]) or "\u2014"
            self.host_info.insert("end",
                f"{label}\n  IP: {host['ip'] or '-'}   IPv6: {host['ipv6'] or '-'}   "
                f"MAC: {host['mac'] or '-'} {host['vendor']}\n"
                f"  Hostnames: {', '.join(host['hostnames']) or '-'}\n"
                f"  OS: {os_s}\n  Distance: {host['distance'] or '-'} hops")
            per_port_f = Counter(fd["port"] for fd in self.report["findings"] if fd["host"] == label)
            self.port_tree.delete(*self.port_tree.get_children())
            for p in host["ports"]:
                s = p["service"]
                ver = " ".join(x for x in (s.get("product"), s.get("version"), s.get("extrainfo")) if x)
                self.port_tree.insert("", "end", iid=str(p["port"]),
                    values=(p["protocol"], p["state"], s.get("name", ""), ver, per_port_f.get(p["port"], 0)))
            self.script_text.delete("1.0", "end")
            self.script_text.insert("end", "Select a port to view its NSE script output.")

        def _on_port_select(self, _):
            sel = self.port_tree.selection()
            if not sel or not self._cur_host: return
            port = int(sel[0])
            p = next((x for x in self._cur_host["ports"] if x["port"] == port), None)
            self.script_text.delete("1.0", "end")
            if not p or not p["scripts"]:
                self.script_text.insert("end", "(no NSE scripts on this port)"); return
            for sid, sc in p["scripts"].items():
                self.script_text.insert("end", f"\u250c\u2500 {sid}\n")
                out = (sc["output"] or "").strip()
                self.script_text.insert("end", "\n".join("\u2502  " + l for l in out.splitlines()) + "\n\n")

        def _ok(self):
            if not self.report:
                messagebox.showinfo("No data", "Open and analyze a scan first."); return False
            return True

        def save_json(self):
            if self._ok():
                p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
                if p: export_json(self.report, p); self.status.set("Saved " + p)

        def save_csv(self):
            if self._ok():
                p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
                if p: export_csv(self.report, p); self.status.set("Saved " + p)

        def save_html(self):
            if self._ok():
                p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
                if p: export_html(self.report, p); self.status.set("Saved " + p)

    App().mainloop()


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Full-spectrum nmap analyzer (GUI + headless).")
    ap.add_argument("file", nargs="?", help="nmap XML or normal-text output")
    ap.add_argument("--no-gui", action="store_true")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--csv", dest="csv_out")
    ap.add_argument("--html", dest="html_out")
    ap.add_argument("--selftest", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--version", action="version", version=f"nmap_analyzer {__version__}")
    args = ap.parse_args()

    if args.no_gui:
        if not args.file:
            ap.error("--no-gui requires a file")
        hosts, meta, kind = load_scan(args.file)
        report = build_report(hosts, meta, analyze(hosts))
        if args.json_out: export_json(report, args.json_out); print("[+] JSON:", args.json_out)
        if args.csv_out: export_csv(report, args.csv_out); print("[+] CSV :", args.csv_out)
        if args.html_out: export_html(report, args.html_out); print("[+] HTML:", args.html_out)
        sc, t = report["severity_counts"], report["totals"]
        print(f"[+] {t['hosts']} hosts \u00b7 {t['open_ports']} open ports \u00b7 {t['findings']} findings "
              f"(crit={sc['critical']} high={sc['high']} med={sc['medium']} low={sc['low']}) \u00b7 "
              f"{len(report['unique_cves'])} CVEs ({t['exploitable']} exploitable)")
        if not any([args.json_out, args.csv_out, args.html_out]):
            print(json.dumps(report["host_summary"], indent=2))
        return
    launch_gui(preload=args.file, selftest=args.selftest)


if __name__ == "__main__":
    main()
