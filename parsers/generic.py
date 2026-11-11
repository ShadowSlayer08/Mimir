"""parsers.generic — regex fallback that extracts hosts, URLs, and CVEs from
   anything. Used when no dedicated parser matches the command prefix.

Deliberately conservative: it only produces a finding for a CVE reference,
and only emits a host/URL when it looks real. It never invents severities —
CVEs land as 'info' with the regex-extracted CVE id; the operator (or a later
enrichment pass) raises severity using KEV/EPSS feeds.
"""
from __future__ import annotations

import re
import ipaddress
from urllib.parse import urlparse
from .base import ParseResult


_IPV4_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.I)
_HOSTNAME_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
_URL_RE = re.compile(
    r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def _is_valid_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def parse(stdout, stderr="", exit_code=0):
    r = ParseResult(source_tool="generic")
    text = (stdout or "") + "\n" + (stderr or "")

    for m in _IPV4_RE.finditer(text):
        ip = m.group(0)
        if _is_valid_ip(ip) and ip not in r.new_hosts:
            # skip obvious localhost / broadcast / zero / loopback
            if ip in ("0.0.0.0", "255.255.255.255") or ip.startswith(("127.", "169.254.")):
                continue
            r.new_hosts.append(ip)

    for m in _IPV6_RE.finditer(text):
        ip = m.group(0)
        if _is_valid_ip(ip) and ip not in r.new_hosts and "::" in ip or ip.count(":") >= 2:
            if ip not in r.new_hosts and _is_valid_ip(ip):
                r.new_hosts.append(ip)

    for m in _HOSTNAME_RE.finditer(text):
        h = m.group(0).lower().rstrip(".")
        # Filter out obvious noise (log timestamps, filenames).
        if h.endswith((".log", ".txt", ".xml", ".json", ".py", ".exe", ".dll")):
            continue
        if h not in r.new_hosts and len(h) <= 253:
            r.new_hosts.append(h)

    for m in _URL_RE.finditer(text):
        try:
            host = urlparse(m.group(0)).hostname or ""
        except Exception:
            host = ""
        if host and host not in r.new_hosts:
            r.new_hosts.append(host)

    seen_cves = set()
    for m in _CVE_RE.finditer(text):
        cve = m.group(0).upper()
        if cve in seen_cves:
            continue
        seen_cves.add(cve)
        r.new_findings.append({
            "host": "",
            "port": None,
            "severity": "info",
            "category": "CVE (regex)",
            "title": cve,
            "cve": cve,
            "owasp": "",
            "cwe": "",
            "exploit_refs": [],
            "source_tool": "generic",
        })

    return r
