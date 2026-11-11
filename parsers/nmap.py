"""parsers.nmap — extract hosts + open services from nmap stdout.

Supports the two most common nmap output modes operators pipe through Autopilot:
  * default text ("Nmap scan report for ...")
  * grepable (-oG)

XML (-oX) is already handled by `nmap_analyzer.py`; this parser is the fast
path for stdout-captured runs. For -oX output we delegate to nmap_analyzer.
"""
from __future__ import annotations

import re
from .base import ParseResult


_HOST_HEADER_RE = re.compile(
    r"^Nmap scan report for\s+(?P<name>\S+)(?:\s+\((?P<ip>[0-9a-f.:]+)\))?",
    re.M | re.I)
_PORT_LINE_RE = re.compile(
    r"^(?P<port>\d{1,5})/(?P<proto>tcp|udp)\s+open\s+(?P<service>\S+)"
    r"(?:\s+(?P<version>.+))?$",
    re.M | re.I)
_GREP_PORTS_RE = re.compile(
    r"Host:\s+(?P<ip>\S+)\s+.*?Ports:\s+(?P<ports>[^\n]+)", re.I)
_GREP_PORT_ITEM_RE = re.compile(
    r"(?P<port>\d+)/open/(?P<proto>tcp|udp)//(?P<service>[^/]+)/",
    re.I)


def _host_from_header(match):
    name = (match.group("name") or "").strip()
    ip = (match.group("ip") or "").strip()
    return ip or name


def parse(stdout, stderr="", exit_code=0):
    """Return a ParseResult populated with hosts + open services from nmap
    stdout. stderr is checked for XML indicator; if the operator redirected
    XML output into stdout we delegate to nmap_analyzer."""
    r = ParseResult(source_tool="nmap")
    text = stdout or ""

    # Delegate XML to the real analyzer.
    if text.lstrip().startswith("<?xml") or "<nmaprun" in text[:4096]:
        try:
            import tempfile, os
            from nmap_analyzer import analyze_file
            fd, p = tempfile.mkstemp(suffix=".xml", prefix="autopilot-nmap-")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(text)
                rep = analyze_file(p)
                for h in (rep.get("hosts") or []):
                    addr = h.get("address") or h.get("ip") or ""
                    if addr and addr not in r.new_hosts:
                        r.new_hosts.append(addr)
                    for pt in (h.get("ports") or []):
                        r.new_services.append({
                            "host": addr, "port": pt.get("port"),
                            "proto": pt.get("protocol", "tcp"),
                            "service": pt.get("service", ""),
                            "version": pt.get("version", "")})
            finally:
                try:
                    os.unlink(p)
                except OSError:
                    pass
        except Exception:
            pass
        return r

    # Default text output: iterate host blocks.
    hosts = []
    for m in _HOST_HEADER_RE.finditer(text):
        hosts.append((m.start(), _host_from_header(m)))
    hosts.append((len(text), ""))                                   # sentinel
    for i in range(len(hosts) - 1):
        start, host = hosts[i]
        end = hosts[i + 1][0]
        if not host:
            continue
        if host not in r.new_hosts:
            r.new_hosts.append(host)
        for pm in _PORT_LINE_RE.finditer(text[start:end]):
            r.new_services.append({
                "host": host,
                "port": int(pm.group("port")),
                "proto": (pm.group("proto") or "tcp").lower(),
                "service": (pm.group("service") or "").strip(),
                "version": (pm.group("version") or "").strip(),
            })

    # Grepable (-oG).
    for gm in _GREP_PORTS_RE.finditer(text):
        ip = gm.group("ip").strip()
        if ip and ip not in r.new_hosts:
            r.new_hosts.append(ip)
        for pm in _GREP_PORT_ITEM_RE.finditer(gm.group("ports") or ""):
            r.new_services.append({
                "host": ip,
                "port": int(pm.group("port")),
                "proto": (pm.group("proto") or "tcp").lower(),
                "service": (pm.group("service") or "").strip(),
                "version": "",
            })

    return r
