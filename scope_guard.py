#!/usr/bin/env python3
"""scope_guard.py — dial-time scope re-check.

Phase 28 fix for a real class of autonomous-mode foot-guns: ROE's scope
gate says "10.0.0.0/24 is in scope," the operator stages
`nmap target.corp.lab`, and by the time autopilot fires the subprocess,
`target.corp.lab`'s DNS has returned 203.0.113.42. The step runs OUTSIDE
scope and we never noticed.

ARTEX calls this out in ADR-002. The fix is the same shape there and
here: re-resolve every hostname in the command AT subprocess-spawn time
and refuse if any resolved address falls outside the ROE's in-scope
CIDRs.

This module is deliberately conservative:
  * It only kicks in when `roe_rules` carries a non-empty `in_scope` list
    AND at least one rule is a CIDR (bare IP or network). Rules that are
    bare hostnames or suffix-globs are a fuzzy match and we leave them to
    the existing step-emit-time check.
  * It never calls network functions other than `socket.getaddrinfo` (no
    HTTP, no DNS libraries, no gRPC).
  * It swallows errors and returns ok=True for "unable to resolve" — this
    gate is a safety net, not the only one. The emit-time ROE gate is
    still authoritative. If an attacker can also break getaddrinfo, the
    operator has a much bigger problem than Mimir.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse


# Strip quoting and shell operators when harvesting hostnames.
_URL_RE = re.compile(r"https?://([A-Za-z0-9._-]+)(?::\d+)?[/\s]", re.I)
_HOST_ARG_RE = re.compile(
    r"(?<![A-Za-z0-9_-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})",
    re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _hostnames_in(cmd):
    """Return every hostname-looking token in a command. IPs are included
    too (they go through the same in-scope check)."""
    if not cmd:
        return []
    out = []
    # URLs first — grab the hostname, not the whole URL.
    for m in _URL_RE.finditer(cmd + " "):
        out.append(m.group(1))
    # Bare FQDNs in argument positions.
    for m in _HOST_ARG_RE.finditer(cmd):
        token = m.group(1)
        if token not in out:
            out.append(token)
    # Bare IPs.
    for m in _IP_RE.finditer(cmd):
        if m.group(0) not in out:
            out.append(m.group(0))
    return out


def _parse_in_scope_cidrs(rules):
    """Return the list of CIDR networks in rules['in_scope']. Skips bare
    hostnames and suffix-globs — those are handled by the emit-time gate."""
    nets = []
    for entry in (rules.get("in_scope") or []):
        s = (entry or "").strip()
        if not s:
            continue
        # Single IP.
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
            continue
        except ValueError:
            pass
        # Not a CIDR — leave it.
    return nets


def _resolve(host):
    """Return the set of resolved IP strings. Empty set on resolution
    failure."""
    out = set()
    try:
        for fam, _st, _pr, _cn, sa in socket.getaddrinfo(host, None):
            if fam in (socket.AF_INET, socket.AF_INET6):
                out.add(sa[0])
    except (socket.gaierror, OSError):
        return set()
    return out


def check(command, roe_rules):
    """Return (ok, reason, resolved_map).

    ok=False means at least one hostname resolved to something that's not
    inside any of the ROE's in-scope CIDRs. `resolved_map` is a
    {hostname: [ip, ...]} dict for the audit trail.

    When the ROE carries no CIDR-shaped in_scope rules, this gate is a
    no-op: ok=True, reason="no_cidr_scope". Callers must treat that as
    a soft pass — the emit-time ROE gate is still authoritative.
    """
    resolved = {}
    if not roe_rules:
        return True, "no_roe", resolved
    nets = _parse_in_scope_cidrs(roe_rules)
    if not nets:
        return True, "no_cidr_scope", resolved
    hosts = _hostnames_in(command or "")
    if not hosts:
        return True, "no_hosts_in_cmd", resolved
    # Resolve each hostname. Bare IPs resolve to themselves.
    for host in hosts:
        try:
            ipaddress.ip_address(host)
            resolved[host] = {host}
            continue
        except ValueError:
            pass
        resolved[host] = _resolve(host)
    for host, ips in resolved.items():
        if not ips:
            continue                                               # see docstring
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not any(addr in net for net in nets):
                return (False,
                        f"scope_drift:{host}->{ip} not in in_scope CIDRs",
                        resolved)
    return True, "ok", resolved
