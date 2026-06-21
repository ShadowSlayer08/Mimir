#!/usr/bin/env python3
"""modules.proxy — open-proxy methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class ProxyModule(SpecModule):
    name = "proxy"
    title = "Open Proxy"
    NAMES = ("socks", "socks5", "socks4")
    UNAUTH = ("socks", "socks5", "socks4")
    SUMMARY = "Proxy service ({frag})."
    KEYWORDS = ("socks", "proxy")
    EXTRA_TECH = ("T1090",)
    SURFACE = (
        ("unauth", "An open/unauthenticated proxy enables anonymisation and pivoting into internal networks — require authentication and ACLs."),
    )
    CHECKS = (
        ("Open relay test", "T1090", "curl -sx socks5://{ip}:{port} http://example.com", "Test whether the proxy relays to external hosts unauthenticated."),
        ("Internal pivot", "T1572", "curl -sx socks5://{ip}:{port} http://<internal-ip>/", "Check reachability of internal hosts through the proxy (authorized)."),
        ("Auth requirement", "T1592", "nmap -p{port} --script socks-auth-info,socks-open-proxy {ip}", "Determine the SOCKS version and whether authentication is enforced."),
        ("Proxy fingerprint", "T1592.002", "nmap -p{port} -sV {ip}", "Identify the proxy software and version."),
    )
