#!/usr/bin/env python3
"""modules.voip — VoIP / SIP methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class VoIPModule(SpecModule):
    name = "voip"
    title = "VoIP / SIP"
    NAMES = ("sip", "sips", "h323", "h323q931", "iax", "mgcp")
    TLS_PORTS = (5061,)
    SUMMARY = "VoIP service ({frag})."
    KEYWORDS = ("sip", "voip", "h323", "asterisk")
    EXTRA_TECH = ("T1590",)
    SURFACE = (
        ("not_tls", "SIP signalling in cleartext exposes credentials and call metadata; enforce SIP/TLS + SRTP."),
        ("has_cve", "PBX/SIP server version has known CVEs (see findings)."),
    )
    CHECKS = (
        ("Methods / options", "T1592", "nmap -sU -p{port} --script sip-methods {ip}", "Enumerate supported SIP methods and the server banner."),
        ("Extension enum", "T1087", "svwar -m INVITE -e 100-999 {ip}", "Enumerate valid SIP extensions (sipvicious)."),
        ("Device discovery", "T1046", "svmap {ip}", "Discover SIP devices/PBXes on the target."),
        ("Registrar auth", "T1110", "svcrack -u <ext> -d passwords.txt {ip}", "Authorized credential testing against the SIP registrar (mind lockout)."),
        ("TLS posture", "T1595", "sslscan {ip}:{port}", "For SIP/TLS (5061), enumerate protocols/ciphers/cert.", "tls"),
    )
