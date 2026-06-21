#!/usr/bin/env python3
"""modules.afp — Apple Filing Protocol (548) methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class AFPModule(SpecModule):
    name = "afp"
    title = "AFP (Apple Filing Protocol)"
    NAMES = ("afp", "afpovertcp")
    UNAUTH = ("afp", "afpovertcp")
    SUMMARY = "AFP file sharing ({prod})."
    KEYWORDS = ("afp", "netatalk", "time machine")
    EXTRA_TECH = ("T1135",)
    SURFACE = (
        ("always", "AFP may allow guest access and exposes server/share metadata; old Netatalk has critical RCE CVEs (CVE-2018-1160)."),
        ("has_cve", "AFP server version has known CVEs (see findings)."),
    )
    CHECKS = (
        ("Server info & shares", "T1135", "nmap -p548 --script afp-serverinfo,afp-showmount {ip}", "Enumerate AFP server info and exported volumes."),
        ("Guest access", "T1078", "nmap -p548 --script afp-ls {ip}", "List volume contents as the guest user where allowed."),
        ("Path-vuln check", "T1595.002", "nmap -p548 --script afp-path-vuln {ip}", "Detection for the AFP directory-traversal vulnerability."),
        ("Credential test", "T1110.003", "hydra -L users.txt -P passwords.txt afp://{ip} -f", "Authorized testing for weak AFP credentials (mind lockout)."),
    )
