#!/usr/bin/env python3
"""modules.aaa — RADIUS / TACACS+ methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class AAAModule(SpecModule):
    name = "aaa"
    title = "AAA (RADIUS / TACACS+)"
    NAMES = ("radius", "radiusacct", "tacacs")
    SUMMARY = "{disp} AAA service ({prod})."
    KEYWORDS = ("radius", "tacacs", "aaa", "shared secret")
    LABELS = {"radius": "RADIUS", "radiusacct": "RADIUS Accounting", "tacacs": "TACACS+"}
    EXTRA_TECH = ("T1110.002",)
    SURFACE = (
        ("always", "AAA shared secrets are often weak/reused; a captured exchange can be cracked offline to forge auth."),
    )
    CHECKS = (
        ("Service detection", "T1046", "nmap -sU -sV -p1812,1813 {ip}; nmap -p49 -sV {ip}", "Confirm RADIUS/TACACS+ and version."),
        ("Shared-secret test", "T1110", "# send Access-Request with a candidate secret (radtest / eapol_test)", "Test for default/weak RADIUS shared secrets (authorized)."),
        ("Offline cracking", "T1110.002", "# capture an exchange, then crack the shared secret offline (hashcat)", "Recover the shared secret from a captured exchange."),
    )
