#!/usr/bin/env python3
"""modules.rdp — RDP assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class RDPModule(SpecModule):
    name = "rdp"
    title = "RDP (Remote Desktop)"
    NAMES = ("ms-wbt-server", "rdp")
    TLS_PORTS = (3389,)
    SUMMARY = "RDP service ({prod})."
    KEYWORDS = ("rdp", "ms-wbt", "bluekeep", "ms12-020")
    EXTRA_TECH = ("T1021.001",)
    SURFACE = (
        ("always", "RDP exposed to the network — restrict to VPN/jump host and enforce NLA + MFA."),
        ("has_cve", "RDP stack version has known CVEs (e.g. BlueKeep CVE-2019-0708); confirm patch level."),
    )
    CHECKS = (
        ("Encryption & NLA", "T1592.004", "nmap -p{port} --script rdp-enum-encryption,rdp-ntlm-info {ip}", "Determine security layer, encryption level, NLA enforcement and leaked names."),
        ("Known-vuln detect", "T1595.002", "nmap -p{port} --script rdp-vuln-ms12-020 {ip}", "Detection-only check for known pre-auth RDP vulnerabilities."),
        ("Certificate review", "T1592", "openssl s_client -connect {ip}:{port}", "Inspect the RDP TLS certificate (self-signed, hostname, expiry)."),
        ("Credential test", "T1110.003", "crowbar -b rdp -s {ip}/32 -u <user> -C passwords.txt -p {port}", "Authorized credential testing against RDP (mind lockout)."),
        ("Authenticated connect", "T1021.001", "xfreerdp /v:{ip}:{port} /u:<user> /p:<pass> +clipboard", "Validate interactive access with tested credentials (authorized)."),
    )
