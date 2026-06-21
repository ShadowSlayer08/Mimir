#!/usr/bin/env python3
"""modules.snmp — SNMP assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class SNMPModule(SpecModule):
    name = "snmp"
    title = "SNMP"
    NAMES = ("snmp",)
    UNAUTH = ("snmp",)
    SUMMARY = "SNMP service ({prod})."
    KEYWORDS = ("snmp", "community", "public", "private")
    EXTRA_TECH = ("T1602.001",)
    SURFACE = (
        ("always", "SNMP v1/v2c community strings are cleartext and often default (public/private) — migrate to SNMPv3."),
        ("unauth", "Default/guessable community strings expose system, routing, process and credential data."),
    )
    CHECKS = (
        ("Community brute", "T1110", "onesixtyone -c community.txt {ip}", "Discover valid SNMP community strings."),
        ("MIB walk", "T1602.001", "snmpwalk -v2c -c public {ip}", "Dump the full MIB — system info, interfaces, routes, processes."),
        ("System enumeration", "T1082", "snmp-check -c public {ip}", "Structured extraction of users, software, network and storage."),
        ("User accounts", "T1087", "snmpwalk -v2c -c public {ip} 1.3.6.1.4.1.77.1.2.25", "Enumerate Windows local user accounts via the LanMgr MIB."),
        ("v3 user enum", "T1087", "nmap -sU -p{port} --script snmp-info {ip}", "Enumerate SNMPv3 engine IDs / usernames where v1/v2c is disabled."),
    )
