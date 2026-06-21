#!/usr/bin/env python3
"""modules.cisco_smi — Cisco Smart Install methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class CiscoSMIModule(SpecModule):
    name = "cisco_smi"
    title = "Cisco Smart Install"
    NAMES = ("smart-install", "smi")
    UNAUTH = ("smart-install", "smi")
    SUMMARY = "Cisco Smart Install ({prod}) exposed."
    KEYWORDS = ("smart install", "smi", "vstack")
    EXTRA_TECH = ("T1602.002",)
    SURFACE = (
        ("always", "Smart Install (TCP 4786) is unauthenticated — config/IOS theft or replacement is possible. Disable with 'no vstack'."),
    )
    CHECKS = (
        ("Exposure check", "T1046", "nmap -p4786 -sV {ip}", "Confirm Smart Install is listening (unauthenticated)."),
        ("Config retrieval", "T1602.002", "python3 SIET.py -i {ip} -g", "Pull the running config over SMI (authorized; configs leak credentials)."),
        ("Hardening verify", "T1592.004", "ssh {ip} 'show vstack config'", "Confirm whether Smart Install is enabled; 'no vstack' disables it."),
    )
