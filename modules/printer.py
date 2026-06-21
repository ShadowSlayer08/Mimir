#!/usr/bin/env python3
"""modules.printer — network printer methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class PrinterModule(SpecModule):
    name = "printer"
    title = "Network Printer"
    NAMES = ("jetdirect", "printer", "ipp", "hp-pjl", "pdl-datastream", "lpd")
    SUMMARY = "Network printer service ({frag})."
    KEYWORDS = ("printer", "jetdirect", "pjl", "ipp", "lpd")
    EXTRA_TECH = ("T1213",)
    SURFACE = (
        ("always", "Printers store credentials (LDAP/SMB/email) and documents; PJL/PostScript can expose the filesystem."),
    )
    CHECKS = (
        ("Printer fingerprint", "T1592.002", "nmap -p{port} -sV {ip}", "Identify model/firmware for known default creds and CVEs."),
        ("PJL enumeration", "T1213", "pret {ip} pjl", "Enumerate the printer via PJL (filesystem, NVRAM, stored jobs)."),
        ("PostScript access", "T1213", "pret {ip} ps", "Test PostScript filesystem access and stored-job retrieval."),
        ("IPP attributes", "T1592", "ipptool -tv ipp://{ip}:{port}/ipp/print get-printer-attributes.test", "Read IPP printer attributes and capabilities."),
        ("SNMP cross-ref", "T1602.001", "snmpwalk -v2c -c public {ip}", "Pull stored credentials/config exposed over the printer's SNMP MIB."),
    )
