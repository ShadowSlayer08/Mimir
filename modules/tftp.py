#!/usr/bin/env python3
"""modules.tftp — TFTP assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class TFTPModule(SpecModule):
    name = "tftp"
    title = "TFTP"
    NAMES = ("tftp",)
    UNAUTH = ("tftp",)
    SUMMARY = "TFTP service ({prod}) — no authentication."
    KEYWORDS = ("tftp",)
    EXTRA_TECH = ("T1602",)
    SURFACE = (
        ("always", "TFTP has no authentication — device configs/firmware (often with credentials) may be readable or overwritable."),
        ("unauth", "Test for well-known file reads and write access."),
    )
    CHECKS = (
        ("Filename enumeration", "T1083", "nmap -sU -p{port} --script tftp-enum {ip}", "Probe for well-known TFTP filenames (configs/firmware)."),
        ("Config read", "T1602.002", "tftp {ip} -c get running-config", "Attempt to read device configuration files that leak credentials."),
        ("Firmware read", "T1592", "tftp {ip} -c get firmware.bin", "Retrieve firmware images for offline analysis."),
        ("Write test", "T1565", "# authorized: tftp {ip} -c put testfile  (verify writable, then remove)", "Determine whether arbitrary writes are accepted."),
    )
