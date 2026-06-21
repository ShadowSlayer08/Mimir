#!/usr/bin/env python3
"""modules.finger — finger assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class FingerModule(SpecModule):
    name = "finger"
    title = "finger"
    NAMES = ("finger",)
    SUMMARY = "finger service ({prod})."
    KEYWORDS = ("finger",)
    EXTRA_TECH = ("T1087",)
    SURFACE = (
        ("always", "finger discloses usernames, login times and home dirs — useful for building a spraying list; disable it."),
    )
    CHECKS = (
        ("User listing", "T1087", "finger @{ip}", "List currently logged-in users."),
        ("Account probe", "T1087", "finger root@{ip}", "Probe specific accounts for existence and details."),
        ("NSE enumeration", "T1087", "nmap -p{port} --script finger {ip}", "Enumerate users via the finger NSE script."),
        ("Bulk enumeration", "T1589", "finger-user-enum -U users.txt -t {ip}", "Enumerate valid usernames in bulk for later spraying."),
    )
