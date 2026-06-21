#!/usr/bin/env python3
"""modules.rsync — rsync-daemon methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class RsyncModule(SpecModule):
    name = "rsync"
    title = "rsync"
    NAMES = ("rsync",)
    UNAUTH = ("rsync",)
    SUMMARY = "rsync daemon ({prod}) reachable."
    KEYWORDS = ("rsync",)
    EXTRA_TECH = ("T1135",)
    SURFACE = (
        ("unauth", "rsync modules are frequently world-readable/writable without authentication — enumerate and test each module."),
    )
    CHECKS = (
        ("Module listing", "T1135", "rsync rsync://{ip}:{port}/", "List available rsync modules (shares)."),
        ("Anonymous read", "T1039", "rsync -av rsync://{ip}:{port}/<module>/ ./loot/", "Test anonymous read access and inventory exposed data (authorized)."),
        ("Write test", "T1565", "# authorized: rsync ./test rsync://{ip}:{port}/<module>/  (then remove)", "Determine whether a module is writable."),
        ("NSE enumeration", "T1135", "nmap -p{port} --script rsync-list-modules {ip}", "Enumerate modules and auth requirements via NSE."),
    )
