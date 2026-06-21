#!/usr/bin/env python3
"""modules.vnc — VNC assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class VNCModule(SpecModule):
    name = "vnc"
    title = "VNC"
    NAMES = ("vnc", "vnc-http")
    UNAUTH = ("vnc",)
    SUMMARY = "VNC service ({prod})."
    KEYWORDS = ("vnc", "realvnc", "tightvnc", "ultravnc")
    EXTRA_TECH = ("T1021.005",)
    SURFACE = (
        ("always", "VNC often has weak/no authentication and weak crypto — tunnel over SSH/VPN and enforce strong auth."),
        ("unauth", "VNC may allow unauthenticated screen access — verify before assuming protection."),
    )
    CHECKS = (
        ("Auth type", "T1592.004", "nmap -p{port} --script vnc-info {ip}", "Enumerate the VNC protocol version and supported security types (incl. None)."),
        ("None-auth check", "T1078", "vncviewer {ip}:{port}", "Test for unauthenticated screen access (authorized)."),
        ("Auth bypass detect", "T1595.002", "nmap -p{port} --script realvnc-auth-bypass {ip}", "Detection for the RealVNC auth-bypass (CVE-2006-2369)."),
        ("Credential test", "T1110.003", "hydra -P passwords.txt vnc://{ip}:{port} -f", "Authorized testing for weak VNC passwords (mind lockout)."),
    )
