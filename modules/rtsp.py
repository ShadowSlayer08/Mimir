#!/usr/bin/env python3
"""modules.rtsp — RTSP / IP-camera (554) methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class RTSPModule(SpecModule):
    name = "rtsp"
    title = "RTSP (IP Camera)"
    NAMES = ("rtsp", "rtspu")
    UNAUTH = ("rtsp",)
    SUMMARY = "RTSP streaming service ({prod})."
    KEYWORDS = ("rtsp", "camera", "nvr", "hikvision", "dahua")
    EXTRA_TECH = ("T1078.001",)
    SURFACE = (
        ("always", "IP cameras/NVRs ship with default credentials and well-known RTSP stream paths; many have firmware auth-bypass CVEs."),
        ("has_cve", "Camera firmware has known CVEs (see findings)."),
    )
    CHECKS = (
        ("Methods & info", "T1592", "nmap -p554 --script rtsp-methods {ip}", "Enumerate supported RTSP methods and the server/firmware banner."),
        ("Stream path discovery", "T1595.003", "nmap -p554 --script rtsp-url-brute {ip}", "Discover valid stream URLs (per-vendor path lists)."),
        ("Default credentials", "T1078.001", "# test documented camera defaults (admin/admin, admin/12345) via RTSP/web", "Identify the vendor and test default credentials (authorized)."),
        ("Credential test", "T1110.003", "hydra -L users.txt -P passwords.txt rtsp://{ip} -f", "Authorized testing for weak RTSP credentials (mind lockout)."),
    )
