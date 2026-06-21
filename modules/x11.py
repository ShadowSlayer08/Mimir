#!/usr/bin/env python3
"""modules.x11 — X11 assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class X11Module(SpecModule):
    name = "x11"
    title = "X11"
    NAMES = ("x11",)
    UNAUTH = ("x11",)
    SUMMARY = "X11 server ({prod}) reachable."
    KEYWORDS = ("x11",)
    EXTRA_TECH = ("T1113",)
    SURFACE = (
        ("always", "An X server with access control disabled (xhost +) allows screenshotting and keystroke capture by any client."),
        ("unauth", "Test for open access before assuming the display is protected."),
    )
    CHECKS = (
        ("Open access test", "T1046", "nmap -p{port} --script x11-access {ip}", "Determine whether the X server accepts unauthenticated clients."),
        ("Display info", "T1082", "xdpyinfo -display {ip}:0", "Read display/server information when access is open."),
        ("Window enumeration", "T1010", "xwininfo -root -tree -display {ip}:0", "Enumerate open windows/applications on the display."),
        ("Screenshot", "T1113", "xwd -root -display {ip}:0 -out screen.xwd", "Capture the remote screen to demonstrate exposure (authorized)."),
    )
