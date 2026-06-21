#!/usr/bin/env python3
"""modules.vpn — VPN / IKE methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class VPNModule(SpecModule):
    name = "vpn"
    title = "VPN / IKE"
    NAMES = ("isakmp", "ike", "openvpn", "pptp", "l2tp")
    SUMMARY = "VPN endpoint ({frag})."
    KEYWORDS = ("isakmp", "ike", "vpn", "pptp", "aggressive mode")
    EXTRA_TECH = ("T1133",)
    SURFACE = (
        ("always", "IKE aggressive mode exposes a crackable PSK hash; PPTP/MS-CHAPv2 is broken — prefer IKEv2/modern VPNs."),
    )
    CHECKS = (
        ("IKE transforms", "T1046", "ike-scan -M {ip}", "Enumerate supported IKE transforms and identify the VPN vendor."),
        ("Aggressive-mode PSK", "T1110", "ike-scan --aggressive -M --pskcrack={ip}.psk {ip}", "Detect aggressive mode and capture the PSK hash (authorized)."),
        ("PPTP version", "T1592.002", "nmap -p{port} -sV {ip}", "Identify PPTP/L2TP and the underlying auth (MS-CHAPv2 weakness)."),
        ("PSK cracking", "T1110.002", "psk-crack {ip}.psk", "Offline-crack a captured aggressive-mode PSK (authorized)."),
    )
