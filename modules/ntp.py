#!/usr/bin/env python3
"""modules.ntp — NTP assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class NTPModule(SpecModule):
    name = "ntp"
    title = "NTP"
    NAMES = ("ntp",)
    SUMMARY = "NTP service ({prod})."
    KEYWORDS = ("ntp", "monlist")
    EXTRA_TECH = ("T1590",)
    SURFACE = (
        ("always", "Legacy NTP (monlist) leaks recent client IPs and enables large DDoS amplification — patch/disable mode 7."),
    )
    CHECKS = (
        ("Version & sysinfo", "T1592.002", "ntpq -c rv {ip}", "Read NTP version, OS and system variables."),
        ("monlist", "T1590", "ntpdc -n -c monlist {ip}", "Test monlist (CVE-2013-5211): client-IP disclosure and amplification."),
        ("NSE info", "T1046", "nmap -sU -p{port} --script ntp-info,ntp-monlist {ip}", "Enumerate NTP info and amplification vectors."),
        ("Peer enumeration", "T1590", "ntpq -p {ip}", "List configured peers/upstreams (topology disclosure)."),
    )
