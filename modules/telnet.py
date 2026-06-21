#!/usr/bin/env python3
"""modules.telnet — Telnet assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class TelnetModule(SpecModule):
    name = "telnet"
    title = "Telnet"
    NAMES = ("telnet",)
    SUMMARY = "Telnet service ({prod}) — cleartext."
    KEYWORDS = ("telnet", "cleartext")
    EXTRA_TECH = ("T1040",)
    SURFACE = (
        ("always", "Telnet is cleartext — all credentials and session data are sniffable on-path; replace with SSH."),
        ("has_cve", "Telnet daemon / device firmware has known CVEs (see findings)."),
    )
    CHECKS = (
        ("Banner / device ID", "T1592.002", "nmap -p{port} -sV --script telnet-ntlm-info {ip}", "Identify the device/OS and any leaked domain info."),
        ("Encryption support", "T1592.004", "nmap -p{port} --script telnet-encryption {ip}", "Check whether the server supports the TELNET ENCRYPT option."),
        ("Default credentials", "T1078.001", "telnet {ip} {port}", "Identify the device type and test documented default credentials (authorized)."),
        ("Credential test", "T1110.003", "hydra -L users.txt -P passwords.txt telnet://{ip}:{port} -f", "Authorized testing for weak/default credentials (mind lockout)."),
        ("On-path capture", "T1040", "# authorized network position: tcpdump -i <iface> host {ip} and port {port}", "Demonstrate credential exposure via cleartext capture."),
    )
