#!/usr/bin/env python3
"""modules.rservices — Berkeley r-services methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class RServicesModule(SpecModule):
    name = "rservices"
    title = "Berkeley r-services"
    NAMES = ("rlogin", "rsh", "exec", "shell", "login", "klogin", "kshell")
    SUMMARY = "Berkeley r-service ({frag}) — cleartext, host-trust auth."
    KEYWORDS = ("rlogin", "rsh", "rexec", "r-service", "rhosts")
    EXTRA_TECH = ("T1021",)
    SURFACE = (
        ("always", "r-services use cleartext and .rhosts/hosts.equiv host-trust — disable in favour of SSH."),
    )
    CHECKS = (
        ("Service enumeration", "T1046", "nmap -p{port} -sV {ip}", "Confirm rexec(512)/rsh(514)/rlogin(513) and read banners."),
        ("Trusted-host access", "T1078", "rlogin {ip} -l root", "Test passwordless access via host-trust relationships (authorized)."),
        ("Remote command (rsh)", "T1021", "rsh {ip} -l <user> id", "Validate trust-based remote command execution."),
        ("On-path capture", "T1040", "# authorized capture: tcpdump -i <iface> host {ip}", "Show cleartext credential exposure on the wire."),
    )
