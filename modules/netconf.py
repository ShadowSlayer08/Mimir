#!/usr/bin/env python3
"""modules.netconf — NETCONF (830) methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class NetconfModule(SpecModule):
    name = "netconf"
    title = "NETCONF"
    NAMES = ("netconf",)
    SUMMARY = "NETCONF management service ({prod})."
    KEYWORDS = ("netconf", "yang")
    EXTRA_TECH = ("T1078",)
    SURFACE = (
        ("always", "NETCONF exposes full device config (get-config/edit-config) to an authenticated client — restrict to the management plane."),
    )
    CHECKS = (
        ("Service detection", "T1046", "nmap -p830 -sV --script ssh2-enum-algos {ip}", "Confirm NETCONF-over-SSH and the host-key/algorithms."),
        ("Hello / capabilities", "T1592.004", "ssh -p 830 -s {ip} netconf", "Read the NETCONF <hello> and advertised YANG capabilities/vendor."),
        ("Credential test", "T1110.003", "hydra -L users.txt -P passwords.txt ssh://{ip}:830 -f", "Authorized testing for weak management credentials (mind lockout)."),
        ("Config read", "T1602.002", "# authenticated: <get-config><source><running/></source></get-config>", "Retrieve the running config once authenticated."),
    )
