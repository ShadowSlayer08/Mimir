#!/usr/bin/env python3
"""modules.ssh — SSH assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class SSHModule(SpecModule):
    name = "ssh"
    title = "SSH"
    NAMES = ("ssh",)
    SUMMARY = "SSH service ({prod})."
    KEYWORDS = ("ssh", "openssh", "dropbear")
    EXTRA_TECH = ("T1021.004",)
    SURFACE = (
        ("has_cve", "SSH daemon version has known CVEs (see findings)."),
        ("always", "Authentication endpoint — enumerate auth methods and test for weak/reused credentials and keys (mind lockout)."),
    )
    CHECKS = (
        ("Version & algorithms", "T1046", "nmap -p{port} -sV --script ssh2-enum-algos,ssh-hostkey {ip}", "Identify version, KEX/cipher/MAC algorithms and host keys."),
        ("Auth methods", "T1592.004", "ssh -o PreferredAuthentications=none -o BatchMode=yes {ip} -p {port}", "List accepted authentication methods."),
        ("Config audit", "T1552.004", "ssh-audit {ip}:{port}", "Audit for weak host keys and deprecated algorithms."),
        ("User enumeration", "T1087", "nmap -p{port} --script ssh-auth-methods --script-args 'ssh.user=root' {ip}", "Probe username validity before any spraying."),
        ("Credential test", "T1110.003", "hydra -L users.txt -P passwords.txt ssh://{ip}:{port} -t 4 -f", "Authorized spraying for weak/default credentials (mind lockout)."),
    )
