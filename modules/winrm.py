#!/usr/bin/env python3
"""modules.winrm — WinRM assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class WinRMModule(SpecModule):
    name = "winrm"
    title = "WinRM"
    NAMES = ("winrm", "wsman")
    TLS_PORTS = (5986,)
    SUMMARY = "WinRM/WSMan service ({prod})."
    KEYWORDS = ("winrm", "wsman", "powershell remoting")
    EXTRA_TECH = ("T1021.006",)
    SURFACE = (
        ("always", "WinRM enables remote PowerShell — a reused/valid credential yields code execution; restrict and monitor."),
        ("tls", "WinRM over HTTPS (5986) — review the TLS certificate."),
    )
    CHECKS = (
        ("Service detection", "T1046", "nmap -p{port} -sV --script http-ntlm-info --script-args http-ntlm-info.root=/wsman {ip}", "Confirm WinRM (Microsoft HTTPAPI) and leak hostname/domain via NTLM on /wsman."),
        ("Auth methods", "T1592.004", "curl -sk {scheme}://{ip}:{port}/wsman -X POST", "Identify supported authentication (Negotiate/Kerberos/Basic)."),
        ("Credential validation", "T1110.003", "crackmapexec winrm {ip} -u users.txt -p passwords.txt", "Authorized validation of credentials over WinRM (mind lockout)."),
        ("Authenticated shell", "T1021.006", "evil-winrm -i {ip} -u <user> -p <pass>", "Validate remote PowerShell access with tested credentials (authorized)."),
        ("Command exec check", "T1059.001", "crackmapexec winrm {ip} -u <user> -p <pass> -x 'whoami'", "Confirm command execution and the resulting privilege level."),
    )
