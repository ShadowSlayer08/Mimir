#!/usr/bin/env python3
"""modules.ftp — FTP assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class FTPModule(SpecModule):
    name = "ftp"
    title = "FTP"
    NAMES = ("ftp", "ftps", "ftp-data")
    TLS_PORTS = (990,)
    SUMMARY = "FTP service ({prod})."
    KEYWORDS = ("ftp", "anonymous", "vsftpd", "proftpd")
    EXTRA_TECH = ("T1078",)
    SURFACE = (
        ("not_tls", "FTP is cleartext — credentials and data are exposed on-path; prefer SFTP/FTPS."),
        ("has_cve", "FTP daemon version has known CVEs (see findings)."),
    )
    CHECKS = (
        ("Anonymous login", "T1078", "nmap -p{port} --script ftp-anon {ip}", "Test for anonymous FTP access and list readable content."),
        ("Banner & version", "T1592.002", "nmap -p{port} -sV --script ftp-syst {ip}", "Identify the FTP daemon and OS for CVE cross-referencing."),
        ("FTP bounce", "T1090", "nmap -p{port} --script ftp-bounce {ip}", "Detect FTP bounce (PORT) proxying that could reach internal hosts."),
        ("Manual enumeration", "T1083", "ftp {ip} {port}", "List directories, check writable paths and upload restrictions (authorized)."),
        ("Credential test", "T1110.003", "hydra -L users.txt -P passwords.txt ftp://{ip}:{port} -f", "Authorized testing for weak/default credentials (mind lockout)."),
        ("TLS posture", "T1595", "sslscan {ip}:{port}", "For FTPS, enumerate TLS protocols/ciphers/certificate.", "tls"),
    )
