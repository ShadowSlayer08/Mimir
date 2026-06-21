#!/usr/bin/env python3
"""modules.mail — SMTP/IMAP/POP3 methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class MailModule(SpecModule):
    name = "mail"
    title = "Mail (SMTP/IMAP/POP3)"
    NAMES = ("smtp", "smtps", "submission", "imap", "imaps", "pop3", "pop3s")
    TLS_PORTS = (465, 993, 995)
    SUMMARY = "{disp} service ({prod})."
    KEYWORDS = ("smtp", "imap", "pop3", "open relay", "starttls")
    EXTRA_TECH = ("T1114",)
    LABELS = {"smtp": "SMTP", "smtps": "SMTPS", "submission": "SMTP Submission",
              "imap": "IMAP", "imaps": "IMAPS", "pop3": "POP3", "pop3s": "POP3S"}
    SURFACE = (
        ("not_tls", "Cleartext mail protocol — enforce STARTTLS/implicit TLS to protect credentials."),
        ("has_cve", "Mail daemon version has known CVEs (see findings)."),
    )
    CHECKS = (
        ("Banner & commands", "T1592.002", "nmap -p{port} -sV --script smtp-commands,banner {ip}", "Identify the MTA/MDA, supported verbs and STARTTLS advertisement."),
        ("Open relay test", "T1590", "nmap -p{port} --script smtp-open-relay {ip}", "Detect whether the server relays mail for arbitrary senders."),
        ("User enumeration", "T1087.003", "smtp-user-enum -M VRFY -U users.txt -t {ip} -p {port}", "Enumerate valid mailboxes via VRFY/EXPN/RCPT."),
        ("STARTTLS posture", "T1595", "openssl s_client -starttls smtp -connect {ip}:{port}", "Verify STARTTLS support and inspect the certificate."),
        ("TLS posture", "T1595", "sslscan {ip}:{port}", "For implicit-TLS ports, enumerate protocols/ciphers/cert.", "tls"),
        ("Credential test", "T1110.003", "hydra -L users.txt -P passwords.txt -s {port} {ip} <smtp|imap|pop3>   # add -S for implicit-TLS (465/993/995)", "Authorized testing for weak mailbox credentials with the matching hydra module (mind lockout)."),
    )
