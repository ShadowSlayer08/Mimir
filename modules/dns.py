#!/usr/bin/env python3
"""modules.dns — DNS assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class DNSModule(SpecModule):
    name = "dns"
    title = "DNS"
    NAMES = ("domain",)
    SUMMARY = "DNS service ({prod})."
    KEYWORDS = ("dns", "zone transfer", "axfr", "bind", "recursion")
    EXTRA_TECH = ("T1590.002",)
    SURFACE = (
        ("always", "Open recursion enables cache poisoning and DDoS amplification; restrict recursion to trusted clients."),
        ("has_cve", "DNS daemon version has known CVEs (see findings)."),
    )
    CHECKS = (
        ("Version / NSID", "T1592.002", "dig CH TXT version.bind @{ip}", "Identify the resolver software/version (BIND/Unbound/etc.)."),
        ("Zone transfer", "T1590.002", "dig AXFR {domain} @{ip}", "Attempt a full zone transfer to dump internal records."),
        ("Recursion test", "T1046", "nmap -sU -p{port} --script dns-recursion {ip}", "Detect open recursion / open-resolver behaviour."),
        ("Subdomain brute", "T1590.002", "dnsenum --dnsserver {ip} {domain}", "Enumerate hosts/subdomains via the resolver."),
        ("Cache snooping", "T1590", "nmap -sU -p{port} --script dns-cache-snoop {ip}", "Infer recently resolved names from cache."),
    )
