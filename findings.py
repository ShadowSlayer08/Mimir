#!/usr/bin/env python3
"""
findings.py — the one canonical finding schema for the engine.

Authorized / lab / CTF use only.

A finding is a flat dict with a fixed set of fields. nmap_analyzer and evidence
both build findings through `finding()` here so the shape can't drift (a finding
created in one place but missing a field elsewhere was a latent bug). `validate()`
is used by tests / CI to assert conformance.
"""
from __future__ import annotations

FIELDS = ("host", "port", "category", "severity", "title", "cve", "detail", "fix", "owasp", "cwe")
SEVERITIES = ("critical", "high", "medium", "low", "info")


def finding(host, port, category, severity, title, cve=None, detail="", fix="",
            owasp=None, cwe=None):
    """Build a schema-conformant finding dict (cve/owasp/cwe de-duplicated, sorted).

    `owasp` (e.g. WSTG-INPV-05, API1:2023) and `cwe` (e.g. CWE-89) are the AppSec
    reference layer; they sit beside the ATT&CK techniques carried per check. Both
    default empty so infra findings are unaffected.
    """
    return {"host": host, "port": port, "category": category, "severity": severity,
            "title": title, "cve": sorted(set(cve or [])), "detail": detail, "fix": fix,
            "owasp": sorted(set(owasp or [])), "cwe": sorted(set(cwe or []))}


def validate(f):
    """Return a list of problems with a finding (empty == valid)."""
    problems = []
    if not isinstance(f, dict):
        return ["not a dict"]
    for k in FIELDS:
        if k not in f:
            problems.append(f"missing field '{k}'")
    if f.get("severity") not in SEVERITIES:
        problems.append(f"bad severity {f.get('severity')!r}")
    for k in ("cve", "owasp", "cwe"):
        if not isinstance(f.get(k, []), list):
            problems.append(f"{k} is not a list")
    return problems
