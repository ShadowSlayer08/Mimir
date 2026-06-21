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

FIELDS = ("host", "port", "category", "severity", "title", "cve", "detail", "fix")
SEVERITIES = ("critical", "high", "medium", "low", "info")


def finding(host, port, category, severity, title, cve=None, detail="", fix=""):
    """Build a schema-conformant finding dict (cve de-duplicated and sorted)."""
    return {"host": host, "port": port, "category": category, "severity": severity,
            "title": title, "cve": sorted(set(cve or [])), "detail": detail, "fix": fix}


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
    if not isinstance(f.get("cve", []), list):
        problems.append("cve is not a list")
    return problems
