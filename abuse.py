#!/usr/bin/env python3
"""
abuse.py — per-technique exploitation insight ("abuse info") lookup.

Authorized / lab / CTF use only.

BloodHound-style guidance attached to staged attack-path steps: what the step
gives a human operator (impact), how it's typically abused with their own tooling
(how), and the detection/safety caveats (opsec). Loaded from docs/abuse_info.md
(knowledge-driven); falls back to the embedded subset. Guided, human-led — the
engine surfaces this insight; the operator executes.
"""
from __future__ import annotations

_FALLBACK = {
    "T1190": {"name": "Exploit Public-Facing Application",
              "impact": "A confirmed exploitable exposure yields an initial foothold / RCE.",
              "how": "Validate detection-only first, then run your exploit for that exact CVE in scope.",
              "opsec": "Exploitation can crash the service — confirm scope and a maintenance window."},
    "T1078": {"name": "Valid Accounts",
              "impact": "Reused/recovered creds grant authenticated access with no exploit.",
              "how": "Spray validated creds across reachable services; look for local-admin reuse.",
              "opsec": "Spraying risks lockout — read the password policy first and throttle."},
    "T1003": {"name": "OS Credential Dumping",
              "impact": "Local hashes/tickets for lateral movement and escalation.",
              "how": "From SYSTEM/root, dump SAM/LSASS or /etc/shadow; crack or pass-the-hash.",
              "opsec": "LSASS access is heavily monitored — expect EDR detection."},
    "T1021": {"name": "Remote Services",
              "impact": "Valid creds give a foothold on the remote host.",
              "how": "Authenticate to the service with validated creds (netexec / native client).",
              "opsec": "Remote logons are logged; prefer the quietest exec method."},
    "T1482": {"name": "Domain Trust Discovery",
              "impact": "Maps privilege paths to Domain Admins / krbtgt.",
              "how": "bloodhound-python -c All; review each edge's abuse info for the route.",
              "opsec": "Collection is noisy — pace it or target collection."},
}


def load_info(docs_dir=None):
    try:
        from knowledge_loader import load_knowledge
        info = load_knowledge(docs_dir).abuse_info or {}
        if info:
            return info
    except Exception:                                                  # pragma: no cover
        pass
    return _FALLBACK


def abuse_for(technique, info=None):
    """Return the abuse-info dict for a technique id, falling back to its base
    technique (T1021.002 -> T1021). None if unknown."""
    info = info or load_info()
    if technique in info:
        return info[technique]
    base = (technique or "").split(".")[0]
    return info.get(base)
