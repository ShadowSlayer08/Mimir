#!/usr/bin/env python3
"""
context.py — context-aware commands: fill discovered/operator facts into the
staged methodology so steps are copy-paste-ready instead of <placeholder>-ridden.

Authorized / lab / CTF use only.

Infers what it safely can from the inventory (the AD domain from hostnames, the DC,
the short company name) and merges operator-supplied facts (--domain/--user/--dc/
--ctx k=v), then substitutes them into every staged command + step guidance.

SECURITY: it never fills secrets. `<pass>` (and any `*pass*`/`*secret*`/`*key*`
token) is deliberately left as a placeholder so credentials are never baked into
staged commands or the written report. Staging only.
"""
from __future__ import annotations

import re
from collections import Counter

# tokens we WILL fill (non-secret). Secrets stay as placeholders.
_FILL = ("domain", "user", "dc", "listener", "company", "account", "bucket", "ca")
_SECRET = re.compile(r"pass|secret|key|token|cred", re.I)


def infer_domain(report):
    """Most common DNS suffix among discovered hostnames (e.g. corp.lab)."""
    c = Counter()
    for h in report.get("hosts", []):
        for name in (h.get("hostnames") or []):
            if "." in name:
                suffix = name.split(".", 1)[1].strip(".").lower()
                if "." in suffix or len(suffix) >= 4:      # skip bare TLDs / junk
                    c[suffix] += 1
    return c.most_common(1)[0][0] if c else ""


def _dc_label(report):
    """A host that looks like a domain controller (Kerberos/LDAP service or DC naming)."""
    for h in report.get("hosts", []):
        names = [(p.get("service", {}).get("name") or "").lower() for p in h.get("ports", [])]
        if any(any(a in n for a in ("kerberos", "ldap", "globalcat")) for n in names):
            return (h.get("hostnames") or [h.get("ip", "")])[0]
        label = (h.get("hostnames") or [""])[0]
        if re.search(r"(?i)(^|[^a-z])dc\d*([^a-z]|$)", label):
            return label
    return ""


def infer(report, overrides=None):
    """Engagement context: inferred facts + operator overrides (overrides win)."""
    ctx = {}
    dom = infer_domain(report)
    if dom:
        ctx["domain"] = dom
        ctx["company"] = dom.split(".")[0]
    dc = _dc_label(report)
    if dc:
        ctx["dc"] = dc
    for k, v in (overrides or {}).items():
        if v and not _SECRET.search(k):                    # never accept a secret into context
            ctx[k] = v
    return ctx


def fill(command, ctx):
    """Replace <token> placeholders with known context values (non-secret only)."""
    if not command or not ctx:
        return command
    out = command
    for k in _FILL:
        v = ctx.get(k)
        if v:
            out = out.replace("<%s>" % k, str(v))
    return out


def apply(mods, paths, ctx):
    """Fill context into every staged command + step guidance, in place."""
    if not ctx:
        return mods, paths
    for m in (mods or []):
        for c in m.get("checks", []):
            c["command"] = fill(c.get("command", ""), ctx)
    for p in (paths or []):
        for s in p.get("steps", []):
            s["command"] = fill(s.get("command", ""), ctx)
            if s.get("guidance"):
                s["guidance"] = fill(s["guidance"], ctx)
    return mods, paths
