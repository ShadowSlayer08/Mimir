#!/usr/bin/env python3
"""
validate_kb.py — integrity check for the docs/ knowledge base.

Authorized / lab / CTF use only.

Verifies the knowledge base the engine loads is internally consistent:
  * module ids unique; every module has matches (unless condition: is_dc)
  * every check has name/command/purpose and a well-formed MITRE ATT&CK id
  * every registry service routes to a module that exists AND whose `matches`
    cover that fragment (so dispatch actually produces a result)
  * nse/tool maps are well-formed (service -> non-empty list of strings)

Exit code 0 = clean, 1 = errors. Safe to run in CI:  python validate_kb.py
"""
from __future__ import annotations

import re
import sys

from knowledge_loader import load_knowledge

ATT = re.compile(r"^T\d{4}(\.\d{3})?$")   # T1190, T1021.002, ICS T0840


def _covers(frag, matches):
    f = (frag or "").lower()
    return any(f == m or f.startswith(m) or m in f for m in matches)


def validate(docs_dir=None):
    kb = load_knowledge(docs_dir)
    errors, warnings = [], []

    if not kb.modules:
        errors.append("no modules loaded from docs/")
    if not kb.registry:
        errors.append("empty service_registry")

    seen = {}
    for name, m in kb.modules.items():
        mid = m.get("module")
        if not mid:
            errors.append(f"module block in {name} has no 'module' id")
        if mid in seen:
            errors.append(f"duplicate module id: {mid}")
        seen[mid] = name
        if not m.get("matches") and m.get("condition") != "is_dc":
            errors.append(f"{mid}: no 'matches' and not condition:is_dc")
        if not m.get("checks"):
            warnings.append(f"{mid}: no checks")
        for c in m.get("checks", []):
            for k in ("name", "command", "purpose"):
                if not c.get(k):
                    errors.append(f"{mid}: check missing '{k}': {c.get('name', c)}")
            a = c.get("attack", "")
            if not ATT.match(a or ""):
                errors.append(f"{mid}: bad ATT&CK id {a!r} in check {c.get('name')!r}")
        for t in m.get("techniques_extra", []):
            if not ATT.match(t or ""):
                errors.append(f"{mid}: bad techniques_extra id {t!r}")

    for frag, mods in kb.registry.items():
        if not isinstance(mods, list) or not mods:
            errors.append(f"registry '{frag}' -> not a non-empty list")
            continue
        for mod in mods:
            md = kb.modules.get(mod)
            if not md:
                errors.append(f"registry '{frag}' -> unknown module '{mod}'")
            elif md.get("condition") != "is_dc" and not _covers(frag, md.get("matches", [])):
                errors.append(f"registry '{frag}' -> '{mod}', but its matches "
                              f"{md.get('matches')} do not cover '{frag}'")

    for label, table in (("nse", kb.nse), ("tools", kb.tools)):
        for k, v in table.items():
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                errors.append(f"{label} map '{k}' -> not a list[str]")
            elif not v:
                warnings.append(f"{label} map '{k}' is empty")

    return kb, errors, warnings


def main():
    kb, errors, warnings = validate(sys.argv[1] if len(sys.argv) > 1 else None)
    print(kb.summary())
    for w in warnings:
        print(f"  warn:  {w}")
    for e in errors:
        print(f"  ERROR: {e}")
    print(f"[{'FAIL' if errors else 'OK'}] {len(errors)} error(s), {len(warnings)} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
