#!/usr/bin/env python3
"""CLI: python3 -m modules <nmap.xml | report.json> [--json out.json]"""
from __future__ import annotations

import json
import sys

# UTF-8 stdio so '·'/'—' and any non-ASCII module output don't crash on a
# legacy Windows code page (the .json path never imports nmap_analyzer).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from . import dispatch, REGISTRY


def _load(src):
    if src.endswith(".json"):
        return json.load(open(src, encoding="utf-8"))
    from nmap_analyzer import load_scan, analyze, build_report
    hosts, meta, _ = load_scan(src)
    return build_report(hosts, meta, analyze(hosts))


def main():
    if len(sys.argv) < 2:
        print("usage: python3 -m modules <nmap.xml | report.json> [--json out.json]")
        print("modules:", ", ".join(m.title for m in REGISTRY))
        sys.exit(1)
    report = _load(sys.argv[1])
    results = dispatch(report)
    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
        json.dump(results, open(out, "w"), indent=2)
        print(f"[+] {len(results)} module result(s) -> {out}")

    by_mod = {}
    for r in results:
        by_mod.setdefault(r["title"], []).append(r)
    print(f"[+] {len(results)} module result(s) across {len(by_mod)} module(s)\n")
    for title, rs in by_mod.items():
        print(f"=== {title} ===")
        for r in rs:
            print(f"  [{r['severity'].upper():8}] {r['target']:24} {r['summary']}")
            if r["attack_surface"]:
                for s in r["attack_surface"]:
                    print(f"        ! {s}")
            for c in r["checks"]:
                print(f"        - {c['name']:22} {c['attack']:10} {c['command']}")
        print()


if __name__ == "__main__":
    main()
