#!/usr/bin/env python3
"""
copilot.py — engagement co-pilot: rank the NEXT BEST ACTIONS from current state.

Authorized / lab / CTF use only.

Turns the engine's output (findings + staged attack paths) into a ranked
"do these first" list, so an operator facing dozens of hosts and hundreds of
staged steps knows where the leverage is. Pure ranking over already-computed data
— it recommends and orders; the human still runs every step, in scope. Staging only.

Score (0-100) blends: impact (severity), confidence, objective-proximity (does it
reach a high-value target / domain?), and low-effort/low-noise (fewer steps, safe).

    python copilot.py engagement.json            # ranked next actions from an --emit-json export
"""
from __future__ import annotations

_SEV = {"critical": 100, "high": 75, "medium": 45, "low": 20, "info": 5}
_CONF = {"high": 100, "medium": 60, "low": 30}
# finding titles that signal an immediate foothold (direct, high-ROI)
_FOOTHOLD = ("docker api", "eternalblue", "ms17-010", "sambacry", "default cred",
             "anonymous", "redis exposed", "unauth", "no auth", "world-read",
             "public exploit", " rce")


def _sev(s):
    return _SEV.get((s or "").lower(), 5)


def _conf(c):
    return _CONF.get((c or "").lower(), 40)


def _from_path(p):
    steps = p.get("steps", []) or []
    kind = (p.get("kind") or "").lower()
    proximity = 100 if kind == "domain" else (82 if kind in ("rce", "rce_system", "webapp") else 62)
    low_effort = 100 - min(len(steps), 6) / 6 * 100
    score = round(0.40 * _sev(p.get("severity")) + 0.25 * _conf(p.get("confidence"))
                  + 0.25 * proximity + 0.10 * low_effort)
    first = steps[0] if steps else {}
    cat = "objective" if kind == "domain" else ("foothold" if proximity >= 82 else "lateral")
    tail = (f" to {p['hosts'][-1]}" if p.get("hosts") else "")
    why = (f"{len(steps)}-step path{tail} · {p.get('confidence', '?')} confidence "
           f"· path score {p.get('score', 0)}")
    return {"category": cat, "title": p.get("name") or p.get("id", "path"), "why": why,
            "command": first.get("command") or first.get("guidance") or "",
            "attack": first.get("technique_id", ""), "risk": "",
            "source": p.get("id", ""), "score": score}


def _from_finding(f):
    sev = (f.get("severity") or "").lower()
    if sev not in ("critical", "high"):
        return None
    title = (f.get("title") or "").lower()
    if not (f.get("category") == "CVE (vulners)" or any(k in title for k in _FOOTHOLD)):
        return None
    score = round(0.55 * _sev(sev) + 0.20 * 70 + 0.15 * 90 + 0.10 * 80)
    tgt = f.get("host", "?") + (f":{f['port']}" if f.get("port") else "")
    return {"category": "quick-win", "title": f.get("title", ""),
            "why": f"Confirmed {sev} exposure on {tgt} - likely immediate foothold; validate in scope.",
            "command": "", "attack": "T1190", "risk": "", "source": tgt, "score": score}


def recommend(findings, paths, top=12):
    """Ranked next-best-action list from the current engagement state (deterministic)."""
    actions = [_from_path(p) for p in (paths or [])]
    actions += [a for a in (_from_finding(f) for f in (findings or [])) if a]
    actions.sort(key=lambda a: (-a["score"], a["category"], a["title"]))
    out, seen = [], set()
    for a in actions:
        key = (a["category"], a["title"], a["source"])
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(a, rank=len(out) + 1))
        if len(out) >= top:
            break
    return out


def recommend_from_engagement(eng, top=12):
    return recommend(eng.get("findings", []), eng.get("attack_paths", []), top)


def main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(prog="copilot.py",
                                 description="rank the next best actions from an engagement JSON "
                                             "(assess --emit-json)")
    ap.add_argument("engagement", help="engagement JSON file")
    ap.add_argument("--top", type=int, default=10)
    args = ap.parse_args(argv)
    with open(args.engagement, encoding="utf-8") as fh:
        eng = json.load(fh)
    recs = recommend_from_engagement(eng, args.top)
    print(f"[+] {len(recs)} recommended next action(s):\n")
    for a in recs:
        print(f"  #{a['rank']:<2} [{a['score']:>3}] ({a['category']}) {a['title']}")
        print(f"      why: {a['why']}")
        if a["command"]:
            print(f"      run: {a['command']}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
