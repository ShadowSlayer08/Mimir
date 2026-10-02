#!/usr/bin/env python3
"""
opsec.py — operator noise profile + staged-step annotation (ARES-inspired).

Authorized / lab / CTF / VAPT / red-team use only.

Vantage stages; it never executes. So an "OPSEC Governor" in the ARES sense
(throttling + abort-on-detection-risk at the exec layer) doesn't apply directly.
What DOES apply: tagging every staged step with a NOISE SCORE + a RECOMMENDED
pacing hint so the operator (and the co-pilot) can order steps by noise budget,
and so an interactive runbook can show "this is loud, slow down" before a
dangerous step.

Noise scores (0-10, higher = louder):
  * 0-2    purely passive / off-target (CT logs, favicon hash lookup, Shodan)
  * 3-4    unauthenticated recon that touches the target lightly (banner grab)
  * 5-6    active enumeration (version scan, dir fuzz)
  * 7-8    intrusive but low-impact (auth probes, non-DoS exploit confirmation)
  * 9-10   DoS / lockout / mass-coercion / high-detection-risk

The operator sets a NOISE PROFILE on the engagement:
  * stealth    - only accept noise <= 3 (passive-first)
  * normal     - accept noise <= 7 (default)
  * aggressive - accept any noise, warn on >= 9

Steps whose noise exceeds the profile are not DROPPED — the ROE gate does that
— they're flagged `noise_warn` so the co-pilot ranks them lower + the operator
sees a visible warning in the runbook. Hard gating lives in `roe.py`.
"""
from __future__ import annotations

import re

# Technique id -> noise score. If an id is absent, we fall back to the risk
# tag + a conservative default.
_TECH_NOISE = {
    # purely passive / OSINT
    "T1590":       2, "T1590.005": 1, "T1596":    2, "T1596.001": 1, "T1596.002": 1,
    "T1589":       2, "T1589.001": 2, "T1589.002": 3,
    # recon that touches the target
    "T1595":       4, "T1595.001": 5, "T1595.002": 4, "T1046":    5,
    "T1592":       3, "T1592.001": 3, "T1592.002": 3,
    # active enumeration + modest auth probes
    "T1087":       5, "T1087.001": 5, "T1087.002": 5, "T1069":    5,
    "T1482":       4, "T1552":    5, "T1552.001": 4, "T1552.004": 5, "T1552.007": 5,
    # credential testing (lockout-aware)
    "T1110":       8, "T1110.001": 9, "T1110.003": 8, "T1110.004": 9,
    "T1621":       9,                                               # MFA fatigue
    # exploitation / RCE confirmation
    "T1190":       7, "T1210":    7, "T1068":    7,
    # credential access / dumping
    "T1003":       7, "T1003.001": 7, "T1003.006": 8, "T1558":    7, "T1558.003": 7,
    # lateral / persistence
    "T1021":       6, "T1021.002": 6, "T1078":    5, "T1078.001": 7, "T1078.004": 6,
    "T1098":       7, "T1098.001": 7,
    # defense evasion
    "T1562":       8, "T1562.001": 9,
    # DoS / impact
    "T1499":      10, "T1499.001": 10, "T1499.002": 10, "T1499.004": 10,
    "T1498":       9, "T1485":   10, "T1486":   10,
    # relaying / coercion
    "T1187":       8, "T1557":    7, "T1557.001": 7, "T1550":    7, "T1550.002": 7,
    # supply-chain / cloud posture
    "T1195":       4, "T1195.001": 3, "T1195.002": 4, "T1526":    4,
    # AI/LLM target
    "T1565":       6,
}

# Fallbacks by risk tag.
_RISK_NOISE = {"safe": 3, "intrusive": 7, "": 4}

# Profile -> acceptable ceiling (inclusive).
_PROFILE_MAX = {"stealth": 3, "normal": 7, "aggressive": 10}
# Pacing hints (recommended delay between consecutive loud steps).
_PACING_SECONDS = {"stealth": 60, "normal": 10, "aggressive": 0}

_HOST_RE = re.compile(r"\b([a-z0-9][a-z0-9\-]+(?:\.[a-z0-9][a-z0-9\-]+){1,})\b", re.I)


def noise_for(step_or_check):
    """Return (score, source_hint). `step_or_check` can be either a staged step
    (`technique_id`) or a module check (`attack` + `risk`)."""
    d = step_or_check or {}
    tech = d.get("technique_id") or d.get("attack") or ""
    if tech and tech in _TECH_NOISE:
        return _TECH_NOISE[tech], f"tech:{tech}"
    # Fall back to the risk tag (safe/intrusive).
    risk = (d.get("risk") or "").strip().lower()
    return _RISK_NOISE.get(risk, 4), f"risk:{risk or 'unknown'}"


def profile_ceiling(profile):
    return _PROFILE_MAX.get((profile or "normal").lower(), _PROFILE_MAX["normal"])


def pacing_seconds(profile):
    return _PACING_SECONDS.get((profile or "normal").lower(), _PACING_SECONDS["normal"])


def annotate_paths(paths, profile="normal"):
    """Attach `noise` to every step + `noise_warn` to the step and the path
    if any step exceeds the profile ceiling. Returns the input (mutated)."""
    ceiling = profile_ceiling(profile)
    for p in paths or []:
        path_max = 0
        for s in p.get("steps") or []:
            score, src = noise_for(s)
            s["noise"] = score
            s["noise_src"] = src
            if score > ceiling:
                s["noise_warn"] = True
            path_max = max(path_max, score)
        p["noise_max"] = path_max
        if path_max > ceiling:
            p["noise_warn"] = True
    return paths


def annotate_modules(modules, profile="normal"):
    """Same for module checks — attaches `noise` + `noise_warn` to each check."""
    ceiling = profile_ceiling(profile)
    for m in modules or []:
        mod_max = 0
        for c in m.get("checks") or []:
            score, src = noise_for(c)
            c["noise"] = score
            c["noise_src"] = src
            if score > ceiling:
                c["noise_warn"] = True
            mod_max = max(mod_max, score)
        m["noise_max"] = mod_max
    return modules


def summary(paths, modules, profile="normal"):
    """Return a dict summarising noise exposure — for the report."""
    ceiling = profile_ceiling(profile)
    all_scores = [s.get("noise", 0) for p in (paths or []) for s in (p.get("steps") or [])]
    all_scores += [c.get("noise", 0) for m in (modules or []) for c in (m.get("checks") or [])]
    exceed_paths = sum(1 for p in (paths or []) if p.get("noise_warn"))
    exceed_checks = sum(1 for m in (modules or [])
                        for c in (m.get("checks") or []) if c.get("noise_warn"))
    return {
        "profile": profile, "ceiling": ceiling,
        "pacing_seconds_hint": pacing_seconds(profile),
        "scores": {"min": min(all_scores) if all_scores else 0,
                   "max": max(all_scores) if all_scores else 0,
                   "count": len(all_scores)},
        "exceed_profile": {"paths": exceed_paths, "checks": exceed_checks},
    }


def main(argv=None):
    import argparse
    import json
    import sys
    ap = argparse.ArgumentParser(prog="vantage-opsec",
                                 description="annotate an engagement JSON with noise scores")
    ap.add_argument("engagement", help="engagement JSON (assess --emit-json)")
    ap.add_argument("--profile", default="normal",
                    choices=list(_PROFILE_MAX.keys()),
                    help="noise profile; steps > ceiling get noise_warn")
    ap.add_argument("--json", metavar="FILE", help="write annotated engagement here")
    args = ap.parse_args(argv)
    with open(args.engagement, encoding="utf-8") as fh:
        eng = json.load(fh)
    annotate_paths(eng.get("attack_paths") or [], args.profile)
    annotate_modules(eng.get("modules") or [], args.profile)
    s = summary(eng.get("attack_paths") or [], eng.get("modules") or [], args.profile)
    print(f"[opsec] profile={s['profile']} ceiling={s['ceiling']} pacing={s['pacing_seconds_hint']}s")
    print(f"[opsec] scores min={s['scores']['min']} max={s['scores']['max']} "
          f"count={s['scores']['count']}")
    print(f"[opsec] over-ceiling: paths={s['exceed_profile']['paths']} "
          f"checks={s['exceed_profile']['checks']}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            eng["opsec"] = s
            json.dump(eng, fh, indent=2)
        print(f"[+] wrote {args.json}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
