#!/usr/bin/env python3
"""
roe.py — Rules of Engagement as machine-checked hard gates.

Authorized / lab / CTF use only.

Reads a signed engagement's ROE (a YAML side-car) and filters what the operator
sees BEFORE the co-pilot ranks it. Nothing is dropped from the ledger — the ROE
gate only hides steps outside scope from the interactive queue, so a compliance
audit can still see the full derived plan and its explicit rejection reasons.

Supported rules (all optional):
  in_scope          : list of CIDR / hostname suffix / exact host — allowed targets
  out_of_scope      : same shape — hard-deny wins over in_scope
  allowed_windows   : list of {days: [...], hours: [HH:MM, HH:MM]} — when scans run
  forbidden_techniques : list of ATT&CK ids (T####[.###]) — never stage these
  forbidden_risk    : list of {"safe","intrusive"} — hide risk-tagged checks
  forbidden_kinds   : list of attack-path kinds (rce/lateral/domain/webapp)
  jurisdiction      : short tag — appears in every rejection reason (audit trail)

Every rejection carries a reason so the report can show the auditor exactly why
a step was hidden. Missing / malformed ROE -> permissive fallback (no filtering)
so the engine still runs without one.

    from roe import load, filter_engagement
    rules = load("engagement.roe.yml")
    kept, rejected = filter_engagement(rules, paths, modules, at_ts=None)
"""
from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime, timezone

_ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Hard-guardrail: institutional TLD patterns that are PERMANENTLY out of scope,
# regardless of what the ROE YAML allows. Scanning government / military /
# educational / international-organisation infrastructure without an engagement
# that explicitly authorises them is both ethically and legally problematic;
# Mimir refuses to stage against these TLDs by default. Opt-in override:
# set MIMIR_ALLOW_INSTITUTIONAL=1 (operator takes responsibility).
_INSTITUTIONAL_TLD = re.compile(
    r"(^|\.)("
    r"gov|gov\.[a-z]{2,3}|gob\.[a-z]{2,3}|gouv\.[a-z]{2,3}|govt\.[a-z]{2,3}|"
    r"go\.[a-z]{2}|gv\.[a-z]{2}|"
    r"mil|mil\.[a-z]{2,3}|"
    r"edu|edu\.[a-z]{2,3}|ac\.[a-z]{2,3}|"
    r"int"
    r")$",
    re.I,
)


def institutional_block_reason(host):
    """Return a specific reason string if `host` matches a protected institutional
    TLD, else "". Overridable via MIMIR_ALLOW_INSTITUTIONAL=1."""
    if os.environ.get("MIMIR_ALLOW_INSTITUTIONAL", os.environ.get("VANTAGE_ALLOW_INSTITUTIONAL", "")).strip() in ("1", "true", "yes"):
        return ""
    if not host or _is_ip(host):
        return ""
    m = _INSTITUTIONAL_TLD.search(host.lower())
    if not m:
        return ""
    tld = m.group(2)
    label = (
        "government" if tld.startswith(("gov", "gob", "gouv", "govt", "go.", "gv.")) else
        "military" if tld.startswith("mil") else
        "educational" if tld.startswith(("edu", "ac.")) else
        "international-org"
    )
    return f"institutional_tld:{label}:{tld}"


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
_TIME_RE = re.compile(r"^(\d{1,2}):(\d{2})$")
_DAY_MAP = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


# --------------------------------------------------------------------------- #
def _norm_days(days):
    if not days:
        return set(range(7))                                      # any day
    out = set()
    for d in days:
        n = _DAY_MAP.get(str(d).strip().lower()[:3])
        if n is not None:
            out.add(n)
    return out or set(range(7))


def _parse_hhmm(s):
    m = _TIME_RE.match(str(s).strip())
    if not m:
        return None
    h, mm = int(m.group(1)), int(m.group(2))
    return h * 60 + mm if (0 <= h <= 24 and 0 <= mm <= 59) else None


def load(path):
    """Parse a ROE YAML file. Returns a dict; empty dict on failure (permissive)."""
    if not path or not os.path.exists(path):
        return {}
    try:
        import yaml
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception:                                              # pragma: no cover
        return {}
    return _normalise(data)


def _normalise(raw):
    """Coerce raw YAML into a stable rule dict."""
    windows = []
    for w in raw.get("allowed_windows") or []:
        if not isinstance(w, dict):
            continue
        days = _norm_days(w.get("days"))
        hours = w.get("hours") or [None, None]
        start = _parse_hhmm(hours[0]) if len(hours) >= 1 else None
        end = _parse_hhmm(hours[1]) if len(hours) >= 2 else None
        if start is not None and end is not None:
            windows.append({"days": days, "start": start, "end": end})
    return {
        "engagement": str(raw.get("engagement") or "").strip(),
        "jurisdiction": str(raw.get("jurisdiction") or "").strip(),
        "in_scope": [str(x).strip() for x in (raw.get("in_scope") or []) if x],
        "out_of_scope": [str(x).strip() for x in (raw.get("out_of_scope") or []) if x],
        "allowed_windows": windows,
        "forbidden_techniques": {t for t in (raw.get("forbidden_techniques") or [])
                                 if isinstance(t, str) and _ATTACK_RE.match(t)},
        "forbidden_risk": {str(r).strip().lower()
                           for r in (raw.get("forbidden_risk") or [])},
        "forbidden_kinds": {str(k).strip().lower()
                            for k in (raw.get("forbidden_kinds") or [])},
    }


# --------------------------------------------------------------------------- #
def _host_matches(host, rule):
    """Match one rule entry against a host label / IP.
    Supports CIDR, exact match, and dotted-suffix wildcards (`.corp.lab`)."""
    if not host or not rule:
        return False
    rule_l = rule.lower()
    host_l = host.lower()
    try:
        net = ipaddress.ip_network(rule, strict=False)
        try:
            return ipaddress.ip_address(host_l) in net
        except ValueError:
            return False
    except ValueError:
        pass
    if rule_l.startswith("."):                                     # suffix match
        return host_l.endswith(rule_l)
    return host_l == rule_l


def _in_scope(host, rules):
    """Hard guardrail (.gov/.mil/.edu/.int) wins; then out_of_scope; then in_scope."""
    reason = institutional_block_reason(host)
    if reason:
        return False, reason
    if any(_host_matches(host, r) for r in rules.get("out_of_scope") or []):
        return False, "out_of_scope"
    in_scope = rules.get("in_scope") or []
    if in_scope and not any(_host_matches(host, r) for r in in_scope):
        return False, "not_in_scope"
    return True, ""


def _in_window(rules, at_ts=None):
    """True if the current (or supplied) local time is inside an allowed window."""
    windows = rules.get("allowed_windows") or []
    if not windows:                                                # no windows -> any time
        return True, ""
    if at_ts is None:
        at_ts = datetime.now(timezone.utc).astimezone()
    day = at_ts.weekday()
    mins = at_ts.hour * 60 + at_ts.minute
    for w in windows:
        if day not in w["days"]:
            continue
        s, e = w["start"], w["end"]
        # Windows that wrap midnight (start > end) are treated as "off-hours".
        if s <= e and s <= mins < e:
            return True, ""
        if s > e and (mins >= s or mins < e):
            return True, ""
    return False, "outside_allowed_window"


def _rejects_step(step, rules):
    """Return reason string if this attack-path step is forbidden, else ''."""
    tech = (step.get("technique_id") or "").strip()
    if tech and tech in rules.get("forbidden_techniques", set()):
        return f"forbidden_technique:{tech}"
    return ""


def _rejects_check(check, rules):
    if (check.get("risk") or "").strip().lower() in rules.get("forbidden_risk", set()):
        return "forbidden_risk:" + check.get("risk", "")
    tech = (check.get("attack") or "").strip()
    if tech and tech in rules.get("forbidden_techniques", set()):
        return f"forbidden_technique:{tech}"
    return ""


# --------------------------------------------------------------------------- #
def filter_engagement(rules, paths, modules, at_ts=None):
    """Apply ROE to attack paths + module check lists.

    Returns (kept, rejected) where each is a list of {"kind","id","reason"}
    plus mutated `paths`/`modules` clones with forbidden items dropped. The
    original lists are NOT modified — safe to call multiple times.
    """
    if not rules:
        return {"paths": list(paths or []), "modules": list(modules or [])}, []

    rejected = []
    kept_paths = []
    window_ok, window_reason = _in_window(rules, at_ts)

    for p in paths or []:
        pid = p.get("id", "")
        # host scope
        for host in (p.get("hosts") or []):
            ok, reason = _in_scope(host, rules)
            if not ok:
                rejected.append({"kind": "path", "id": pid, "reason": reason,
                                 "host": host})
                break
        else:
            # kind gate
            k = (p.get("kind") or "").lower()
            if k and k in rules.get("forbidden_kinds", set()):
                rejected.append({"kind": "path", "id": pid,
                                 "reason": f"forbidden_kind:{k}"})
                continue
            # step-level forbidden technique
            step_reject = ""
            for s in p.get("steps") or []:
                r = _rejects_step(s, rules)
                if r:
                    step_reject = r
                    break
            if step_reject:
                rejected.append({"kind": "path", "id": pid, "reason": step_reject})
                continue
            if not window_ok:
                rejected.append({"kind": "path", "id": pid, "reason": window_reason})
                continue
            kept_paths.append(p)

    kept_modules = []
    for m in modules or []:
        target = m.get("target", "") or m.get("host", "")
        # If the target is a URL, extract host part.
        host_probe = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        ok, reason = _in_scope(host_probe, rules) if host_probe else (True, "")
        if not ok:
            rejected.append({"kind": "module", "id": target, "reason": reason})
            continue
        keep_checks = []
        for c in m.get("checks") or []:
            r = _rejects_check(c, rules)
            if r:
                rejected.append({"kind": "check", "id": c.get("name", ""),
                                 "attack": c.get("attack", ""), "reason": r,
                                 "module": m.get("module", "")})
            else:
                keep_checks.append(c)
        keep = dict(m, checks=keep_checks)
        kept_modules.append(keep)

    if rules.get("jurisdiction"):
        for r in rejected:
            r["jurisdiction"] = rules["jurisdiction"]

    return {"paths": kept_paths, "modules": kept_modules}, rejected


# --------------------------------------------------------------------------- #
def main(argv=None):
    import argparse
    import json
    import sys
    ap = argparse.ArgumentParser(prog="roe.py",
                                 description="apply ROE hard-gates to an engagement JSON")
    ap.add_argument("engagement", help="engagement JSON (assess --emit-json)")
    ap.add_argument("roe", help="ROE yaml file")
    ap.add_argument("--json", help="write filtered engagement to this JSON file")
    args = ap.parse_args(argv)
    rules = load(args.roe)
    if not rules:
        print(f"[roe] no rules loaded from {args.roe} (permissive)")
        return 0
    with open(args.engagement, encoding="utf-8") as fh:
        eng = json.load(fh)
    kept, rejected = filter_engagement(rules, eng.get("attack_paths", []),
                                       eng.get("modules", []))
    print(f"[roe] engagement: {rules.get('engagement') or '(unnamed)'}   "
          f"jurisdiction: {rules.get('jurisdiction') or '(none)'}")
    print(f"[roe] paths   : kept {len(kept['paths'])} / rejected "
          f"{sum(1 for r in rejected if r['kind']=='path')}")
    print(f"[roe] checks  : rejected {sum(1 for r in rejected if r['kind']=='check')}")
    for r in rejected[:20]:
        tail = (" @ " + r.get("host")) if r.get("host") else ""
        print(f"    - [{r['kind']:<6}] {r.get('id', '?')}{tail}   ({r['reason']})")
    if args.json:
        eng["attack_paths"] = kept["paths"]
        eng.setdefault("roe", {})["applied"] = rules
        eng["roe"]["rejected"] = rejected
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(eng, fh, indent=2)
        print(f"[+] filtered engagement -> {args.json}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
