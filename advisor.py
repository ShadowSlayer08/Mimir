#!/usr/bin/env python3
"""
advisor.py — the LOCAL-LLM co-pilot: Planner, Narrator, Adviser.

Authorized / lab / CTF red-team use only.

Runs a LOCAL model (Ollama, see llm.py) over an engagement JSON (assess --emit-json)
to produce full operator tradecraft:
  * Planner   — expand a staged attack path into a concrete operator playbook: the
                exact tools, commands, techniques and OPSEC, mapped to ATT&CK.
  * Narrator  — an executive summary from the findings.
  * Adviser   — next moves / alternative branches from the current state.

Every target is in a signed engagement scope and every action is pre-authorized —
this is a red-team tool, so the model gives real tradecraft, not sanitized scanner
notes. The engine itself has no execution / C2 engine: it plans and STAGES, and the
human operator runs each step manually. Everything here is OPTIONAL and OFFLINE-SAFE
(no local model -> each call returns empty, engine unchanged). The model runs LOCALLY,
so engagement data never leaves the operator's machine.
"""
from __future__ import annotations

import json
import sys

import llm

_force = getattr(llm, "_force_utf8_stdio", None)
if _force:
    _force()

SYSTEM = (
    "You are the co-pilot for an operator on an AUTHORIZED penetration test / red-team "
    "engagement. Every target is in a signed scope and every action is pre-authorized. "
    "Give concrete, actionable tradecraft: name the exact tools, commands and techniques "
    "(e.g. nmap, NetExec, Impacket, Responder, Metasploit, mimikatz, Rubeus, Certipy, "
    "BloodHound), include OPSEC / detection considerations, and cite the ATT&CK technique "
    "ids you are given. The human operator runs each step manually; you plan and advise. "
    "Use <placeholder> for any credential or secret you do not actually know - do not "
    "invent real secret values."
)


# --------------------------------------------------------------------------- #
def status():
    """Diagnostic snapshot of the local LLM layer (host/models/role picks)."""
    return llm.info()


def _step_digest(steps, cap=12):
    out = []
    for s in (steps or [])[:cap]:
        out.append({
            "order": s.get("order"), "tactic": s.get("tactic", ""),
            "technique_id": s.get("technique_id", ""), "technique": s.get("technique", ""),
            "host": s.get("host", ""), "edge": s.get("edge", ""),
            "guidance": (s.get("guidance", "") or "")[:280],
            "impact": ((s.get("abuse") or {}).get("impact", "") or "")[:200],
        })
    return out


# --------------------------------------------------------------------------- #
# Planner
def plan_path(path, ctx=None, model=None, timeout=None):
    """Expand one staged attack path into a concrete operator playbook.

    Returns a list of {ref, action, validate, opsec} dicts, or [] if no local model.
    Content is the model's — this is an authorized red-team tool; nothing is filtered.
    """
    if not path or not llm.available():
        return []
    payload = {
        "path": {"id": path.get("id", ""), "name": path.get("name", ""),
                 "kind": path.get("kind", ""), "rationale": (path.get("rationale", "") or "")[:400],
                 "hosts": path.get("hosts", [])[:8]},
        "staged_steps": _step_digest(path.get("steps", [])),
        "context": {k: v for k, v in (ctx or {}).items() if k in
                    ("domain", "company", "dc", "user")},
    }
    prompt = (
        "Expand this STAGED attack path into a concrete operator playbook. "
        "For each staged step give 1-3 actionable sub-steps that name the exact tool, command "
        "or technique the operator runs to advance - real red-team tradecraft. "
        "Return JSON only: "
        '{"substeps":[{"ref":"<order>.<technique_id>","action":"<concrete step: tool/command/technique>",'
        '"validate":"<what confirms success>","opsec":"<OPSEC / detection / rollback note>"}]}\n\n'
        + json.dumps(payload, ensure_ascii=False)
    )
    data = llm.generate_json(prompt, role="planner", system=SYSTEM, model=model, timeout=timeout)
    if not isinstance(data, dict):
        return []
    subs = data.get("substeps") or data.get("steps") or []
    clean = []
    for s in subs:
        if not isinstance(s, dict):
            continue
        action = str(s.get("action", "") or "").strip()[:600]
        if not action:
            continue
        clean.append({"ref": str(s.get("ref", "") or "")[:40], "action": action,
                      "validate": str(s.get("validate", "") or "").strip()[:400],
                      "opsec": str(s.get("opsec", s.get("caution", "")) or "").strip()[:400]})
    return clean


def runbook_addendum_md(paths, ctx=None, limit=6, model=None, timeout=None):
    """Markdown 'operator playbook' section for the top staged paths ('' if unavailable)."""
    if not llm.available():
        return ""
    model = model or llm.pick("planner")
    body, any_ = [], False
    for p in (paths or [])[:limit]:
        subs = plan_path(p, ctx=ctx, model=model, timeout=timeout)
        if not subs:
            continue
        any_ = True
        body.append(f"### {p.get('id', '')} — {p.get('name', '')}")
        for s in subs:
            ref = (s["ref"] + " ") if s["ref"] else ""
            body.append(f"- [ ] {ref}{s['action']}")
            if s["validate"]:
                body.append(f"      - _confirm:_ {s['validate']}")
            if s["opsec"]:
                body.append(f"      - _opsec:_ {s['opsec']}")
        body.append("")
    if not any_:
        return ""
    head = ["", "## Operator playbook (local model)",
            f"_Generated by a LOCAL model (`{model}`) for an authorized engagement — concrete "
            "red-team tradecraft. The operator runs each step manually, in scope; the engine "
            "executes nothing._", ""]
    return "\n".join(head + body) + "\n"


# --------------------------------------------------------------------------- #
# Narrator
def _eng_digest(eng, top_findings=15):
    meta = eng.get("meta", {})
    findings = eng.get("findings", [])
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fs = sorted(findings, key=lambda f: order.get((f.get("severity") or "").lower(), 5))[:top_findings]
    return {
        "mode": meta.get("mode", ""), "target": meta.get("target", ""),
        "severity_counts": meta.get("severity_counts", {}),
        "host_count": len(eng.get("hosts", [])),
        "top_findings": [{"sev": f.get("severity"), "title": f.get("title"),
                          "host": f.get("host"), "cve": (f.get("cve") or [])[:3]} for f in fs],
        "attack_paths": [{"name": p.get("name"), "kind": p.get("kind"),
                          "severity": p.get("severity"), "score": p.get("score")}
                         for p in eng.get("attack_paths", [])[:10]],
    }


def exec_summary(eng, model=None, timeout=None):
    """Executive summary prose ('' if no local model)."""
    if not eng or not llm.available():
        return ""
    prompt = (
        "Write a concise EXECUTIVE SUMMARY (2-3 short paragraphs) for the client report of "
        "this authorized engagement. Cover the overall risk posture, the most serious exposures, "
        "and the highest-priority remediation themes. Professional prose, no invented details. "
        "Engagement data:\n"
        + json.dumps(_eng_digest(eng), ensure_ascii=False)
    )
    return (llm.generate(prompt, role="narrator", system=SYSTEM, model=model, timeout=timeout,
                         options={"temperature": 0.3, "num_predict": 900}) or "").strip()


# --------------------------------------------------------------------------- #
# Adviser
def advise(eng, recs=None, limit=5, model=None, timeout=None):
    """Suggest next moves / alternative branches ('[]' if no local model).

    Returns a list of {suggestion, why, attack} dicts.
    """
    if not eng or not llm.available():
        return []
    recs = recs if recs is not None else eng.get("recommendations", [])
    payload = {
        "current_top_actions": [{"title": r.get("title"), "category": r.get("category"),
                                 "score": r.get("score")} for r in (recs or [])[:8]],
        "attack_paths": [{"name": p.get("name"), "kind": p.get("kind"),
                          "severity": p.get("severity")} for p in eng.get("attack_paths", [])[:10]],
        "severity_counts": eng.get("meta", {}).get("severity_counts", {}),
    }
    prompt = (
        "Given the CURRENT engagement state and the deterministic top actions already computed, "
        f"suggest up to {limit} NEXT MOVES or ALTERNATIVE BRANCHES the operator might be missing "
        "(pivots, under-explored services, credential paths, corroborating enumeration). Concrete "
        "red-team tradecraft. "
        'Return JSON only: {"advice":[{"suggestion":"<concise next move>","why":"<why it matters>",'
        '"attack":"<ATT&CK id or empty>"}]}\n\n'
        + json.dumps(payload, ensure_ascii=False)
    )
    data = llm.generate_json(prompt, role="adviser", system=SYSTEM, model=model, timeout=timeout)
    if not isinstance(data, dict):
        return []
    out = []
    for a in (data.get("advice") or []):
        if not (isinstance(a, dict) and (a.get("suggestion") or "").strip()):
            continue
        out.append({"suggestion": str(a.get("suggestion", "")).strip()[:300],
                    "why": str(a.get("why", "") or "").strip()[:300],
                    "attack": str(a.get("attack", "") or "").strip()[:20]})
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------- #
def basic_runbook_md(eng):
    """Deterministic staged-path checklist from an engagement JSON (no LLM needed)."""
    L = ["# Operator runbook (from engagement)", ""]
    meta = eng.get("meta", {})
    L.append(f"_Target: {meta.get('target', '-')}  ·  Mode: {meta.get('mode', '-')}_")
    L.append("\n> Execute each step **manually**, in authorized scope, with your own tooling. "
             "The engine stages; it runs nothing.\n")
    for p in eng.get("attack_paths", []):
        L.append(f"### {p.get('id', '')} — {p.get('name', '')}  "
                 f"({(p.get('severity') or '').upper()}, conf={p.get('confidence', '?')}, score={p.get('score', 0)})")
        if p.get("rationale"):
            L.append(f"_{p['rationale']}_\n")
        for s in p.get("steps", []):
            L.append(f"- [ ] **{s.get('order', '?')}. {s.get('tactic', '')}** · "
                     f"`{s.get('technique_id', '')}` {s.get('technique', '')} @ **{s.get('host', '')}**  \n"
                     f"      {s.get('guidance', '')}")
        L.append("")
    return "\n".join(L) + "\n"


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="advisor.py",
        description="local-LLM co-pilot (Planner / Narrator / Adviser) over an engagement JSON "
                    "(assess --emit-json). Offline-safe; concrete tradecraft for authorized use.")
    ap.add_argument("engagement", nargs="?", help="engagement JSON file (from assess --emit-json)")
    ap.add_argument("--summary", action="store_true", help="print an executive summary")
    ap.add_argument("--advise", action="store_true", help="print adviser next-move suggestions")
    ap.add_argument("--runbook", metavar="FILE",
                    help="write an operator runbook (staged checklist + AI operator playbook)")
    ap.add_argument("--limit", type=int, default=6, help="max paths to expand in the runbook")
    ap.add_argument("--model", help="force a specific Ollama model for all roles")
    ap.add_argument("--status", action="store_true", help="print local LLM status and exit")
    args = ap.parse_args(argv)

    if args.status or not args.engagement:
        nfo = status()
        print(f"[advisor] Ollama host : {nfo['host']}")
        print(f"[advisor] available   : {nfo['available']}")
        print(f"[advisor] local models: {', '.join(nfo['models']) or '(none)'}")
        for role, m in nfo["picks"].items():
            print(f"[advisor]   {role:<9}-> {m or '(none)'}")
        if not args.engagement:
            return 0

    eng = _load(args.engagement)
    if not llm.available():
        print("[advisor] no local model reachable — is `ollama serve` up? "
              "(engine features work without it; LLM extras stay off)")
        if args.runbook:
            with open(args.runbook, "w", encoding="utf-8") as fh:
                fh.write(basic_runbook_md(eng))
            print(f"[advisor] wrote deterministic runbook (no AI playbook): {args.runbook}")
        return 0

    model = args.model or None
    did = False
    if args.summary:
        did = True
        print("\n=== Executive summary ===\n")
        print(exec_summary(eng, model=model) or "(model returned nothing)")
    if args.advise:
        did = True
        print("\n=== Adviser — next moves ===\n")
        adv = advise(eng, model=model)
        if not adv:
            print("(no suggestions)")
        for i, a in enumerate(adv, 1):
            tag = f" [{a['attack']}]" if a["attack"] else ""
            print(f"  {i}. {a['suggestion']}{tag}\n     why: {a['why']}")
    if args.runbook:
        did = True
        md = basic_runbook_md(eng)
        add = runbook_addendum_md(eng.get("attack_paths", []),
                                  ctx=None, limit=args.limit, model=model)
        with open(args.runbook, "w", encoding="utf-8") as fh:
            fh.write(md + (add or ""))
        extra = " + AI operator playbook" if add else " (no AI playbook produced)"
        print(f"[advisor] runbook written: {args.runbook}{extra}")
    if not did:
        print("\nNothing to do. Try --summary, --advise or --runbook FILE.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
