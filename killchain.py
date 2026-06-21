#!/usr/bin/env python3
"""
killchain.py — organise an engagement into a 5-stage, kill-chain-aligned playbook.

Authorized / lab / CTF use only.

Maps the engine's findings, per-service methodology and staged ATT&CK attack-path
steps onto the Lockheed-Martin Cyber Kill Chain (5 operator stages; see
docs/kill_chain.md). This is METHODOLOGY + ATT&CK MAPPING + STAGING only — the
engine plans and stages each step; a human operator executes it manually, in
authorized scope, with their own tooling. No payloads, exploitation, implants or
C2 are produced or run.
"""
from __future__ import annotations

# attack_path_engine step `tactic` -> kill-chain stage id
_TACTIC_STAGE = {
    "Reconnaissance": 1,
    "Resource Development": 2,
    "Initial Access": 3, "Execution": 3,
    "Privilege Escalation": 4, "Credential Access": 4, "Lateral Movement": 4,
    "Discovery": 4, "Persistence": 4, "Defense Evasion": 4,
    "Command and Control": 5, "Collection": 5, "Exfiltration": 5, "Impact": 5,
}

# Compact fallback used only if docs/kill_chain.md is unavailable.
_FALLBACK_STAGES = [
    {"id": 1, "name": "Reconnaissance", "phases": ["Reconnaissance"],
     "tactics": ["TA0043 Reconnaissance", "TA0007 Discovery"],
     "objective": "Map the attack surface.", "methodology": [], "boundary": ""},
    {"id": 2, "name": "Weaponization & Vulnerability Analysis", "phases": ["Weaponization"],
     "tactics": ["TA0042 Resource Development"],
     "objective": "Correlate findings to exploitable conditions — planning only.",
     "methodology": [], "boundary": "Engine maps tooling needs; it builds no payloads."},
    {"id": 3, "name": "Delivery & Exploitation", "phases": ["Delivery", "Exploitation"],
     "tactics": ["TA0001 Initial Access", "TA0002 Execution"],
     "objective": "Stage initial-access steps; operator executes manually.",
     "methodology": [], "boundary": "Engine stages only; it launches nothing."},
    {"id": 4, "name": "Post-Exploitation", "phases": ["Installation"],
     "tactics": ["TA0004 Privilege Escalation", "TA0006 Credential Access",
                 "TA0008 Lateral Movement", "TA0007 Discovery", "TA0003 Persistence"],
     "objective": "Methodology for after a foothold.", "methodology": [],
     "boundary": "Enumeration/credential-testing references; the engine performs none of it."},
    {"id": 5, "name": "Command & Control / Actions on Objectives",
     "phases": ["Command and Control", "Actions on Objectives"],
     "tactics": ["TA0011 Command and Control", "TA0009 Collection",
                 "TA0010 Exfiltration", "TA0040 Impact"],
     "objective": "Plan objective actions and report.", "methodology": [],
     "boundary": "The engine never operates C2 or exfiltrates data."},
]


def load_stages(docs_dir=None):
    try:
        from knowledge_loader import load_knowledge
        stages = (load_knowledge(docs_dir).kill_chain or {}).get("stages")
        if stages:
            return stages
    except Exception:                                                  # pragma: no cover
        pass
    return _FALLBACK_STAGES


def build_killchain(report, modules, paths, docs_dir=None):
    """Return the per-stage playbook: stage metadata + the staged attack-path
    steps and findings that fall into each kill-chain stage."""
    stages = load_stages(docs_dir)
    steps_by_stage, paths_by_stage = {s["id"]: [] for s in stages}, {s["id"]: set() for s in stages}
    for p in paths:
        for step in p.get("steps", []):
            sid = _TACTIC_STAGE.get(step.get("tactic", ""))
            if sid in steps_by_stage:
                steps_by_stage[sid].append({**step, "path": p.get("id", "")})
                paths_by_stage[sid].add(p.get("id", ""))

    # CVE / exploitable findings inform stages 2-3; everything else is recon (1).
    cve_findings = [f for f in report.get("findings", []) if f.get("category") == "CVE (vulners)"]

    out = []
    for st in stages:
        sid = st["id"]
        out.append({
            "id": sid, "name": st["name"], "phases": st.get("phases", []),
            "tactics": st.get("tactics", []), "objective": st.get("objective", ""),
            "boundary": st.get("boundary", ""), "methodology": st.get("methodology", []),
            "staged_steps": steps_by_stage.get(sid, []),
            "path_ids": sorted(x for x in paths_by_stage.get(sid, set()) if x),
            "findings": cve_findings if sid in (2, 3) else [],
        })
    return out


def build_markdown(report, modules, paths, docs_dir=None, scan=None):
    kc = build_killchain(report, modules, paths, docs_dir)
    L = ["# Kill-Chain Playbook\n"]
    if scan:
        L.append(f"_Mode: {scan.get('mode', '-')} · Target: {scan.get('target', '-')}_  ")
    L.append("\n> Methodology + ATT&CK mapping + **staging** only. The engine plans and "
             "stages; a human operator executes each step manually, in authorized scope, "
             "with their own tooling. No payloads, exploitation, implants or C2 are produced "
             "or run.\n")
    for st in kc:
        L.append(f"## Stage {st['id']} — {st['name']}")
        L.append(f"_Kill-chain: {', '.join(st['phases'])} · ATT&CK: {', '.join(st['tactics'])}_\n")
        if st["objective"]:
            L.append(st["objective"] + "\n")
        if st["methodology"]:
            L.append("**Methodology (operator references):**")
            for m in st["methodology"]:
                L.append(f"- `{m.get('attack', '')}` {m.get('name', '')} — `{m.get('command', '')}`")
            L.append("")
        if st["staged_steps"]:
            L.append("**Staged from this engagement:**")
            for s in st["staged_steps"]:
                L.append(f"- [ ] [{s['path']}] `{s['technique_id']}` {s['technique']} "
                         f"@ {s['host']} — {s['guidance']}")
            L.append("")
        if st["findings"]:
            L.append(f"**Relevant findings:** {len(st['findings'])} CVE finding(s) — see Stage 2 of the report.\n")
        if st["boundary"]:
            L.append(f"> ⚠ {st['boundary']}\n")
    return "\n".join(L) + "\n"


def write_killchain(report, modules, paths, path, docs_dir=None, scan=None):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_markdown(report, modules, paths, docs_dir, scan))


def coverage_summary(report, modules, paths, docs_dir=None):
    """One line per stage: name + how many staged steps land there. For CLI output."""
    kc = build_killchain(report, modules, paths, docs_dir)
    return [(st["id"], st["name"], len(st["staged_steps"]), len(st["path_ids"])) for st in kc]


if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) < 2:
        print("usage: python killchain.py <report.json | nmap.xml>"); sys.exit(1)
    src = sys.argv[1]
    if src.endswith(".json"):
        rep = json.load(open(src, encoding="utf-8")); mods, paths = rep.get("modules", []), rep.get("attack_paths", [])
        report = rep.get("report", rep)
    else:
        from nmap_analyzer import load_scan, analyze, build_report
        from modules import dispatch
        from attack_path_engine import generate_paths
        hosts, meta, _ = load_scan(src)
        report = build_report(hosts, meta, analyze(hosts))
        mods, paths = dispatch(report), generate_paths(report)
    print(build_markdown(report, mods, paths))
