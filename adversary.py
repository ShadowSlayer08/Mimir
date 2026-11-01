#!/usr/bin/env python3
"""
adversary.py — adversary emulation profiles (Caldera-inspired TTP overlays).

Authorized / lab / CTF / VAPT / red-team use only.

A profile is a named *ordered sequence* of ATT&CK technique ids drawn from a
specific threat actor's documented TTP library. Mimir uses profiles two ways:

  1. As a FILTER / OVERLAY for the co-pilot — when `copilot.recommend(...,
     adversary='APT29')` is set, actions whose technique matches the profile
     get a bounded +15 score bonus (and are tagged `profile_match`).
  2. As a METHODOLOGY GENERATOR — `adversary.profile_as_path(profile)` emits a
     staged attack-path shape listing every TTP in the profile's order, so an
     operator can walk through the actor's playbook on their engagement.

Grounded in MITRE ATT&CK, CTID emulation plans and public threat-actor reports.
This is methodology; the engine runs nothing.

Profiles shipped:
  * apt29 (Cozy Bear, SVR)       — long-dwell cloud + identity + sideloading
  * apt28 (Fancy Bear, GRU)      — spear-phish + lateral + credential-access
  * fin7                         — financially-motivated; Carbanak-style post-ex
  * volt_typhoon                 — living-off-the-land; stealth lateral
  * lazarus                      — supply-chain + crypto theft
  * conti / lockbit              — ransomware groups (operator-vocabulary)
  * initial_access               — purely-recon synthetic profile
  * post_exploitation            — synthetic "after a foothold" profile
"""
from __future__ import annotations

import json
import sys


# Profile model: (short name, long name, ordered TTP list, notes)
_PROFILES = {
    "apt29": {
        "name": "APT29 (Cozy Bear / SVR)",
        "notes": "Long-dwell state-sponsored; cloud + identity-focused post-SolarWinds. "
                 "Preferred tradecraft: supply chain, token theft, OAuth app abuse, "
                 "Golden SAML, service-principal escalation.",
        "ttps": [
            ("T1195.002", "Compromise Software Supply Chain"),
            ("T1078.004", "Valid Accounts — Cloud Accounts"),
            ("T1528",     "Steal Application Access Token"),
            ("T1550.001", "Application Access Token"),
            ("T1606.002", "Forge Web Credentials — SAML"),
            ("T1098.001", "Account Manipulation — Additional Cloud Credentials"),
            ("T1098.003", "Account Manipulation — Additional Cloud Roles"),
            ("T1555.005", "Credentials from Password Managers"),
            ("T1552.004", "Private Keys"),
            ("T1114.003", "Email Collection — Email Forwarding Rule"),
            ("T1486",     "Data Encrypted for Impact (rare but staged)"),
        ],
    },
    "apt28": {
        "name": "APT28 (Fancy Bear / GRU 26165)",
        "notes": "Spear-phishing + credential-harvesting; heavy use of X-Agent + "
                 "Zebrocy; later moved to legitimate services (Dropbox, pCloud) for C2.",
        "ttps": [
            ("T1566.001", "Spearphishing Attachment"),
            ("T1204.002", "User Execution — Malicious File"),
            ("T1056.001", "Keylogging"),
            ("T1555.003", "Credentials from Web Browsers"),
            ("T1021.001", "RDP Lateral"),
            ("T1021.002", "SMB / Admin Shares"),
            ("T1003.001", "LSASS Memory Dump"),
            ("T1070.004", "File Deletion"),
            ("T1041",     "Exfil over C2 channel"),
        ],
    },
    "fin7": {
        "name": "FIN7 (Carbanak-adjacent)",
        "notes": "Financially-motivated; LNK + ISO delivery, custom Carbanak backdoor, "
                 "SQL-server lateral movement, PoS card-track theft, 2024+ pivot to "
                 "ransomware affiliate work.",
        "ttps": [
            ("T1566.001", "Spearphishing Attachment"),
            ("T1204.002", "User Execution"),
            ("T1053.005", "Scheduled Task"),
            ("T1055",     "Process Injection"),
            ("T1562.001", "Impair Defenses — Disable AV/EDR"),
            ("T1021.002", "SMB Lateral"),
            ("T1003.001", "LSASS Dump"),
            ("T1486",     "Data Encrypted for Impact (ransomware pivot)"),
            ("T1041",     "Exfil over C2"),
        ],
    },
    "volt_typhoon": {
        "name": "Volt Typhoon (PRC — critical infra)",
        "notes": "Living-off-the-land; stealth-first; targets critical infra (ICS-adjacent). "
                 "Minimal binaries, maximal LOLBAS, long dwell. Uses SOHO device compromise "
                 "for operational relay.",
        "ttps": [
            ("T1133",     "External Remote Services"),
            ("T1190",     "Exploit Public-Facing App (edge devices)"),
            ("T1078",     "Valid Accounts"),
            ("T1059.003", "Windows Command Shell"),
            ("T1047",     "WMI"),
            ("T1003.003", "NTDS Dumping"),
            ("T1021.002", "SMB Admin Shares"),
            ("T1070",     "Indicator Removal"),
            ("T1049",     "System Network Connections Discovery"),
            ("T1016",     "System Network Configuration Discovery"),
        ],
    },
    "lazarus": {
        "name": "Lazarus (DPRK)",
        "notes": "Supply-chain + crypto-targeted; recent ops heavily around 3CX / "
                 "crypto-exchange SWIFT + wallet theft. Macro-less loaders; signed samples.",
        "ttps": [
            ("T1195.002", "Compromise Software Supply Chain"),
            ("T1566.002", "Spearphishing Link"),
            ("T1553.002", "Code Signing"),
            ("T1055.001", "DLL Injection"),
            ("T1057",     "Process Discovery"),
            ("T1552.001", "Credentials in Files"),
            ("T1555.001", "Keychain"),
            ("T1041",     "Exfil over C2"),
            ("T1657",     "Financial Theft"),
        ],
    },
    "conti": {
        "name": "Conti / LockBit (ransomware affiliate playbook)",
        "notes": "Operator-grade ransomware affiliate workflow — Qakbot / IcedID loader, "
                 "Cobalt Strike beacon, AD attack via RDP + SMB + credential dumping, "
                 "deploy over SMB admin shares.",
        "ttps": [
            ("T1566.001", "Spearphishing Attachment"),
            ("T1204.002", "User Execution"),
            ("T1055",     "Process Injection"),
            ("T1021.001", "RDP"),
            ("T1021.002", "SMB Admin Shares"),
            ("T1003.001", "LSASS Dump"),
            ("T1558.003", "Kerberoasting"),
            ("T1562.001", "Disable AV / EDR"),
            ("T1489",     "Service Stop"),
            ("T1486",     "Data Encrypted for Impact"),
            ("T1490",     "Inhibit System Recovery"),
        ],
    },
    "initial_access": {
        "name": "Initial Access playbook (synthetic)",
        "notes": "Not an actor — a synthetic profile that covers the top T1190 / T1566 "
                 "vectors a red team walks on day one.",
        "ttps": [
            ("T1595.001", "Active Scanning — IP Block"),
            ("T1595.002", "Vulnerability Scanning"),
            ("T1590.005", "Gather Victim Network Information — IPs"),
            ("T1589.002", "Email Addresses"),
            ("T1190",     "Exploit Public-Facing App"),
            ("T1566.001", "Spearphishing Attachment"),
            ("T1566.002", "Spearphishing Link"),
            ("T1133",     "External Remote Services"),
        ],
    },
    "post_exploitation": {
        "name": "Post-exploitation playbook (synthetic)",
        "notes": "After a foothold — enumerate, escalate, dump credentials, pivot.",
        "ttps": [
            ("T1082",     "System Information Discovery"),
            ("T1016",     "System Network Configuration Discovery"),
            ("T1087.001", "Local Account Discovery"),
            ("T1087.002", "Domain Account Discovery"),
            ("T1069.001", "Local Groups"),
            ("T1069.002", "Domain Groups"),
            ("T1068",     "Exploitation for Privilege Escalation"),
            ("T1003.001", "LSASS Dump"),
            ("T1558.003", "Kerberoasting"),
            ("T1482",     "Domain Trust Discovery"),
            ("T1021.002", "SMB Admin Shares"),
            ("T1098",     "Account Manipulation"),
        ],
    },
}


def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                          # pragma: no cover
            pass


_force_utf8_stdio()


# --------------------------------------------------------------------------- #
def list_profiles():
    """Return profile summaries — the list the CLI / web GUI shows."""
    out = []
    for k, p in _PROFILES.items():
        out.append({"id": k, "name": p["name"],
                    "ttps": len(p["ttps"]),
                    "notes": p["notes"]})
    return sorted(out, key=lambda x: x["id"])


def get(profile_id):
    """Return the raw profile dict or None if unknown."""
    return _PROFILES.get((profile_id or "").strip().lower())


def ttp_set(profile_id):
    """Return the set of ATT&CK ids in a profile. Empty set on unknown."""
    p = get(profile_id)
    return {t[0] for t in (p or {}).get("ttps", [])}


def profile_as_path(profile_id, target="scope"):
    """Project a profile as a staged attack-path (same shape attack_path_engine
    emits). Lets the operator walk the actor's playbook across their engagement."""
    p = get(profile_id)
    if not p:
        return None
    steps = []
    for i, (tech_id, tech_name) in enumerate(p["ttps"], 1):
        steps.append({
            "order": i, "tactic": "Adversary Emulation",
            "technique_id": tech_id, "technique": tech_name,
            "host": target,
            "guidance": f"TTP #{i} of {p['name']} emulation plan.",
            "basis": p["name"],
        })
    return {
        "id": f"ADV-{profile_id.upper()}",
        "name": f"Adversary emulation — {p['name']}",
        "kind": "adversary",
        "severity": "high", "confidence": "medium", "score": 90,
        "hosts": [target], "tactics": ["Adversary Emulation"],
        "rationale": p["notes"],
        "steps": steps,
    }


def apply_overlay(actions, profile_id, bonus=15):
    """Non-destructive. For each action whose `attack` matches a TTP in the
    profile, add `profile_match` + a bounded score bonus. Caller re-sorts."""
    tset = ttp_set(profile_id)
    if not tset:
        return actions
    out = []
    for a in actions or []:
        tech = (a.get("attack") or "").strip()
        if tech in tset:
            b = dict(a)
            b["score"] = int(b.get("score", 0)) + int(bonus)
            tr = dict(b.get("trace") or {})
            tr["profile_match"] = profile_id
            tr["profile_bonus"] = int(bonus)
            b["trace"] = tr
            out.append(b)
        else:
            out.append(a)
    return out


def to_markdown(profile_id):
    p = get(profile_id)
    if not p:
        return f"# Unknown profile: {profile_id}\n"
    L = [f"# Adversary emulation — {p['name']}", "", f"_{p['notes']}_", "",
         "## TTP sequence (ordered)", ""]
    for i, (tech_id, tech_name) in enumerate(p["ttps"], 1):
        L.append(f"{i}. `{tech_id}` — {tech_name}")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------- #
def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="mimir-adversary",
                                 description="adversary emulation profiles (Caldera-inspired)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list all profiles")
    s = sub.add_parser("show", help="print a profile's TTP sequence as Markdown")
    s.add_argument("profile")
    j = sub.add_parser("path", help="emit a profile as a staged attack-path JSON")
    j.add_argument("profile")
    j.add_argument("--target", default="scope")
    args = ap.parse_args(argv)
    if args.cmd == "list":
        for p in list_profiles():
            print(f"  {p['id']:<22} {p['ttps']:>3} TTP(s)  — {p['name']}")
            print(f"      {p['notes'][:90]}")
        return 0
    if args.cmd == "show":
        sys.stdout.write(to_markdown(args.profile))
        return 0
    if args.cmd == "path":
        p = profile_as_path(args.profile, args.target)
        if not p:
            print(f"[adversary] unknown profile: {args.profile}", file=sys.stderr)
            return 1
        print(json.dumps(p, indent=2))
        return 0


if __name__ == "__main__":
    sys.exit(main())
