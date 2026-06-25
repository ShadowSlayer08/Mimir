#!/usr/bin/env python3
"""
attack_path_engine.py  —  Correlate nmap-analyzer findings into attack paths.

Authorized / lab / CTF use only.

This module performs ANALYSIS ONLY. It turns a set of findings into candidate
attack *paths* — ordered chains of MITRE ATT&CK techniques an operator could
pursue — scored and explained. It contains no exploit code and executes
nothing; every step is a planning artifact for a human operator to validate
and carry out manually, within an authorized engagement.

A path is a list of Steps:  (tactic, ATT&CK technique, host, basis, guidance).
Generation covers:
  * single-host RCE chains (confirmed vuln scans, exploitable CVEs, unauth services)
  * credential-exposure -> valid-accounts -> lateral-movement chains across hosts
  * domain-compromise chains when a domain controller is reachable
"""
from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field, asdict

SEV_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# MITRE ATT&CK technique names (subset relevant to network findings).
TECH = {
    "T1190": "Exploit Public-Facing Application",
    "T1210": "Exploitation of Remote Services",
    "T1068": "Exploitation for Privilege Escalation",
    "T1078": "Valid Accounts",
    "T1021": "Remote Services",
    "T1021.001": "Remote Services: RDP",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.004": "Remote Services: SSH",
    "T1003": "OS Credential Dumping",
    "T1040": "Network Sniffing",
    "T1557": "Adversary-in-the-Middle",
    "T1552": "Unsecured Credentials",
    "T1213": "Data from Information Repositories",
    "T1005": "Data from Local System",
    "T1482": "Domain Trust Discovery",
}

REMOTE_SVC_TECH = {
    "ms-wbt-server": "T1021.001", "rdp": "T1021.001",
    "microsoft-ds": "T1021.002", "netbios-ssn": "T1021.002", "smb": "T1021.002",
    "ssh": "T1021.004",
    "winrm": "T1021.006", "wsman": "T1021.006",
    "vnc": "T1021.005", "vnc-http": "T1021.005",
    "mysql": "T1078", "ms-sql-s": "T1078", "postgresql": "T1078",
    "mongodb": "T1078", "redis": "T1078",
    "ftp": "T1078", "telnet": "T1078",
    # Web/application services are public-facing initial-access surface, so an app
    # finding chains into the host's onward (lateral/AD) paths — cross-layer.
    "http": "T1190", "https": "T1190", "http-alt": "T1190",
    "http-proxy": "T1190", "www": "T1190", "soap": "T1190",
}
CRED_SOURCE_HINTS = ("heartbleed", "telnet", "cleartext", "anonymous ftp",
                     "default cred", "snmp", "ftp is cleartext")
DC_SERVICE_HINTS = ("kerberos", "ldap", "kpasswd", "ldapssl", "globalcat")


@dataclass
class Step:
    order: int
    tactic: str
    technique_id: str
    technique: str
    host: str
    basis: str       # the finding/condition that enables this step
    guidance: str    # high-level operator guidance (no payloads)

    def to_dict(self):
        return asdict(self)


@dataclass
class AttackPath:
    id: str
    name: str
    kind: str                  # rce | lateral | domain
    severity: str
    confidence: str            # high | medium | low
    score: int
    hosts: list
    steps: list
    rationale: str

    def to_dict(self):
        d = asdict(self)
        d["steps"] = [s.to_dict() if isinstance(s, Step) else s for s in self.steps]
        d["tactics"] = self.tactics()
        return d

    def tactics(self):
        seen = []
        for s in self.steps:
            t = s.tactic if isinstance(s, Step) else s["tactic"]
            if t not in seen:
                seen.append(t)
        return seen


# --------------------------------------------------------------------------- #
# Capability extraction from findings
# --------------------------------------------------------------------------- #
def _host_services(report):
    """host -> set of service names (from parsed hosts, if present)."""
    out = {}
    for h in report.get("hosts", []):
        label = (h["hostnames"][0] if h.get("hostnames") else h.get("ip")) or "?"
        out[label] = {(p["service"].get("name") or "").lower() for p in h.get("ports", [])}
    return out


def _is_dc(label, services):
    if re.search(r"(?i)(^|[^a-z])dc\d*([^a-z]|$)", label):
        return True
    return any(any(hint in s for hint in DC_SERVICE_HINTS) for s in services)


def _capabilities(findings):
    """host -> list of capability dicts derived from its findings."""
    caps = {}
    for f in findings:
        host, title = f["host"], f["title"].lower()
        sev, cat = f["severity"], f["category"]
        cap = None
        if "ms17-010" in title or "eternalblue" in title or "ms08-067" in title:
            cap = ("rce_system", "T1190", "high",
                   "Confirmed unauthenticated RCE to SYSTEM via SMB.")
        elif "sambacry" in title or "cve-2017-7494" in title:
            cap = ("rce_system", "T1190", "high", "Confirmed Samba RCE to root.")
        elif cat == "CVE (vulners)" and sev in ("critical", "high") and "exploit" in title:
            cap = ("rce", "T1190", "medium",
                   "Public exploit reported for this service version; validate applicability.")
        elif "redis exposed" in title:
            cap = ("rce", "T1190", "medium",
                   "Unauthenticated Redis can often be leveraged to write files / load modules.")
        elif "heartbleed" in title:
            cap = ("cred_exposure", "T1552", "high",
                   "Memory disclosure can leak private keys, session tokens or credentials.")
        elif "default cred" in title:
            cap = ("cred_exposure", "T1078", "high", "Default credentials grant direct access.")
        elif "telnet" in title or "cleartext" in title or "ftp is cleartext" in title:
            cap = ("cred_exposure", "T1040", "medium",
                   "Cleartext protocol exposes credentials to sniffing / AiTM on-path.")
        elif "anonymous ftp" in title:
            cap = ("data_access", "T1078", "high", "Anonymous access exposes file contents.")
        elif "tftp" in title:
            cap = ("cred_exposure", "T1602", "medium",
                   "TFTP has no auth; device configs/firmware fetched over it often embed credentials.")
        elif "rsync" in title or "nfs export" in title or "nfs" in title:
            cap = ("data_access", "T1135", "medium",
                   "Network file share/export may expose readable (or writable) data.")
        elif "x11" in title:
            cap = ("cred_exposure", "T1056.001", "medium",
                   "Open X11 display enables screen capture and keystroke logging.")
        elif "ipmi" in title or "bmc" in title:
            cap = ("cred_exposure", "T1552", "high",
                   "BMC weaknesses (RAKP hash leak / default creds) yield out-of-band control and credentials.")
        elif cat == "Evidence" and any(k in title for k in
                                       ("credential", "hash", "private key", "password")):
            cap = ("cred_exposure", "T1552", "high",
                   "Credential material recovered from prior evidence; test reuse against "
                   "reachable services (valid accounts -> lateral movement).")
        elif cat == "Database":
            cap = ("data_access", "T1213", "medium", "Network-reachable datastore.")
        if cap:
            caps.setdefault(host, []).append(
                {"cap": cap[0], "tech": cap[1], "confidence": cap[2],
                 "guidance": cap[3], "basis": f["title"], "severity": sev})
    return caps


def _path_severity(bases):
    return min((b["severity"] for b in bases), key=lambda s: SEV_RANK.get(s, 9)) if bases else "info"


def _conf_min(*levels):
    order = ["low", "medium", "high"]
    return min(levels, key=lambda c: order.index(c) if c in order else 0)


# --------------------------------------------------------------------------- #
# Path generation
# --------------------------------------------------------------------------- #
def generate_paths(report):
    findings = report.get("findings", [])
    services = _host_services(report)
    caps = _capabilities(findings)
    paths = []
    counter = itertools.count(1)

    def mkid():
        return f"AP-{next(counter):03d}"

    # ---- 1. single-host RCE chains ----
    for host, hcaps in caps.items():
        for c in [c for c in hcaps if c["cap"] in ("rce", "rce_system")]:
            steps = [Step(1, "Initial Access", c["tech"], TECH[c["tech"]], host,
                          c["basis"], c["guidance"] + " Confirm target is in scope first.")]
            system = c["cap"] == "rce_system"
            if system:
                steps.append(Step(2, "Privilege Escalation", "T1068", TECH["T1068"], host,
                                  c["basis"], "Exploit yields SYSTEM/root directly."))
                steps.append(Step(3, "Credential Access", "T1003", TECH["T1003"], host,
                                  c["basis"], "From SYSTEM, harvest local credentials / hashes."))
            sev = "critical" if system else _path_severity([c])
            score = SEV_WEIGHT.get(sev, 0) + (30 if system else 0)
            paths.append(AttackPath(
                mkid(), f"RCE on {host} via {c['basis'][:40]}",
                "rce", sev, c["confidence"], score, [host], steps,
                "Direct foothold from a single confirmed exposure."))

    # ---- 2. credential-exposure -> lateral movement ----
    cred_hosts = {h: [c for c in cs if c["cap"] in ("cred_exposure", "data_access")]
                  for h, cs in caps.items()}
    cred_hosts = {h: cs for h, cs in cred_hosts.items() if cs}
    for src, scaps in cred_hosts.items():
        best = min(scaps, key=lambda c: SEV_RANK.get(c["severity"], 9))
        for dst, dsvcs in services.items():
            if dst == src:
                continue
            remote = sorted((s, REMOTE_SVC_TECH[s]) for s in dsvcs if s in REMOTE_SVC_TECH)
            if not remote:
                continue
            svc, tech = remote[0]
            steps = [
                Step(1, "Credential Access", best["tech"], TECH[best["tech"]], src,
                     best["basis"], best["guidance"]),
                Step(2, "Lateral Movement", "T1078", TECH["T1078"], dst,
                     f"reuse creds from {src}",
                     "Try recovered/valid credentials against the remote service (assumes reuse)."),
                Step(3, "Lateral Movement", tech, TECH[tech], dst,
                     f"{svc} on {dst}", f"Authenticate to {svc} to gain a foothold on {dst}."),
            ]
            sev = _path_severity(scaps)
            score = SEV_WEIGHT.get(sev, 0) + 10
            paths.append(AttackPath(
                mkid(), f"{src} \u2192 {dst} via credential reuse ({svc})",
                "lateral", sev, _conf_min(best["confidence"], "low"), score,
                [src, dst], steps,
                "Credentials/keys exposed on one host reused to move to another. "
                "Speculative until credential reuse is confirmed."))

    # ---- 3. domain-compromise chains ----
    dc_hosts = [h for h, svcs in services.items() if _is_dc(h, svcs)]
    for dc in dc_hosts:
        # is there any path that lands on the DC?
        reaches_dc = [p for p in paths if dc in p.hosts and p.kind in ("rce", "lateral")]
        if not reaches_dc:
            continue
        seed = max(reaches_dc, key=lambda p: p.score)
        steps = list(seed.steps)
        n = len(steps)
        already_dumped = any(
            (s.technique_id if isinstance(s, Step) else s["technique_id"]) == "T1003"
            and (s.host if isinstance(s, Step) else s["host"]) == dc for s in steps)
        if not already_dumped:
            n += 1
            steps.append(Step(n, "Credential Access", "T1003", TECH["T1003"], dc,
                              "foothold on domain controller",
                              "Dump domain credential material (e.g., from the directory database) once SYSTEM on the DC."))
        steps += [
            Step(n + 1, "Discovery", "T1482", TECH["T1482"], dc,
                 "domain controller", "Enumerate domain trusts and high-value targets."),
            Step(n + 2, "Lateral Movement", "T1078", TECH["T1078"], dc,
                 "domain credentials", "Use domain credentials for organisation-wide access."),
        ]
        score = seed.score + 40
        paths.append(AttackPath(
            mkid(), f"Domain compromise via {dc}", "domain", "critical",
            _conf_min(seed.confidence, "medium"), score, sorted(set(seed.hosts + [dc])),
            steps, f"{dc} appears to be a domain controller; compromising it escalates "
                   "a host foothold to full domain control."))

    paths.sort(key=lambda p: (-p.score, SEV_RANK.get(p.severity, 9)))
    # Dedup near-identical chains (same kind, hosts and technique sequence); the
    # highest-scoring instance survives because the list is already score-sorted.
    seen, deduped = set(), []
    for p in paths:
        sig = (p.kind, tuple(sorted(p.hosts)),
               tuple((s.technique_id if isinstance(s, Step) else s["technique_id"])
                     for s in p.steps))
        if sig in seen:
            continue
        seen.add(sig)
        deduped.append(p)
    result = [p.to_dict() for p in deduped]
    # Attach BloodHound-style abuse insight to each step (guided, human-led).
    try:
        from abuse import abuse_for, load_info
        info = load_info()
        for p in result:
            for s in p["steps"]:
                a = abuse_for(s.get("technique_id", ""), info)
                if a:
                    s["abuse"] = a
    except Exception:                                                  # pragma: no cover
        pass
    return result


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import json
    import sys
    # UTF-8 stdio so path names containing '→' don't crash on a legacy Windows
    # code page (the .json path below never imports nmap_analyzer, which would
    # otherwise have done this for us).
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if len(sys.argv) < 2:
        print("usage: attack_path_engine.py <nmap.xml | report.json>")
        sys.exit(1)
    src = sys.argv[1]
    if src.endswith(".json"):
        report = json.load(open(src, encoding="utf-8"))
    else:
        from nmap_analyzer import load_scan, analyze, build_report
        hosts, meta, _ = load_scan(src)
        report = build_report(hosts, meta, analyze(hosts))
    paths = generate_paths(report)
    print(f"[+] {len(paths)} attack path(s)\n")
    for p in paths:
        print(f"  {p['id']}  [{p['severity'].upper():8}] conf={p['confidence']:6} "
              f"score={p['score']:<4} {p['name']}")
        for s in p["steps"]:
            print(f"        {s['order']}. {s['tactic']:20} {s['technique_id']:9} "
                  f"{s['technique']}  @ {s['host']}")
        print()
