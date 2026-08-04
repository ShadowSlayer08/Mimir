#!/usr/bin/env python3
"""
ad_graph.py — AD relationship graph: ingest BloodHound-compatible collector output
(BloodHound / SoapHound / RustHound-CE / SharpHound / ldapdomaindump-via-bh) and
derive STAGED privilege-escalation paths to high-value targets.

Authorized / lab / CTF use only.

Boundary: the engine does NOT collect (that authenticated, active step is the
operator's — staged in the active_directory module). It INGESTS the JSON the
operator's collector produced and reasons over it, exactly like evidence.py. It
then STAGES each abusable edge as a guided step (technique + how + opsec) for the
human to execute. It launches nothing.

    # operator collects (their tooling, in scope):
    #   soaphound.py ... --bloodhound   |   rusthound-ce ...   |   bloodhound-python -c All
    python ad_graph.py bloodhound.zip --owned "DOMAIN USERS@LAB"
    (or:  assess ... --bloodhound bloodhound.zip)
"""
from __future__ import annotations

import glob
import json
import os
import zipfile
from collections import defaultdict, deque

# Well-known high-value RIDs (Domain/Enterprise/Schema Admins, DCs, Administrators, ...).
_HIGH_RIDS = ("-512", "-519", "-516", "-518", "-517", "-521", "-498", "-500", "-544")
# Default "what can ANY authenticated user reach" start set.
_ANY_USER = ("-513",)                       # Domain Users; + S-1-5-11 Authenticated Users
_ANY_SIDS = ("S-1-5-11", "S-1-5-21-0-0-0-513")

# edge type -> (technique_id, technique, tactic, how, impact, opsec)
EDGE_ABUSE = {
    "MemberOf": ("T1078", "Valid Accounts", "Privilege Escalation",
                 "Inherit the group's rights (transitive membership).",
                 "You gain everything the group can do.", ""),
    "GenericAll": ("T1098", "Account Manipulation", "Privilege Escalation",
                   "Full control: shadow credentials (certipy shadow auto) or reset password "
                   "(bloodyAD set password) or add to group.", "Full control of the target.",
                   "Prefer shadow creds over a password reset (less disruptive/loud)."),
    "GenericWrite": ("T1098", "Account Manipulation", "Privilege Escalation",
                     "Write attributes: set an SPN for targeted Kerberoast, or "
                     "msDS-KeyCredentialLink for shadow creds.", "Coerce a usable credential.", ""),
    "WriteDacl": ("T1222", "Permissions Modification", "Privilege Escalation",
                  "Grant yourself GenericAll (dacledit.py / bloodyAD add genericAll), then abuse it.",
                  "Escalate to full control.", ""),
    "WriteOwner": ("T1098", "Account Manipulation", "Privilege Escalation",
                   "Set yourself as owner, then WriteDacl -> GenericAll.", "Full control of the target.", ""),
    "Owns": ("T1098", "Account Manipulation", "Privilege Escalation",
             "As owner, set WriteDacl -> GenericAll.", "Full control of the target.", ""),
    "ForceChangePassword": ("T1098", "Account Manipulation", "Privilege Escalation",
                            "Reset the target's password (net rpc password / bloodyAD).",
                            "Authenticate as the target.",
                            "Resetting a live account is disruptive; coordinate with the client."),
    "AddMember": ("T1098", "Account Manipulation", "Privilege Escalation",
                  "Add yourself to the group (bloodyAD add groupMember / net group).",
                  "Inherit the group's privileges.", ""),
    "AddSelf": ("T1098", "Account Manipulation", "Privilege Escalation",
                "Add yourself to the group.", "Inherit the group's privileges.", ""),
    "AddKeyCredentialLink": ("T1556", "Modify Authentication Process", "Credential Access",
                             "Shadow credentials: add a KeyCredential and PKINIT (certipy shadow auto / pywhisker).",
                             "Obtain the target's NT hash / a TGT.", ""),
    "AllExtendedRights": ("T1098", "Account Manipulation", "Privilege Escalation",
                          "ForceChangePassword (users) or DCSync rights (domain).",
                          "Escalate against the target.", ""),
    "GetChanges": ("T1003.006", "DCSync", "Credential Access",
                   "With GetChangesAll, DCSync the domain.", "Replicate domain secrets.", ""),
    "GetChangesAll": ("T1003.006", "DCSync", "Credential Access",
                      "DCSync: replicate secrets (secretsdump.py -just-dc).",
                      "krbtgt + all domain hashes.", ""),
    "DCSync": ("T1003.006", "DCSync", "Credential Access",
               "DCSync the domain (secretsdump -just-dc / mimikatz lsadump::dcsync).",
               "krbtgt + all domain hashes -> full compromise.", ""),
    "AdminTo": ("T1021.002", "Remote Services: SMB Admin Shares", "Lateral Movement",
                "Local admin: dump creds (secretsdump / lsass) and move (psexec/wmiexec/nxc).",
                "Code execution + credentials on the host.", ""),
    "HasSession": ("T1003", "OS Credential Dumping", "Credential Access",
                   "Own the host, then harvest the session's credentials from LSASS.",
                   "Recover the logged-on user's credentials.", ""),
    "CanRDP": ("T1021.001", "Remote Services: RDP", "Lateral Movement",
               "RDP to the host with these credentials.", "Interactive access.", ""),
    "CanPSRemote": ("T1021.006", "Remote Services: WinRM", "Lateral Movement",
                    "PS-Remote / WinRM to the host (evil-winrm).", "Remote execution.", ""),
    "ExecuteDCOM": ("T1021.003", "Remote Services: DCOM", "Lateral Movement",
                    "Execute via DCOM.", "Remote execution.", ""),
    "AllowedToDelegate": ("T1558.003", "Kerberoasting / S4U", "Credential Access",
                          "Constrained delegation: s4u impersonate (getST -impersonate).",
                          "Impersonate any user to the target SPN.", ""),
    "AllowedToAct": ("T1134.001", "Access Token Manipulation", "Privilege Escalation",
                     "RBCD: s4u impersonate (getST -impersonate).", "Impersonate any user on the host.", ""),
    "AddAllowedToAct": ("T1134.001", "Access Token Manipulation", "Privilege Escalation",
                        "Configure RBCD (rbcd.py) then s4u impersonate any user (getST).",
                        "Impersonate any user on the host.", ""),
    "Enroll": ("T1649", "Forge Authentication Certificates", "Credential Access",
               "Enroll against the vulnerable template (certipy req) to auth as a privileged user.",
               "Certificate -> TGT as a high-value account.", ""),
}
_DEFAULT_ABUSE = ("T1078", "Valid Accounts", "Lateral Movement", "Traverse this relationship.", "", "")


def _rid_high(sid):
    return isinstance(sid, str) and any(sid.endswith(r) for r in _HIGH_RIDS)


def _results(obj):
    """BloodHound wraps some collections as {'Results': [...]} (or a bare list)."""
    if isinstance(obj, dict):
        return obj.get("Results", []) or []
    if isinstance(obj, list):
        return obj
    return []


def _iter_json(path):
    """Yield parsed BloodHound JSON documents from a .zip, a directory, or a file."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.lower().endswith(".json"):
                    try:
                        yield json.loads(z.read(n).decode("utf-8", "ignore"))
                    except Exception:
                        continue
        return
    files = (sorted(glob.glob(os.path.join(path, "*.json"))) if os.path.isdir(path) else [path])
    for f in files:
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                yield json.load(fh)
        except Exception:
            continue


_TYPE = {"users": "User", "groups": "Group", "computers": "Computer", "domains": "Domain",
         "gpos": "GPO", "ous": "OU", "containers": "Container", "certtemplates": "CertTemplate",
         "cas": "CA"}


class ADGraph:
    def __init__(self):
        self.nodes = {}                        # sid -> {sid,name,type,highvalue}
        self.edges = defaultdict(list)         # src_sid -> [(dst_sid, edge_type)]
        self.high = set()
        self.owned = set()

    # -- build -----------------------------------------------------------
    def add_node(self, sid, name, ntype, highvalue=False):
        if not sid:
            return
        self.nodes[sid] = {"sid": sid, "name": (name or sid).upper(), "type": ntype,
                           "highvalue": bool(highvalue) or _rid_high(sid)}
        if self.nodes[sid]["highvalue"]:
            self.high.add(sid)

    def add_edge(self, src, dst, etype):
        if src and dst and src != dst:
            self.edges[src].append((dst, etype))

    def load_bloodhound(self, path):
        for doc in _iter_json(path):
            if not isinstance(doc, dict):
                continue
            typ = (doc.get("meta") or {}).get("type", "")
            for obj in doc.get("data", []) or []:
                self._ingest(obj, typ)
        return self

    def _ingest(self, obj, typ):
        if not isinstance(obj, dict):
            return
        props = obj.get("Properties", {}) or {}
        sid = obj.get("ObjectIdentifier") or props.get("objectid")
        if not sid:
            return
        name = props.get("name") or props.get("distinguishedname") or sid
        self.add_node(sid, name, _TYPE.get(typ, "Base"), props.get("highvalue"))
        # ACEs: principal --RightName--> this object
        for ace in obj.get("Aces", []) or []:
            self.add_edge(ace.get("PrincipalSID"), sid, ace.get("RightName", "") or "GenericAll")
        # membership: member --MemberOf--> group
        for m in obj.get("Members", []) or []:
            self.add_edge(m.get("ObjectIdentifier"), sid, "MemberOf")
        # local admins / sessions / RBCD / delegation (computers)
        for a in _results(obj.get("LocalAdmins")):
            self.add_edge(a.get("ObjectIdentifier"), sid, "AdminTo")
        for r in _results(obj.get("PSRemoteUsers")):
            self.add_edge(r.get("ObjectIdentifier"), sid, "CanPSRemote")
        for r in _results(obj.get("RemoteDesktopUsers")):
            self.add_edge(r.get("ObjectIdentifier"), sid, "CanRDP")
        for s in _results(obj.get("Sessions")):
            self.add_edge(sid, s.get("UserSID") or s.get("ObjectIdentifier"), "HasSession")
        for d in _results(obj.get("AllowedToAct")):
            self.add_edge(d.get("ObjectIdentifier"), sid, "AddAllowedToAct")
        for d in obj.get("AllowedToDelegate", []) or []:
            tgt = d.get("ObjectIdentifier") if isinstance(d, dict) else d
            self.add_edge(sid, tgt, "AllowedToDelegate")

    # -- analyse ---------------------------------------------------------
    def seed_owned(self, names=()):
        want = {str(n).lower() for n in (names or ())}
        for sid, n in self.nodes.items():
            if sid.lower() in want or n["name"].lower() in want:
                self.owned.add(sid)
        if not self.owned:                     # default: what ANY authenticated user can reach
            for sid, n in self.nodes.items():
                if (any(sid.endswith(r) for r in _ANY_USER) or sid in _ANY_SIDS
                        or n["name"].lower().startswith(("domain users@", "authenticated users@"))):
                    self.owned.add(sid)
        return self.owned

    def _bfs(self, start, max_depth):
        prev = {start: None}
        q = deque([(start, 0)])
        while q:
            node, d = q.popleft()
            if node in self.high and node != start:
                edges, cur = [], node
                while prev[cur] is not None:
                    p, et = prev[cur]
                    edges.append((p, et, cur))
                    cur = p
                return list(reversed(edges))
            if d >= max_depth:
                continue
            for dst, et in self.edges.get(node, []):
                if dst not in prev:
                    prev[dst] = (node, et)
                    q.append((dst, d + 1))
        return None

    def paths_to_high(self, max_paths=25, max_depth=10):
        seen, out = set(), []
        for start in sorted(self.owned):
            ep = self._bfs(start, max_depth)
            if ep:
                key = tuple((s, e, d) for s, e, d in ep)
                if key not in seen:
                    seen.add(key)
                    out.append(ep)
        out.sort(key=len)
        return out[:max_paths]


def derive_paths(graph, max_paths=25):
    """BloodHound edge-paths -> staged attack_path dicts (engine shape)."""
    paths = []
    for i, ep in enumerate(graph.paths_to_high(max_paths=max_paths), 1):
        steps = []
        for order, (src, et, dst) in enumerate(ep, 1):
            tid, tname, tactic, how, impact, opsec = EDGE_ABUSE.get(et, _DEFAULT_ABUSE)
            dname = graph.nodes.get(dst, {}).get("name", dst)
            sname = graph.nodes.get(src, {}).get("name", src)
            steps.append({
                "order": order, "tactic": tactic, "technique_id": tid, "technique": tname,
                "host": dname, "basis": f"{sname} --{et}--> {dname}", "guidance": how,
                "abuse": {"impact": impact or f"Gain control of {dname}.", "how": how, "opsec": opsec}})
        start = graph.nodes.get(ep[0][0], {}).get("name", ep[0][0])
        end = graph.nodes.get(ep[-1][2], {}).get("name", ep[-1][2])
        paths.append({
            "id": f"AD-{i:03d}", "name": f"{start} -> {end}", "kind": "domain",
            "severity": "critical", "confidence": "high", "score": 100 + len(steps),
            "hosts": [start, end], "tactics": sorted({s["tactic"] for s in steps}),
            "rationale": "BloodHound-derived privilege-escalation path to a high-value target; "
                         "confirm each edge and execute manually, in scope.",
            "steps": steps})
    return paths


def ingest(path, owned=()):
    """(graph, staged_attack_paths) from a collector export. Ingest + stage only."""
    g = ADGraph().load_bloodhound(path)
    g.seed_owned(owned)
    return g, derive_paths(g)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="ad_graph.py",
                                 description="ingest BloodHound/SoapHound/RustHound output -> "
                                             "staged AD attack paths")
    ap.add_argument("export", help="BloodHound .zip / directory / .json")
    ap.add_argument("--owned", action="append", default=[],
                    help="starting principal name or SID (repeatable; default: Domain Users)")
    args = ap.parse_args(argv)
    g, paths = ingest(args.export, args.owned)
    print(f"[+] graph: {len(g.nodes)} nodes, {sum(len(v) for v in g.edges.values())} edges, "
          f"{len(g.high)} high-value; owned start: {len(g.owned)}")
    if not paths:
        print("    no privilege-escalation path found to a high-value target.")
    for p in paths:
        print(f"\n  {p['id']}  {p['name']}  [{p['severity']}]")
        for s in p["steps"]:
            print(f"    {s['order']}. {s['tactic']:22} {s['technique_id']:10} {s['basis']}")
            print(f"       -> {s['guidance']}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
