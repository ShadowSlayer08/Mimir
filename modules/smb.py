#!/usr/bin/env python3
"""modules.smb — SMB / NetBIOS assessment methodology."""
from __future__ import annotations

from .base import Module, ModuleResult, Check, host_label, worst


class SMBModule(Module):
    name = "smb"
    title = "SMB / NetBIOS"
    NAMES = ("microsoft-ds", "netbios-ssn", "smb")

    def assess(self, host, findings):
        ports = self.ports(host, self.NAMES)
        if not ports:
            return []
        label, ip = host_label(host), host.get("ip") or host_label(host)
        port = ports[0]["port"]
        svc = ports[0]["service"]
        prod = " ".join(x for x in (svc.get("product"), svc.get("version")) if x) or "SMB"
        port_ids = {p["port"] for p in ports}
        ff = [f for f in findings if f.get("port") in port_ids
              or "smb" in f["title"].lower() or "ms17-010" in f["title"].lower()
              or "eternalblue" in f["title"].lower()]

        surface = []
        if any(("ms17-010" in f["title"].lower() or "eternalblue" in f["title"].lower()) for f in findings):
            surface.append("MS17-010 (EternalBlue) reported VULNERABLE — unauthenticated RCE to SYSTEM.")
        if "samba" in prod.lower():
            surface.append("Samba server — check version against SambaCry (CVE-2017-7494) and config.")

        checks = [
            Check("Protocols & signing",
                  f"nmap -p445 --script smb-protocols,smb-security-mode,smb2-security-mode {ip}",
                  "Detect SMBv1 and whether message signing is enforced.", "T1592.004"),
            Check("Null session / shares", f"smbclient -N -L //{ip}",
                  "List shares with no credentials.", "T1135"),
            Check("Full enumeration", f"enum4linux-ng -A {ip}",
                  "Users, groups, shares, password policy, OS.", "T1087"),
            Check("RID cycling", f"rpcclient -U '' -N {ip} -c enumdomusers",
                  "Enumerate users via RPC.", "T1087.002"),
            Check("Share permissions", f"smbmap -H {ip}",
                  "Map read/write access across shares.", "T1135"),
            Check("Auth check / spray", f"crackmapexec smb {ip} -u users.txt -p passwords.txt",
                  "Validate credentials (authorized; mind lockout).", "T1110"),
            Check("Vuln scan", f"nmap -p445 --script 'smb-vuln-*' {ip}",
                  "Check ms17-010, ms08-067 and related.", "T1210"),
        ]
        return [ModuleResult(
            self.name, self.title, f"{label}:{port}", "smb",
            f"SMB exposed ({prod}).", worst(ff),
            techniques=self.techs(checks, extra=("T1021.002",)),
            attack_surface=surface, checks=[c.to_dict() for c in checks], findings=ff)]
