#!/usr/bin/env python3
"""modules.active_directory — LDAP / Kerberos / AD assessment methodology."""
from __future__ import annotations

from .base import Module, ModuleResult, Check, host_label, worst, looks_like_dc


class ADModule(Module):
    name = "active_directory"
    title = "Active Directory"

    def assess(self, host, findings):
        if not looks_like_dc(host):
            return []
        label, ip = host_label(host), host.get("ip") or host_label(host)
        ff = [f for f in findings
              if f["category"] in ("Directory", "Vuln scan")
              or any(k in f["title"].lower() for k in ("ldap", "kerberos", "smb", "ms17-010"))]

        surface = ["Host shows domain-controller indicators (Kerberos/LDAP services or DC naming).",
                   "Domain context — credential exposure here can escalate to domain-wide access."]

        checks = [
            Check("LDAP anonymous bind", f"ldapsearch -x -H ldap://{ip} -s base namingContexts",
                  "Test anonymous bind and read the base DSE / naming contexts.", "T1087.002"),
            Check("Domain user enumeration", f"kerbrute userenum -d <domain> --dc {ip} users.txt",
                  "Validate usernames via Kerberos pre-auth responses.", "T1087.002"),
            Check("AS-REP roasting", f"GetNPUsers.py <domain>/ -dc-ip {ip} -usersfile users.txt -no-pass -format hashcat",
                  "Find accounts without Kerberos pre-auth (offline cracking).", "T1558.004"),
            Check("Kerberoasting", f"GetUserSPNs.py <domain>/<user>:<pass> -dc-ip {ip} -request -outputfile spn.hashes",
                  "List/request SPN tickets for offline cracking.", "T1558.003"),
            Check("Password policy", f"rpcclient -U '<user>%<pass>' {ip} -c getdompwinfo",
                  "Read lockout/complexity policy before any spraying.", "T1201"),
            Check("Attack-path mapping", f"bloodhound-python -d <domain> -u <user> -p <pass> -dc {label} -c All",
                  "Collect AD objects/ACLs to map privilege paths.", "T1482"),
        ]
        return [ModuleResult(
            self.name, self.title, label, "active-directory",
            "Active Directory / domain-controller methodology.", worst(ff),
            techniques=self.techs(checks, extra=("T1003.006",)),
            attack_surface=surface, checks=[c.to_dict() for c in checks], findings=ff)]
