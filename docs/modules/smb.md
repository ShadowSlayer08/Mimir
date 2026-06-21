# SMB Module

SMB assessment methodology. One assessment per host with an SMB service.

```yaml
module: smb
title: SMB / NetBIOS
scope: host
matches: [microsoft-ds, netbios-ssn, smb]
summary: "SMB exposed ({prod})."
finding_keywords: [smb, ms17-010, eternalblue, netbios]
attack_surface:
  - when: "ms17010"
    note: "MS17-010 (EternalBlue) reported VULNERABLE — unauthenticated RCE to SYSTEM."
  - when: "samba"
    note: "Samba server — check version against SambaCry (CVE-2017-7494) and config."
techniques_extra: [T1021.002]
checks:
  - {name: Protocols & signing, attack: T1592.004, command: "nmap -p445 --script smb-protocols,smb-security-mode,smb2-security-mode {ip}",
     purpose: "Detect SMBv1 and whether message signing is enforced."}
  - {name: Null session / shares, attack: T1135,   command: "smbclient -N -L //{ip}",
     purpose: "List shares with no credentials."}
  - {name: Full enumeration,    attack: T1087,     command: "enum4linux-ng -A {ip}",
     purpose: "Users, groups, shares, password policy, OS."}
  - {name: RID cycling,         attack: T1087.002, command: "rpcclient -U '' -N {ip} -c enumdomusers",
     purpose: "Enumerate users via RPC."}
  - {name: Share permissions,   attack: T1135,     command: "smbmap -H {ip}",
     purpose: "Map read/write access across shares."}
  - {name: Auth check / spray,  attack: T1110,     command: "crackmapexec smb {ip} -u users.txt -p passwords.txt",
     purpose: "Validate credentials (authorized; mind lockout)."}
  - {name: Vuln scan,           attack: T1210,     command: "nmap -p445 --script 'smb-vuln-*' {ip}",
     purpose: "Check ms17-010, ms08-067 and related."}
```
