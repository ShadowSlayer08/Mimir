# AFP Module

Apple Filing Protocol (TCP 548) methodology — macOS / NAS file sharing. Enumerate
shares and server info, test guest access, then authorized credential testing.

```yaml
module: afp
title: AFP (Apple Filing Protocol)
scope: port
matches: [afp, afpovertcp]
summary: "AFP file sharing ({prod})."
finding_keywords: [afp, netatalk, time machine]
unauth_services: [afp, afpovertcp]
techniques_extra: [T1135]
attack_surface:
  - { when: "always", note: "AFP may allow guest access and exposes server/share metadata; old Netatalk has critical RCE CVEs (e.g. CVE-2018-1160)." }
  - { when: "has_cve", note: "AFP server version has known CVEs (see findings)." }
checks:
  - { name: Server info & shares, attack: T1135, command: "nmap -p548 --script afp-serverinfo,afp-showmount {ip}", purpose: "Enumerate AFP server info and exported volumes." }
  - { name: Guest access, attack: T1078, command: "nmap -p548 --script afp-ls {ip}", purpose: "List volume contents as the guest/anonymous user where allowed." }
  - { name: Path-vuln check, attack: T1595.002, command: "nmap -p548 --script afp-path-vuln {ip}", purpose: "Detection for the AFP directory-traversal vulnerability." }
  - { name: Credential test, attack: T1110.003, command: "hydra -L users.txt -P passwords.txt afp://{ip} -f", purpose: "Authorized testing for weak AFP credentials (mind lockout)." }
```
