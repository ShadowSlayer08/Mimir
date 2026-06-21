# Cisco Smart Install Module

Cisco Smart Install (TCP 4786) methodology. SMI is unauthenticated by design — a
reachable port lets an attacker pull or replace the device configuration and IOS
image, so it is a high-impact switch/router exposure.

```yaml
module: cisco_smi
title: Cisco Smart Install
scope: port
matches: [smart-install, smi]
summary: "Cisco Smart Install ({prod}) exposed."
finding_keywords: [smart install, smi, vstack]
unauth_services: [smart-install, smi]
techniques_extra: [T1602.002]
attack_surface:
  - { when: "always", note: "Smart Install (TCP 4786) is unauthenticated — config/IOS theft or replacement is possible. Disable with 'no vstack'." }
checks:
  - { name: Exposure check, attack: T1046, command: "nmap -p4786 -sV {ip}", purpose: "Confirm Smart Install is listening (unauthenticated)." }
  - { name: Config retrieval, attack: T1602.002, command: "python3 SIET.py -i {ip} -g", purpose: "Pull the running config over SMI (authorized; device configs leak credentials)." }
  - { name: Hardening verify, attack: T1592.004, command: "ssh {ip} 'show vstack config'", purpose: "Confirm whether Smart Install is enabled; 'no vstack' disables it." }
```
