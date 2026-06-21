# SNMP Module

SNMP methodology. One assessment per SNMP port. v1/v2c community strings are
cleartext and frequently default — brute, then walk the MIB for system data.

```yaml
module: snmp
title: SNMP
scope: port
matches: [snmp]
summary: "SNMP service ({prod})."
finding_keywords: [snmp, community, public, private]
unauth_services: [snmp]
techniques_extra: [T1602.001]
attack_surface:
  - { when: "always", note: "SNMP v1/v2c community strings are cleartext and often default (public/private) — migrate to SNMPv3." }
  - { when: "unauth", note: "Default/guessable community strings expose system, routing, process and credential data." }
checks:
  - { name: Community brute, attack: T1110, command: "onesixtyone -c community.txt {ip}", purpose: "Discover valid SNMP community strings (public/private/etc.)." }
  - { name: MIB walk, attack: T1602.001, command: "snmpwalk -v2c -c public {ip}", purpose: "Dump the full MIB — system info, interfaces, routes, processes." }
  - { name: System enumeration, attack: T1082, command: "snmp-check -c public {ip}", purpose: "Structured extraction of users, software, network and storage." }
  - { name: User accounts, attack: T1087, command: "snmpwalk -v2c -c public {ip} 1.3.6.1.4.1.77.1.2.25", purpose: "Enumerate Windows local user accounts via the LanMgr MIB." }
  - { name: Running processes, attack: T1057, command: "snmpwalk -v2c -c public {ip} 1.3.6.1.2.1.25.4.2.1.2", purpose: "List running processes (host resources MIB)." }
  - { name: v3 user enum, attack: T1087, command: "nmap -sU -p{port} --script snmp-info {ip}", purpose: "Enumerate SNMPv3 engine IDs / usernames where v1/v2c is disabled." }
```
