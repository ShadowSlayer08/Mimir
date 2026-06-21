# Network Printer Module

Network printer methodology (JetDirect 9100, LPD 515, IPP 631). Printers store
back-end credentials and documents and often expose a filesystem via PJL.

```yaml
module: printer
title: Network Printer
scope: port
matches: [jetdirect, printer, ipp, hp-pjl, pdl-datastream, lpd]
summary: "Network printer service ({frag})."
finding_keywords: [printer, jetdirect, pjl, ipp, lpd]
techniques_extra: [T1213]
attack_surface:
  - { when: "always", note: "Printers store credentials (LDAP/SMB/email) and documents; PJL/PostScript can expose the filesystem." }
checks:
  - { name: Printer fingerprint, attack: T1592.002, command: "nmap -p{port} -sV {ip}", purpose: "Identify model/firmware for known default creds and CVEs." }
  - { name: PJL enumeration, attack: T1213, command: "pret {ip} pjl", purpose: "Enumerate the printer via PJL (filesystem, NVRAM, stored jobs)." }
  - { name: PostScript access, attack: T1213, command: "pret {ip} ps", purpose: "Test PostScript filesystem access and stored-job retrieval." }
  - { name: IPP attributes, attack: T1592, command: "ipptool -tv ipp://{ip}:{port}/ipp/print get-printer-attributes.test", purpose: "Read IPP printer attributes and capabilities." }
  - { name: SNMP cross-ref, attack: T1602.001, command: "snmpwalk -v2c -c public {ip}", purpose: "Pull stored credentials/config exposed over the printer's SNMP MIB." }
  - { name: Stored credentials, attack: T1552, command: "# via PJL/web UI: extract saved LDAP/SMB/SMTP scan-to credentials (authorized)", purpose: "Surface back-end credentials stored on the device." }
```
