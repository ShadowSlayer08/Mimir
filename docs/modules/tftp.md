# TFTP Module

TFTP methodology (69/udp). TFTP has no authentication — device configs and
firmware (often containing credentials) may be readable or overwritable.

```yaml
module: tftp
title: TFTP
scope: port
matches: [tftp]
summary: "TFTP service ({prod}) — no authentication."
finding_keywords: [tftp]
unauth_services: [tftp]
techniques_extra: [T1602]
attack_surface:
  - { when: "always", note: "TFTP has no authentication — device configs/firmware (often with credentials) may be readable or overwritable." }
  - { when: "unauth", note: "Test for well-known file reads and write access." }
checks:
  - { name: Filename enumeration, attack: T1083, command: "nmap -sU -p{port} --script tftp-enum {ip}", purpose: "Probe for well-known TFTP filenames (configs/firmware)." }
  - { name: Config read, attack: T1602.002, command: "tftp {ip} -c get running-config", purpose: "Attempt to read device configuration files that leak credentials." }
  - { name: Firmware read, attack: T1592, command: "tftp {ip} -c get firmware.bin", purpose: "Retrieve firmware images for offline analysis." }
  - { name: Write test, attack: T1565, command: "# authorized: tftp {ip} -c put testfile  (verify writable, then remove)", purpose: "Determine whether arbitrary writes are accepted." }
```
