# ICS / SCADA Module

OT/ICS protocol methodology (Modbus, S7, BACnet, DNP3, EtherNet/IP, IEC-104,
Fox). SAFETY: passive identification only — never write or replay on live OT.

```yaml
module: ics
title: ICS / SCADA
scope: port
matches: [modbus, s7, bacnet, dnp3, ethernet-ip, ethernetip, iec-104, fox, omron,
          opcua, opc-ua, codesys, profinet, profinet-io, hart-ip, fins]
summary: "ICS/OT protocol ({frag}) exposed."
finding_keywords: [modbus, s7, bacnet, dnp3, opc, codesys, profinet, scada, ics, plc]
techniques_extra: [T0840, T0846]
attack_surface:
  - { when: "always", note: "SAFETY: OT device — perform PASSIVE enumeration only. Never write/replay; active probing can disrupt physical processes." }
  - { when: "always", note: "ICS protocols are typically unauthenticated — network isolation is the primary control." }
checks:
  - { name: Modbus discovery, attack: T0846, command: "nmap -p{port} --script modbus-discover {ip}", purpose: "Enumerate Modbus unit IDs and device identification (read-only)." }
  - { name: S7 info, attack: T0888, command: "nmap -p{port} --script s7-info {ip}", purpose: "Read Siemens S7 module/firmware identification." }
  - { name: BACnet info, attack: T0888, command: "nmap -sU -p{port} --script bacnet-info {ip}", purpose: "Read BACnet device properties (vendor, model, firmware)." }
  - { name: EtherNet/IP info, attack: T0888, command: "nmap -p{port} --script enip-info {ip}", purpose: "Identify EtherNet/IP / CIP device attributes." }
  - { name: OPC-UA endpoints, attack: T0888, command: "nmap -p4840 --script opcua-discovery {ip}  # or: opcua-client GetEndpoints", purpose: "Enumerate OPC-UA endpoints, security policies and whether anonymous is allowed." }
  - { name: CODESYS / PROFINET ID, attack: T0888, command: "nmap -p2455,34962-34964 -sV {ip}", purpose: "Identify CODESYS (1217/2455) and PROFINET-IO devices (read-only)." }
  - { name: Protocol/device ID, attack: T0840, command: "nmap -sV -p{port} {ip}", purpose: "Fingerprint the ICS protocol and device without writing state." }
  - { name: OT asset inventory, attack: T0846, command: "# passively catalogue device role, vendor and firmware for the asset register", purpose: "Build an OT asset inventory for risk review (no active control)." }
```
