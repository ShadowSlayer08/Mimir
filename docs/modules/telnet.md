# Telnet Module

Telnet methodology. One assessment per Telnet port. Telnet is cleartext, so the
core risks are credential sniffing and default device credentials.

```yaml
module: telnet
title: Telnet
scope: port
matches: [telnet]
summary: "Telnet service ({prod}) — cleartext."
finding_keywords: [telnet, cleartext]
techniques_extra: [T1040]
attack_surface:
  - { when: "always", note: "Telnet is cleartext — all credentials and session data are sniffable on-path; replace with SSH." }
  - { when: "has_cve", note: "Telnet daemon / device firmware has known CVEs (see findings)." }
checks:
  - { name: Banner / device ID, attack: T1592.002, command: "nmap -p{port} -sV --script telnet-ntlm-info {ip}", purpose: "Identify the device/OS and any leaked domain info from the banner." }
  - { name: Encryption support, attack: T1592.004, command: "nmap -p{port} --script telnet-encryption {ip}", purpose: "Check whether the server supports the TELNET ENCRYPT option." }
  - { name: Default credentials, attack: T1078.001, command: "telnet {ip} {port}", purpose: "Identify the device type and test documented default credentials (authorized)." }
  - { name: Credential test, attack: T1110.003, command: "hydra -L users.txt -P passwords.txt telnet://{ip}:{port} -f", purpose: "Authorized testing for weak/default credentials (mind lockout)." }
  - { name: On-path capture, attack: T1040, command: "# with authorized network position: tcpdump -i <iface> host {ip} and port {port}", purpose: "Demonstrate credential exposure via cleartext capture." }
```
