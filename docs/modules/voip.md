# VoIP / SIP Module

VoIP methodology (SIP 5060/5061, H.323 1720, IAX 4569, MGCP 2727). Enumerate
methods and extensions, then test registrar authentication.

```yaml
module: voip
title: VoIP / SIP
scope: port
matches: [sip, sips, h323, h323q931, iax, mgcp]
tls_ports: [5061]
summary: "VoIP service ({frag})."
finding_keywords: [sip, voip, h323, asterisk]
techniques_extra: [T1590]
attack_surface:
  - { when: "not tls", note: "SIP signalling in cleartext exposes credentials and call metadata; enforce SIP/TLS + SRTP." }
  - { when: "has_cve", note: "PBX/SIP server version has known CVEs (see findings)." }
checks:
  - { name: Methods / options, attack: T1592, command: "nmap -sU -p{port} --script sip-methods {ip}", purpose: "Enumerate supported SIP methods and the server banner." }
  - { name: Extension enum, attack: T1087, command: "svwar -m INVITE -e 100-999 {ip}", purpose: "Enumerate valid SIP extensions (sipvicious)." }
  - { name: Device discovery, attack: T1046, command: "svmap {ip}", purpose: "Discover SIP devices/PBXes on the target." }
  - { name: Registrar auth, attack: T1110, command: "svcrack -u <ext> -d passwords.txt {ip}", purpose: "Authorized credential testing against the SIP registrar (mind lockout)." }
  - { name: TLS posture, attack: T1595, when: tls, command: "sslscan {ip}:{port}", purpose: "For SIP/TLS (5061), enumerate protocols/ciphers/cert." }
```
