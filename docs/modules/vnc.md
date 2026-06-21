# VNC Module

VNC methodology. One assessment per VNC port. VNC frequently ships with weak or
no authentication and weak crypto.

```yaml
module: vnc
title: VNC
scope: port
matches: [vnc, vnc-http]
summary: "VNC service ({prod})."
finding_keywords: [vnc, realvnc, tightvnc, ultravnc]
unauth_services: [vnc]
techniques_extra: [T1021.005]
attack_surface:
  - { when: "always", note: "VNC often has weak/no authentication and weak crypto — tunnel over SSH/VPN and enforce strong auth." }
  - { when: "unauth", note: "VNC may allow unauthenticated screen access — verify before assuming protection." }
checks:
  - { name: Auth type, attack: T1592.004, command: "nmap -p{port} --script vnc-info {ip}", purpose: "Enumerate the VNC protocol version and supported security types (incl. None)." }
  - { name: None-auth check, attack: T1078, command: "vncviewer {ip}:{port}", purpose: "Test for unauthenticated screen access (authorized)." }
  - { name: Auth bypass detect, attack: T1595.002, command: "nmap -p{port} --script realvnc-auth-bypass {ip}", purpose: "Detection for the RealVNC auth-bypass (CVE-2006-2369)." }
  - { name: Credential test, attack: T1110.003, command: "hydra -P passwords.txt vnc://{ip}:{port} -f", purpose: "Authorized testing for weak VNC passwords (mind lockout)." }
  - { name: Authenticated access, attack: T1021.005, command: "vncviewer {ip}:{port} -passwd <pwfile>", purpose: "Validate interactive access with tested credentials." }
```
