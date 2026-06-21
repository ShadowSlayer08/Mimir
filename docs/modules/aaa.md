# AAA Module (RADIUS / TACACS+)

RADIUS (1812/1813 UDP) and TACACS+ (TCP 49) methodology — the AAA plane behind
network infrastructure. Both rely on a shared secret; a weak/recovered secret or
a captured exchange enables offline cracking and auth bypass.

```yaml
module: aaa
title: AAA (RADIUS / TACACS+)
scope: port
matches: [radius, radiusacct, tacacs]
summary: "{disp} AAA service ({prod})."
finding_keywords: [radius, tacacs, aaa, shared secret]
labels:
  radius: RADIUS
  radiusacct: RADIUS Accounting
  tacacs: TACACS+
techniques_extra: [T1110.002]
attack_surface:
  - { when: "always", note: "AAA shared secrets are often weak/reused; a captured Access-Request or TACACS+ exchange can be cracked offline to forge auth." }
checks:
  - { name: Service detection, attack: T1046, command: "nmap -sU -sV -p1812,1813 {ip}; nmap -p49 -sV {ip}", purpose: "Confirm RADIUS/TACACS+ and version." }
  - { name: Shared-secret test, attack: T1110, command: "# send Access-Request with a candidate secret (e.g. radtest / eapol_test)", purpose: "Test for default/weak RADIUS shared secrets (authorized)." }
  - { name: Offline cracking, attack: T1110.002, command: "# capture an exchange, then crack the shared secret offline (e.g. with hashcat)", purpose: "Recover the shared secret from a captured RADIUS/TACACS+ exchange." }
```
