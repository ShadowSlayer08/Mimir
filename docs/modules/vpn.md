# VPN / IKE Module

VPN-endpoint methodology (IKE/ISAKMP 500, OpenVPN 1194, PPTP 1723, L2TP 1701).
IKE aggressive mode can expose a crackable PSK; PPTP/MS-CHAPv2 is broken.

```yaml
module: vpn
title: VPN / IKE
scope: port
matches: [isakmp, ike, openvpn, pptp, l2tp]
summary: "VPN endpoint ({frag})."
finding_keywords: [isakmp, ike, vpn, pptp, aggressive mode]
techniques_extra: [T1133]
attack_surface:
  - { when: "always", note: "IKE aggressive mode exposes a crackable PSK hash; PPTP/MS-CHAPv2 is broken — prefer IKEv2/modern VPNs." }
checks:
  - { name: IKE transforms, attack: T1046, command: "ike-scan -M {ip}", purpose: "Enumerate supported IKE transforms and identify the VPN vendor." }
  - { name: Aggressive-mode PSK, attack: T1110, command: "ike-scan --aggressive -M --pskcrack={ip}.psk {ip}", purpose: "Detect aggressive mode and capture the PSK hash for offline cracking (authorized)." }
  - { name: PPTP version, attack: T1592.002, command: "nmap -p{port} -sV {ip}", purpose: "Identify PPTP/L2TP and the underlying auth (MS-CHAPv2 weakness)." }
  - { name: OpenVPN probe, attack: T1046, command: "nmap -sU -sV -p{port} {ip}", purpose: "Confirm an OpenVPN service via version detection (no official OpenVPN NSE; add the openvpn-version community script if installed)." }
  - { name: PSK cracking, attack: T1110.002, command: "psk-crack {ip}.psk", purpose: "Offline-crack a captured aggressive-mode PSK (authorized)." }
```
