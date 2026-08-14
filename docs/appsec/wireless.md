# Wireless / RF Module

**AppSec pillar — target-driven.** Assesses a wireless target (Wi-Fi ESSID /
interface / RF scope) across Wi-Fi, Bluetooth/BLE, Zigbee (802.15.4) and sub-GHz
SDR. No OWASP standard applies, so checks are ATT&CK + CWE-mapped with a
`safe|intrusive` risk tag: passive survey and offline cracking are safe; deauth,
evil-twin, injection and active RF are intrusive (VAPT-hidden).

Targets come from `assess --wireless [wifi|ble|zigbee|rf|<ssid>]`. Band-specific
checks are gated with `when: wifi|ble|zigbee|rf`; cross-band ones are `always`.
Tooling: aircrack-ng, hcxdumptool, hashcat, wifite, kismet, bettercap, eaphammer,
hostapd-wpe, gatttool, btlejack, ubertooth, killerbee, hackrf, URH.

**Boundary:** methodology + staging only — the operator transmits/captures with
their own radios, in scope. Transmitting checks are intrusive and lockout/DoS-aware.

```yaml
module: wireless
title: Wireless / RF
scope: target
matches: [wifi, ble, zigbee, rf, wireless]
summary: "Wireless / RF assessment."
techniques_extra: []
checks:
  - {name: Wireless survey / recon, attack: T1595, owasp: "", cwe: CWE-200, risk: safe, when: always,
     command: "airodump-ng {iface}   # or: kismet / wifite -i {iface}",
     purpose: "Map APs, clients, channels and encryption in range."}
  - {name: Wireless footprint OSINT, attack: T1590, owasp: "", cwe: CWE-200, risk: safe, when: always,
     command: "# wigle.net lookup for {ssid}; flag hidden/rogue SSIDs and open guest networks",
     purpose: "Enumerate the target's wireless footprint."}
  - {name: WPS exposure, attack: T1595, owasp: "", cwe: CWE-1391, risk: safe, when: wifi,
     command: "wash -i {iface}   # flag WPS-enabled APs (reaver / bully candidates)",
     purpose: "Identify WPS-enabled access points."}
  - {name: WPA/WPA2 handshake capture, attack: T1040, owasp: "", cwe: CWE-319, risk: intrusive, when: wifi,
     command: "hcxdumptool -i {iface} --enable_status=1   # or airodump + aireplay-ng deauth to force it",
     purpose: "Capture the 4-way handshake / PMKID (authorized)."}
  - {name: Offline WPA crack, attack: T1110.002, owasp: "", cwe: CWE-521, risk: safe, when: wifi,
     command: "hashcat -m 22000 capture.hc22000 wordlist.txt",
     purpose: "Crack the captured PMKID/handshake offline."}
  - {name: Evil twin / rogue AP, attack: T1557, owasp: "", cwe: CWE-290, risk: intrusive, when: wifi,
     command: "# authorized only: eaphammer / hostapd-wpe rogue AP to capture creds or MITM clients",
     purpose: "Test client trust and capture credentials."}
  - {name: WPA-Enterprise EAP, attack: T1557, owasp: "", cwe: CWE-295, risk: intrusive, when: wifi,
     command: "hostapd-wpe   # capture MSCHAPv2, assess EAP server-cert validation on clients",
     purpose: "Test EAP configuration and certificate pinning."}
  - {name: BLE enumeration, attack: T1592, owasp: "", cwe: CWE-200, risk: safe, when: ble,
     command: "bettercap -eval 'ble.recon on'   # or: gatttool -I / nRF Connect",
     purpose: "Enumerate BLE devices, services and characteristics."}
  - {name: BLE transport / pairing, attack: T1040, owasp: "", cwe: CWE-319, risk: intrusive, when: ble,
     command: "# authorized: btlejack / Ubertooth sniff; test pairing (JustWorks) and replay",
     purpose: "Test BLE transport security and pairing."}
  - {name: Zigbee / 802.15.4, attack: T1040, owasp: "", cwe: CWE-319, risk: intrusive, when: zigbee,
     command: "# killerbee: zbstumbler / zbdump / zbreplay (authorized)",
     purpose: "Enumerate and test Zigbee networks."}
  - {name: Sub-GHz SDR analysis, attack: T1200, owasp: "", cwe: CWE-1188, risk: safe, when: rf,
     command: "# hackrf/rtl-sdr + Universal Radio Hacker (URH) to capture/analyse 433/868/915 MHz",
     purpose: "Analyse proprietary sub-GHz RF protocols."}
  - {name: Deauth / DoS resilience, attack: T1499, owasp: "", cwe: CWE-400, risk: intrusive, when: wifi,
     command: "# authorized only: aireplay-ng --deauth to test client resilience and detection",
     purpose: "Test deauthentication handling (noisy; scope-gated)."}
```
