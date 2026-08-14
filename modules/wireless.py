#!/usr/bin/env python3
"""modules.wireless — wireless / RF methodology (target-driven).

Authorized / lab / CTF use only.

Assesses a WIRELESS target (Wi-Fi ESSID / interface / RF scope) across Wi-Fi,
Bluetooth/BLE, Zigbee (802.15.4) and sub-GHz SDR. No OWASP standard, so checks are
ATT&CK + CWE-mapped with a `safe|intrusive` risk tag: passive survey and offline
cracking are safe; deauth, evil-twin, injection and active RF are intrusive
(VAPT-hidden). Methodology + STAGING only; the engine transmits nothing.

Tooling: aircrack-ng, hcxdumptool, hashcat, wifite, kismet, bettercap, eaphammer,
hostapd-wpe, bluetoothctl, gatttool, btlejack, ubertooth, killerbee, hackrf, URH.

Checks load from docs/appsec/wireless.md (`module: wireless`) when present, else
built-in. Bands: --wireless [wifi|ble|zigbee|rf]. Placeholders: {iface} {ssid} {target}.
"""
from __future__ import annotations

import string

from .base import Check, ModuleResult, worst

_A = "always"
# (name, attack, owasp, cwe, risk, when, command, purpose)
BUILTIN_CHECKS = [
    ("Wireless survey / recon", "T1595", "", "CWE-200", "safe", _A,
     "airodump-ng {iface}   # or: kismet / wifite -i {iface}",
     "Map APs, clients, channels and encryption in range."),
    ("Wireless footprint OSINT", "T1590", "", "CWE-200", "safe", _A,
     "# wigle.net lookup for {ssid}; flag hidden/rogue SSIDs and open guest networks",
     "Enumerate the target's wireless footprint."),
    ("WPS exposure", "T1595", "", "CWE-1391", "safe", "wifi",
     "wash -i {iface}   # flag WPS-enabled APs (reaver / bully candidates)",
     "Identify WPS-enabled access points."),
    ("WPA/WPA2 handshake capture", "T1040", "", "CWE-319", "intrusive", "wifi",
     "hcxdumptool -i {iface} --enable_status=1   # or airodump + aireplay-ng deauth to force it",
     "Capture the 4-way handshake / PMKID (authorized)."),
    ("Offline WPA crack", "T1110.002", "", "CWE-521", "safe", "wifi",
     "hashcat -m 22000 capture.hc22000 wordlist.txt",
     "Crack the captured PMKID/handshake offline."),
    ("Evil twin / rogue AP", "T1557", "", "CWE-290", "intrusive", "wifi",
     "# authorized only: eaphammer / hostapd-wpe rogue AP to capture creds or MITM clients",
     "Test client trust and capture credentials."),
    ("WPA-Enterprise EAP", "T1557", "", "CWE-295", "intrusive", "wifi",
     "hostapd-wpe   # capture MSCHAPv2, assess EAP server-cert validation on clients",
     "Test EAP configuration and certificate pinning."),
    ("BLE enumeration", "T1592", "", "CWE-200", "safe", "ble",
     "bettercap -eval 'ble.recon on'   # or: gatttool -I / nRF Connect",
     "Enumerate BLE devices, services and characteristics."),
    ("BLE transport / pairing", "T1040", "", "CWE-319", "intrusive", "ble",
     "# authorized: btlejack / Ubertooth sniff; test pairing (JustWorks) and replay",
     "Test BLE transport security and pairing."),
    ("Zigbee / 802.15.4", "T1040", "", "CWE-319", "intrusive", "zigbee",
     "# killerbee: zbstumbler / zbdump / zbreplay (authorized)",
     "Enumerate and test Zigbee networks."),
    ("Sub-GHz SDR analysis", "T1200", "", "CWE-1188", "safe", "rf",
     "# hackrf/rtl-sdr + Universal Radio Hacker (URH) to capture/analyse 433/868/915 MHz",
     "Analyse proprietary sub-GHz RF protocols."),
    ("Deauth / DoS resilience", "T1499", "", "CWE-400", "intrusive", "wifi",
     "# authorized only: aireplay-ng --deauth to test client resilience and detection",
     "Test deauthentication handling (noisy; scope-gated)."),
]

_BANDS = ("wifi", "ble", "zigbee", "rf")


class _SafeDict(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(s, ctx):
    return string.Formatter().vformat(s or "", (), _SafeDict(ctx))


class WirelessModule:
    name = "wireless"
    title = "Wireless / RF"

    def __init__(self, docs_dir=None):
        try:
            from knowledge_loader import load_knowledge
            self._mdef = load_knowledge(docs_dir).modules.get("wireless")
        except Exception:                                              # pragma: no cover
            self._mdef = None

    def _checks(self):
        if self._mdef and self._mdef.get("checks"):
            return self._mdef["checks"]
        return [{"name": n, "attack": a, "owasp": o, "cwe": w, "risk": rk,
                 "when": wh, "command": cmd, "purpose": pp}
                for (n, a, o, w, rk, wh, cmd, pp) in BUILTIN_CHECKS]

    def assess_target(self, target, findings):
        band = (target.get("band") or "").lower()
        ctx = {"iface": target.get("iface") or "wlan0",
               "ssid": target.get("ssid") or target.get("ref") or "<ssid>",
               "target": target.get("ref", ""), "label": target.get("label", "")}
        try:
            from config import PATHS as _PATHS
            ctx.update(_PATHS)
        except Exception:                 # pragma: no cover
            pass

        flags = {"always": True}
        for b in _BANDS:
            flags[b] = (band == "" or band == b)
        checks, techs = [], set()
        for c in self._checks():
            when = c.get("when", "always") or "always"
            if not flags.get(when, when == "always"):
                continue
            checks.append(Check(c["name"], _fmt(c["command"], ctx), c.get("purpose", ""),
                                c.get("attack", ""), c.get("owasp", ""), c.get("cwe", ""),
                                c.get("risk", "")).to_dict())
            if c.get("attack"):
                techs.add(c["attack"])

        surface = ["Wireless perimeter - rogue APs, weak PSK/EAP, and BLE/Zigbee/RF "
                   "devices extend the attack surface beyond the wired network."]
        return [ModuleResult(
            self.name, self.title, target.get("ref", "wireless"), "rf",
            f"Wireless / RF assessment ({band or 'all bands'}).",
            worst([]), techniques=sorted(techs), attack_surface=surface,
            checks=checks, findings=[])]
