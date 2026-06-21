#!/usr/bin/env python3
"""
profiles.py — operation profiles for the target-acquisition dashboard.

Authorized / lab / CTF use only.

Two modes tune the Stage-1 enumeration scan. Both run a comprehensive baseline
(`-p- -Pn -A --script vuln`); Red Team layers on extra intrusive enumeration and
a higher packet rate.

  vapt    — comprehensive DETECTION scan: all ports, aggressive service/OS
            detection, vuln-category NSE. Thorough but non-weaponizing
            (no exploit / dos / brute categories). The default.
  redteam — the same full aggressive scan PLUS share/user enumeration, zone
            transfer and SNMP/HTTP enum at a higher rate. Higher detection &
            account-lockout risk.

IMPORTANT — the mode changes only how hard the engine *enumerates*. Neither mode
auto-exploits: both feed analysis -> ATT&CK methodology -> attack-path *staging*,
and every attack step is executed MANUALLY by a human operator within an
authorized engagement (see docs/instructions.md). Even Red Team selects only
detection/enumeration scripts — never nmap's `exploit` or `dos` categories.
"""
from __future__ import annotations

PROFILES = {
    "vapt": {
        "label": "VAPT (thorough)",
        "scripts": "vuln",
        "timing": "4",
        "aggressive": True,      # -A  (implies -sV -O --script=default --traceroute)
        "full_ports": True,      # -p-  (all TCP)
        # UDP service ports our modules cover (DNS/TFTP/NTP/SNMP/IKE/IPMI/UPnP/mDNS/BACnet);
        # full UDP is impractically slow, so we scan the ports we have modules for.
        "udp_ports": "53,69,123,161,500,623,1900,5353,47808",
        "os_detect": True,
        "pn": True,              # -Pn
        "extra": "",
        "risk": "medium",
        "banner": ("VAPT mode — comprehensive detection scan: -p- -Pn -A --script "
                   "vuln (all ports, aggressive, vuln-detection NSE). Thorough but "
                   "non-weaponizing: no exploit / dos / brute categories."),
    },
    "redteam": {
        "label": "Red Team (in-depth)",
        "scripts": ("vuln,vulners,smb-enum-shares,smb-enum-users,smb-vuln-*,"
                    "dns-zone-transfer,http-enum,snmp-info,ftp-anon"),
        "timing": "4",
        "aggressive": True,
        "full_ports": True,
        "udp_ports": "53,67,69,123,137,138,161,177,500,520,623,1434,1900,4500,5060,5353,47808",
        "os_detect": True,
        "pn": True,
        "extra": "--min-rate 800",
        "risk": "high",
        "banner": ("RED TEAM mode — full aggressive scan (-p- -Pn -A) PLUS extra "
                   "intrusive enumeration (share/user enum, zone transfer, SNMP/HTTP) "
                   "at a higher rate. Higher detection & lockout risk; authorized only. "
                   "Still STAGES for manual execution — no auto-exploitation."),
    },
}

DEFAULT_MODE = "vapt"
MODES = tuple(PROFILES)


def get_profile(mode):
    """Return the profile dict for a mode name (falls back to the safe default)."""
    return PROFILES.get((mode or DEFAULT_MODE).lower(), PROFILES[DEFAULT_MODE])
