#!/usr/bin/env python3
"""
device_profile.py — heuristic device-class tagging.

Authorized / lab / CTF use only.

A remote scan sees services, not device types. This infers a host's likely class
(ICS/OT, network device, NAS, camera/IoT, printer, Windows DC/host, Linux host)
from its OS fingerprint and service mix, so the engine can surface class-specific
methodology context. Inference only — it scans nothing.
"""
from __future__ import annotations

OT_SVCS = {"modbus", "s7", "bacnet", "dnp3", "ethernet-ip", "ethernetip", "iec-104",
           "fox", "omron", "opcua", "opc-ua", "codesys", "profinet", "profinet-io",
           "hart-ip", "fins"}
NETDEV_SVCS = {"smart-install", "smi", "netconf", "bgp"}
NAS_SVCS = {"afp", "afpovertcp", "iscsi", "iscsi-target"}
CAMERA_SVCS = {"rtsp", "rtspu"}
IOT_SVCS = {"upnp", "ssdp", "ws-discovery", "wsdd", "coap", "mdns", "zeroconf"}
PRINTER_SVCS = {"jetdirect", "printer", "ipp", "hp-pjl", "pdl-datastream", "lpd"}
WIN_SVCS = {"microsoft-ds", "netbios-ssn", "ms-wbt-server", "winrm", "wsman"}
DC_SVCS = {"kerberos", "ldap", "ldapssl", "globalcat", "kpasswd"}
_APPLIANCE_OS = ("ios", "junos", "fortios", "pan-os", "routeros", "mikrotik",
                 "embedded", "switch", "router", "firewall", "screenos")


def _services(host):
    return {(p["service"].get("name") or "").lower() for p in host.get("ports", [])}


def _os_family(host):
    return " ".join(f"{o.get('family', '')} {o.get('name', '')}" for o in host.get("os", [])).lower()


def classify(host):
    """Return (device_class, [indicators]) for a parsed host dict."""
    svcs = _services(host)
    osf = _os_family(host)

    def hit(group):
        return sorted(svcs & group)

    if svcs & OT_SVCS:
        return "ICS/OT device", hit(OT_SVCS)
    if svcs & CAMERA_SVCS:
        return "IP camera / IoT", hit(CAMERA_SVCS | IOT_SVCS)
    if svcs & NETDEV_SVCS:
        return "Network device (switch/router)", hit(NETDEV_SVCS)
    if {"snmp"} & svcs and (svcs & {"ssh", "telnet"}) and not (svcs & (NAS_SVCS | WIN_SVCS)) \
            and any(k in osf for k in _APPLIANCE_OS):
        return "Network device / appliance", sorted(svcs & {"snmp", "ssh", "telnet", "http", "https"})
    if svcs & NAS_SVCS:
        return "NAS / storage", hit(NAS_SVCS)
    if {"nfs", "microsoft-ds"} <= svcs and "ms-wbt-server" not in svcs:
        return "NAS / storage", sorted(svcs & {"nfs", "microsoft-ds", "ftp", "rsync"})
    if svcs & PRINTER_SVCS:
        return "Printer", hit(PRINTER_SVCS)
    if (svcs & DC_SVCS) and (svcs & WIN_SVCS):
        return "Windows domain controller", sorted(svcs & (DC_SVCS | WIN_SVCS))
    if (svcs & WIN_SVCS) or "windows" in osf:
        return "Windows host", sorted(svcs & WIN_SVCS) or ["windows os"]
    if svcs & IOT_SVCS:
        return "IoT device", hit(IOT_SVCS)
    if "ssh" in svcs or "linux" in osf or "unix" in osf:
        return "Linux/Unix host", sorted(svcs & {"ssh", "http", "https"}) or ["unix os"]
    return "Host (generic)", []


def device_class(host):
    return classify(host)[0]
