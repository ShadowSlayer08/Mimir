#!/usr/bin/env python3
"""modules.ics — ICS/SCADA assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class ICSModule(SpecModule):
    name = "ics"
    title = "ICS / SCADA"
    NAMES = ("modbus", "s7", "bacnet", "dnp3", "ethernet-ip", "ethernetip", "iec-104", "fox", "omron")
    SUMMARY = "ICS/OT protocol ({frag}) exposed."
    KEYWORDS = ("modbus", "s7", "bacnet", "dnp3", "scada", "ics", "plc")
    EXTRA_TECH = ("T0840", "T0846")
    SURFACE = (
        ("always", "SAFETY: OT device — PASSIVE enumeration only. Never write/replay; active probing can disrupt physical processes."),
        ("always", "ICS protocols are typically unauthenticated — network isolation is the primary control."),
    )
    CHECKS = (
        ("Modbus discovery", "T0846", "nmap -p{port} --script modbus-discover {ip}", "Enumerate Modbus unit IDs and device identification (read-only)."),
        ("S7 info", "T0888", "nmap -p{port} --script s7-info {ip}", "Read Siemens S7 module/firmware identification."),
        ("BACnet info", "T0888", "nmap -sU -p{port} --script bacnet-info {ip}", "Read BACnet device properties (vendor, model, firmware)."),
        ("EtherNet/IP info", "T0888", "nmap -p{port} --script enip-info {ip}", "Identify EtherNet/IP / CIP device attributes."),
        ("Protocol/device ID", "T0840", "nmap -sV -p{port} {ip}", "Fingerprint the ICS protocol and device without writing state."),
    )
