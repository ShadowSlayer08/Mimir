#!/usr/bin/env python3
"""modules.iot — IoT/discovery protocols methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class IoTModule(SpecModule):
    name = "iot"
    title = "IoT / Discovery"
    NAMES = ("upnp", "ssdp", "ws-discovery", "wsdd", "coap", "mdns", "zeroconf")
    UNAUTH = ("upnp", "ssdp", "ws-discovery", "wsdd", "coap", "mdns", "zeroconf")
    SUMMARY = "IoT/discovery service ({frag})."
    KEYWORDS = ("upnp", "ssdp", "coap", "mdns", "ws-discovery", "igd")
    EXTRA_TECH = ("T1590",)
    SURFACE = (
        ("always", "Discovery protocols leak device model/firmware and services; UPnP IGD can allow unauthenticated NAT/port-mapping changes."),
    )
    CHECKS = (
        ("SSDP / UPnP enum", "T1592.002", "nmap -sU -p1900 --script upnp-info {ip}", "Enumerate UPnP device/service descriptors (model, firmware, control URLs)."),
        ("WS-Discovery probe", "T1592", "nmap -sU -p3702 --script wsdd-discover {ip}", "Enumerate ONVIF/WS-Discovery devices (cameras, printers, NAS)."),
        ("CoAP resources", "T1592", "coap-client -m get coap://{ip}/.well-known/core", "List CoAP resources exposed by the device."),
        ("mDNS services", "T1046", "avahi-browse -art", "Enumerate advertised mDNS/Bonjour services."),
        ("UPnP IGD abuse", "T1190", "# review AddPortMapping on the IGD control URL for unauthenticated NAT changes (authorized)", "Assess whether the IGD allows unauthenticated port-mapping."),
    )
