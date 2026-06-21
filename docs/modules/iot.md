# IoT Discovery Module

IoT / SOHO discovery protocols: UPnP/SSDP (1900 UDP), WS-Discovery (3702 UDP),
CoAP (5683 UDP) and mDNS (5353). These leak device inventory and, for UPnP IGD,
can expose NAT/port-mapping abuse.

```yaml
module: iot
title: IoT / Discovery
scope: port
matches: [upnp, ssdp, ws-discovery, wsdd, coap, mdns, zeroconf]
summary: "IoT/discovery service ({frag})."
finding_keywords: [upnp, ssdp, coap, mdns, ws-discovery, igd]
unauth_services: [upnp, ssdp, ws-discovery, wsdd, coap, mdns, zeroconf]
techniques_extra: [T1590]
attack_surface:
  - { when: "always", note: "Discovery protocols leak device model/firmware and services; UPnP IGD can allow unauthenticated NAT/port-mapping changes (CVE-class 'CallStranger', etc.)." }
checks:
  - { name: SSDP / UPnP enum, attack: T1592.002, command: "nmap -sU -p1900 --script upnp-info {ip}", purpose: "Enumerate UPnP device/service descriptors (model, firmware, control URLs)." }
  - { name: WS-Discovery probe, attack: T1592, command: "nmap -sU -p3702 --script wsdd-discover {ip}", purpose: "Enumerate ONVIF/WS-Discovery devices (cameras, printers, NAS)." }
  - { name: CoAP resources, attack: T1592, command: "coap-client -m get coap://{ip}/.well-known/core", purpose: "List CoAP resources exposed by the device." }
  - { name: mDNS services, attack: T1046, command: "avahi-browse -art   # or: dns-sd -B _services._dns-sd._udp {ip}", purpose: "Enumerate advertised mDNS/Bonjour services." }
  - { name: UPnP IGD abuse, attack: T1190, command: "# review AddPortMapping on the IGD control URL for unauthenticated NAT changes (authorized)", purpose: "Assess whether the IGD allows unauthenticated port-mapping." }
```
