# RTSP Module

RTSP (TCP 554) methodology — IP cameras / NVRs. Enumerate streams, test default
credentials, and identify known camera-firmware exposures.

```yaml
module: rtsp
title: RTSP (IP Camera)
scope: port
matches: [rtsp, rtspu]
summary: "RTSP streaming service ({prod})."
finding_keywords: [rtsp, camera, nvr, hikvision, dahua]
unauth_services: [rtsp]
techniques_extra: [T1078.001]
attack_surface:
  - { when: "always", note: "IP cameras/NVRs ship with default credentials and well-known RTSP stream paths; many have firmware auth-bypass CVEs." }
  - { when: "has_cve", note: "Camera firmware has known CVEs (see findings)." }
checks:
  - { name: Methods & info, attack: T1592, command: "nmap -p554 --script rtsp-methods {ip}", purpose: "Enumerate supported RTSP methods and the server/firmware banner." }
  - { name: Stream path discovery, attack: T1595.003, command: "nmap -p554 --script rtsp-url-brute {ip}", purpose: "Discover valid stream URLs (per-vendor path lists)." }
  - { name: Default credentials, attack: T1078.001, command: "# test documented camera defaults (admin/admin, admin/12345) via the RTSP/web UI", purpose: "Identify the vendor and test default credentials (authorized)." }
  - { name: Credential test, attack: T1110.003, command: "hydra -L users.txt -P passwords.txt rtsp://{ip} -f", purpose: "Authorized testing for weak RTSP credentials (mind lockout)." }
```
