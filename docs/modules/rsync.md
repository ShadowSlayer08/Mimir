# rsync Module

rsync-daemon methodology (873). rsync modules are frequently world-readable or
world-writable without authentication.

```yaml
module: rsync
title: rsync
scope: port
matches: [rsync]
summary: "rsync daemon ({prod}) reachable."
finding_keywords: [rsync]
unauth_services: [rsync]
techniques_extra: [T1135]
attack_surface:
  - { when: "unauth", note: "rsync modules are frequently world-readable/writable without authentication — enumerate and test each module." }
checks:
  - { name: Module listing, attack: T1135, command: "rsync rsync://{ip}:{port}/", purpose: "List available rsync modules (shares)." }
  - { name: Anonymous read, attack: T1039, command: "rsync -av rsync://{ip}:{port}/<module>/ ./loot/", purpose: "Test anonymous read access and inventory exposed data (authorized)." }
  - { name: Write test, attack: T1565, command: "# authorized: rsync ./test rsync://{ip}:{port}/<module>/  (then remove)", purpose: "Determine whether a module is writable." }
  - { name: NSE enumeration, attack: T1135, command: "nmap -p{port} --script rsync-list-modules {ip}", purpose: "Enumerate modules and auth requirements via NSE." }
```
