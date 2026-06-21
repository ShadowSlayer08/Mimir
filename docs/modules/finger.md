# finger Module

finger methodology (79). finger discloses usernames, login times and home
directories — useful for building a spraying list.

```yaml
module: finger
title: finger
scope: port
matches: [finger]
summary: "finger service ({prod})."
finding_keywords: [finger]
techniques_extra: [T1087]
attack_surface:
  - { when: "always", note: "finger discloses usernames, login times and home dirs — useful for building a spraying list; disable it." }
checks:
  - { name: User listing, attack: T1087, command: "finger @{ip}", purpose: "List currently logged-in users." }
  - { name: Account probe, attack: T1087, command: "finger root@{ip}", purpose: "Probe specific accounts for existence and details." }
  - { name: NSE enumeration, attack: T1087, command: "nmap -p{port} --script finger {ip}", purpose: "Enumerate users via the finger NSE script." }
  - { name: Bulk enumeration, attack: T1589, command: "finger-user-enum -U users.txt -t {ip}", purpose: "Enumerate valid usernames in bulk for later spraying." }
```
