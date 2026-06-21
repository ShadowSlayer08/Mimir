# DNS Module

DNS server methodology. One assessment per DNS port: zone transfer, version,
recursion/open-resolver, subdomain enumeration and cache snooping.

```yaml
module: dns
title: DNS
scope: port
matches: [domain]
summary: "DNS service ({prod})."
finding_keywords: [dns, zone transfer, axfr, bind, recursion]
techniques_extra: [T1590.002]
attack_surface:
  - { when: "always", note: "Open recursion enables cache poisoning and DDoS amplification; restrict recursion to trusted clients." }
  - { when: "has_cve", note: "DNS daemon version has known CVEs (see findings)." }
checks:
  - { name: Version / NSID, attack: T1592.002, command: "dig CH TXT version.bind @{ip}", purpose: "Identify the resolver software/version (BIND/Unbound/etc.)." }
  - { name: Zone transfer, attack: T1590.002, command: "dig AXFR {domain} @{ip}", purpose: "Attempt a full zone transfer to dump internal records." }
  - { name: Recursion test, attack: T1046, command: "nmap -sU -p{port} --script dns-recursion {ip}", purpose: "Detect open recursion / open-resolver behaviour (amplification risk)." }
  - { name: Subdomain brute, attack: T1590.002, command: "dnsenum --dnsserver {ip} {domain}", purpose: "Enumerate hosts/subdomains via the resolver." }
  - { name: Cache snooping, attack: T1590, command: "nmap -sU -p{port} --script dns-cache-snoop {ip}", purpose: "Infer recently resolved names from cache (non-recursive queries)." }
  - { name: NSEC walking, attack: T1590.002, command: "nmap -sU -p{port} --script dns-nsec-enum --script-args dns-nsec-enum.domains={domain} {ip}", purpose: "Enumerate DNSSEC-signed zones via NSEC chaining." }
```
