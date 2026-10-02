# Web Recon Module (attack-surface discovery)

**AppSec pillar — target-driven.** Methodology for the five web-recon surfaces
a professional engagement always needs and most VAPT tools skip:
subdomain enumeration + takeover, hidden virtual hosts, CDN/WAF origin
discovery, GraphQL misconfiguration, and web cache poisoning.

Checks are ATT&CK + OWASP (WSTG where applicable) + CWE-mapped with a
`safe|intrusive` risk tag. Takeover + GraphQL + cache-poisoning *testing* is
intrusive (changes state); passive enumeration + fingerprinting is safe.

Targets come from `assess --web-recon <domain|url>`. For an existing engagement
with discovered http/https services, operator can also auto-promote the apex
domains with `--web-recon-auto`. Tooling the methodology references: subfinder /
amass / assetfinder / subjack / nuclei / baddns / ffuf / graphw00f / graphql-cop
/ clairvoyance / WCVS.

**Boundary:** methodology + staging only — the operator runs each tool with their
own tooling, in authorized scope.

```yaml
module: web_recon
title: Web Attack Surface Recon
scope: target
matches: [web-recon, webrecon, recon]
summary: "Web recon ({host}) — subdomain + takeover + vhost + CDN origin + GraphQL + cache poisoning."
techniques_extra: []
checks:
  - {name: Subdomain enumeration (passive), attack: T1590.005, owasp: WSTG-INFO-04, cwe: CWE-200, risk: safe, when: always,
     command: "subfinder -d {host} -silent -all   # or: amass enum -passive -d {host}; assetfinder {host}",
     purpose: "Discover subdomains via CT logs / passive DNS / APIs (no traffic to target)."}
  - {name: Subdomain takeover (dangling CNAME), attack: T1583.001, owasp: WSTG-CONF-10, cwe: CWE-404, risk: safe, when: always,
     command: "subjack -w subs.txt -t 50 -timeout 30 -ssl -c ~/subjack/fingerprints.json -o takeovers.txt",
     purpose: "Find dangling CNAMEs that point at reclaimable third-party services."}
  - {name: Hidden vhost discovery, attack: T1595, owasp: WSTG-CONF-01, cwe: CWE-200, risk: safe, when: always,
     command: "ffuf -u https://{host}/ -H 'Host: FUZZ.{host}' -w ~/.cache/wordlists/subdomains.txt -fc 404,400 -fs 0",
     purpose: "Find virtual hosts the DNS doesn't expose by fuzzing the Host header."}
  - {name: CDN / WAF fingerprint, attack: T1596, owasp: WSTG-INFO-01, cwe: CWE-200, risk: safe, when: always,
     command: "wafw00f https://{host}; whatwaf -u https://{host}",
     purpose: "Identify which CDN / WAF is in front of the target."}
  - {name: Origin discovery via CT history, attack: T1596.001, owasp: "", cwe: CWE-200, risk: safe, when: always,
     command: "# crt.sh?q={host} historical certs; dig old subdomains that bypass the CDN",
     purpose: "Find the origin IP in historical CT log data (common CDN-bypass path)."}
  - {name: GraphQL introspection, attack: T1595.002, owasp: WSTG-APIT-01, cwe: CWE-306, risk: safe, when: always,
     command: "graphql-cop -t https://{host}/graphql   # or: inql scan -t https://{host}/graphql",
     purpose: "Dump the schema when introspection is enabled (OWASP API Top 10)."}
  - {name: Cache behaviour discovery, attack: T1557, owasp: WSTG-CONF-07, cwe: CWE-444, risk: safe, when: always,
     command: "wcvs -u https://{host}/",
     purpose: "Map which headers / parameters the cache keys on."}
  - {name: Unkeyed input poisoning, attack: T1557, owasp: WSTG-CONF-07, cwe: CWE-444, risk: intrusive, when: always,
     command: "wcvs -u https://{host}/ -X 'X-Forwarded-Host,X-Original-URL,X-Rewrite-URL'",
     purpose: "Test unkeyed header injection that lands in cached responses."}
```
