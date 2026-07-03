# Knowledge Engine

Master knowledge file for methodology-driven pentest orchestration.

The platform is **knowledge-driven**: behaviour lives in this `docs/` tree as
structured Markdown, and the engine (`knowledge_loader.py` + `modules/`) reads
from it at runtime. Adding a service, an NSE script, a tool, or an assessment
step is an edit to a Markdown file — not a code change.

## Knowledge files (machine-read)

Each file below carries a fenced ```yaml block the loader merges:

| File | Provides | Consumed by |
| --- | --- | --- |
| `service_registry.md` | service-name → module(s) routing | dispatcher |
| `nse_mapping.md` | service → recommended NSE scripts | enumeration |
| `tool_mapping.md` | service → external tools | enumeration |
| `risk_scoring.md` | CVSS+EPSS+Exposure+Business weights, bands, KEV override; live EPSS/KEV via `enrich.py` (`--enrich`) | risk model |
| `appsec/web.md` | OWASP-WSTG web-app methodology (target-driven; checks carry OWASP+CWE) | web_app module |
| `modules/web.md` | HTTP/HTTPS methodology (checks, attack surface) | web module |
| `modules/smb.md` | SMB methodology | smb module |
| `modules/active_directory.md` | LDAP/Kerberos/AD methodology | AD module |
| `modules/database.md` | database methodology (per-engine connect map) | database module |

## Pipeline

```yaml
pipeline:
  architecture: [Inventory, Knowledge, Workers, Correlation, Reporting]
  workflow: [Discovery, Classification, Enumeration, Correlation, "Attack Paths", Reporting]
```

Inventory comes from `nmap_analyzer` (parse + findings). Knowledge is this tree.
Workers are the modules dispatched per service. Correlation builds attack paths
(`attack_path_engine`). Reporting renders the results.

## Placeholders

Module commands are templated; the engine substitutes:
`{ip} {port} {scheme} {SCHEME} {label} {domain} {frag} {disp} {prod} {ver} {auth_cmd}`.

## Methodology only

Module knowledge describes enumeration and authorized credential-testing steps
mapped to MITRE ATT&CK. The engine generates and tracks; it does not execute.
