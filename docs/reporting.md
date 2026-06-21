# Reporting

Dual-track output: an **executive** view (risk posture, grades, top exposures)
and a **technical** view (per-finding detail, CVEs, remediation, ATT&CK).

## Available outputs
```yaml
formats:
  terminal: "nmap_analyzer --no-gui summary; modules CLI methodology"
  json:     "nmap_analyzer --json  (findings, host_summary, severity_counts, CVEs)"
  csv:      "nmap_analyzer --csv   (flat findings for spreadsheets/SIEM)"
  html:     "nmap_analyzer --html  (styled report: severity cards + host + findings tables)"
  gui:      "pentest_console: Dashboard-style attack paths + module playbooks + execution queue"
```

## Content
- **Executive** — host grades (A–F), severity counts, unique CVEs, highest-risk
  hosts, service distribution.
- **Technical** — each finding with severity, CVEs, detail and remediation;
  per-module enumeration playbooks; attack-path step chains with ATT&CK ids.

## Risk basis
Severity follows `risk_scoring.md` (CVSS + EPSS + Exposure + Business Impact,
with KEV / public-exploit overrides). Wiring the composite score into
`nmap_analyzer`'s severity (currently CVSS-band based) is the next reporting
task.

## Planned
PDF and GitHub-flavoured Markdown exporters, and export of the console execution
queue + staged playbooks, to align with the wider toolkit's reporting pipeline.
