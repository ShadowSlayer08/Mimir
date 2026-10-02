# Vantage

> **The elevated viewpoint that reveals the whole surface.**
> A knowledge-driven pentest / red-team **orchestration** engine — it plans and
> stages an engagement end-to-end so a human operator can run it.

**Authorized / lab / CTF / VAPT / red-team use only.** See
[`docs/instructions.md`](docs/instructions.md) — the constitution.

---

## Why Vantage

A modern engagement produces more findings than any operator can triage, more
attack paths than any team can run, and more deliverables than any report can
hold. Vantage sits above the tools and the ledger and gives the operator a
single, measurable, auditable workflow:

- **Methodology, not weaponization.** Vantage does **not** run exploits, build
  payloads, or operate C2. Every attack step is staged with its MITRE ATT&CK
  technique + abuse insight + reference commands for a human to execute
  manually, in authorized scope, with their own tooling.
- **Knowledge in docs.** Methodology and routing live in `docs/*.md` as fenced
  YAML. The Python is a generic loader — a doc edit ships new coverage.
- **LLM-first with deterministic fallback.** Every qualitative decision
  (ranking, re-ordering attack paths, narrating a stage, writing an exec
  summary) routes through `qualia.decide` — a local Ollama model if present,
  the deterministic weighted ranker otherwise. The engine works airgapped.
- **Measured, not asserted.** The eval harness (`vantage-bench`) scores the
  engine against a scenario corpus — regressions are a red CI, not an
  argument.

## What ships

- **Full-spectrum nmap analyzer** + 46 assessment modules covering 129 services
  (Windows / Linux / Database / Mail / DNS / VoIP / VPN / ICS/OT / IoT / IPMI /
  Printer / SNMP / RTSP / and more).
- **Target-driven AppSec pillar** — web (OWASP WSTG) / API (OWASP API Top 10) /
  mobile (MASVS) / thick client (Win / Linux / **macOS Mach-O**) / cloud
  (ATT&CK-Cloud: AWS / Azure / GCP) / Kubernetes (ATT&CK-Containers) /
  wireless / supply-chain / SaaS identity / hypervisor.
- **Attack path engine** — correlates findings into MITRE-ATT&CK-mapped multi-
  step paths (Initial Access → Lateral → Credential → Domain Compromise).
- **AD graph** — ingests BloodHound / SoapHound / RustHound; stages path-to-DA.
- **Local LLM co-pilot** (optional, offline-safe) — Planner / Narrator /
  Adviser running against Ollama. Cloud models excluded by default.
- **Read-only MCP server** — expose an engagement as query-only tools to any
  LLM client (Claude Desktop, Cursor, Windsurf).
- **Governance** — Rules of Engagement YAML with scope / technique / risk /
  time-window gates, plus a hard guardrail for `.gov` / `.mil` / `.edu` /
  `.int` TLDs.
- **Encrypted vault** — AES-256-GCM credential store for operator secrets
  (never written into staged commands or reports).
- **Enrichment** — live CISA-KEV + FIRST-EPSS; CVSS 4.0 vectors; CVE →
  public exploit references (never payloads).
- **Reporting** — Markdown / HTML / ATT&CK Navigator layer / engagement
  timeline / operator runbook / signed engagement JSON contract.
- **Eval harness** — 7 scenario YAMLs / 102 assertions / 100 % recall; A/B
  deterministic vs LLM-first.
- **Ledger + lessons** — persistent SQLite history with run diff, triage, and
  a bounded "what worked" bias feeding the co-pilot's ranking.

## Install

Python **3.11+**. Install via pip/pipx or build an OS-native binary:

```bash
pip install .[gui]          # GUI (PySide6) + CLI       (or: pipx install ".[gui]")
pip install .               # headless CLI engine only
```

```bash
# Native binary (no Python required on the target machine)
python build_app.py         # dist/Vantage.exe | dist/Vantage | dist/Vantage.app
```

Live scanning needs **nmap** on `PATH` (Windows: Npcap too). Offline ingest
works without it.

## Quickstart (60 seconds)

```bash
# Ingest an existing nmap XML, derive attack paths, emit a signed engagement JSON
vantage-cli --from-xml tests/fixtures/full_scan.xml --yes --emit-json eng.json

# Browse the engagement in the local read-only web GUI
vantage-web eng.json                              # http://localhost:8787

# Ranked next-best actions (deterministic ranker + score trace)
vantage-copilot eng.json --why

# Operator runbook + LLM-expanded playbook (needs Ollama; offline-safe otherwise)
vantage-advisor eng.json --runbook rb.md

# Measured regression check
vantage-bench                                     # all scenarios, non-zero exit on any miss
```

Full command list: `vantage-cli --help`, plus specialist entry points —
`vantage-mcp`, `vantage-roe`, `vantage-timeline`, `vantage-vault`,
`vantage-exploits`, `vantage-adgraph`, `vantage-lessons`, `vantage-bench`.

## Rules of Engagement (hard gates)

Every target host crosses two filters before the operator sees it staged:

1. **Hard institutional guardrail** — refuses `.gov` / `.mil` / `.edu` / `.int`
   (plus country variants `.gov.uk`, `.gob.es`, `.gouv.fr`, `.ac.uk`, …) by
   default. Override only with explicit operator consent via
   `VANTAGE_ALLOW_INSTITUTIONAL=1`.
2. **ROE YAML** — scope (`in_scope` CIDR / hostname suffix / exact), time
   windows, forbidden techniques (`T####`), forbidden attack-path kinds, and
   forbidden risk tags (`intrusive`). Every rejection carries a reason + the
   engagement's jurisdiction for the audit trail.

```yaml
# engagement.roe.yml
engagement: acme-2026Q4
jurisdiction: US-NY
in_scope: [10.0.0.0/24, .corp.lab]
out_of_scope: [10.0.0.99]
allowed_windows: [{days: [mon,tue,wed,thu,fri], hours: ['18:00', '04:00']}]
forbidden_techniques: [T1499, T1499.001]            # no DoS
forbidden_risk: [intrusive]                          # VAPT mode
```

```bash
vantage-roe eng.json engagement.roe.yml --json eng.filtered.json
```

## Repository health

- **193/193 tests pass.** `python run_tests.py`
- **Knowledge base validates cleanly.** `python validate_kb.py`
- **7 eval scenarios / 102 assertions / 100 % recall.** `vantage-bench`
- CI (GitHub Actions) runs tests + KB check + evals on every PR, matrix
  across Python 3.11 / 3.12 on Ubuntu / Windows / macOS.

## Documentation

- [`docs/instructions.md`](docs/instructions.md) — the constitution (hard rules)
- [`docs/developer_guide.md`](docs/developer_guide.md) — how to add a module
- [`CLAUDE.md`](CLAUDE.md) / [`AGENTS.md`](AGENTS.md) — agent instructions and layout
- [`docs/packaging.md`](docs/packaging.md) — pip, pipx, PyInstaller, Flutter viewer
- [`SECURITY.md`](SECURITY.md) — reporting a vulnerability
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to help

## License

AGPL-3.0-or-later. See [`LICENSE`](LICENSE). Vantage is open — the AGPL
protects against commercial repackaging that doesn't contribute back.

## Legal and ethical reminder

Running network scans or application assessments against systems **without
written authorization** is illegal in most jurisdictions. Vantage will refuse
to help you do so — the hard guardrail is on by default, and the ROE scope gate
and `--yes` authorization confirmation are not decorative. If you need to
assess your own systems, your written engagement scope is the artifact Vantage
expects. Everything else is out of bounds and will not be supported.
