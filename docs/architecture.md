# Architecture

Component view of the engine. Five stages, each backed by a concrete piece of the repo.
Inventory          Knowledge            Workers           Correlation        Handoff
┌───────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐    ┌───────────┐
│nmap parse │ ──> │ docs/ + KB  │ ──> │  modules/   │ ──> │attack_path_ │ ─> │ console + │
│ +findings │     │   loader    │     │ (per svc)   │     │  engine     │    │  staging  │
└───────────┘     └─────────────┘     └─────────────┘     └─────────────┘    └───────────┘
nmap_analyzer    knowledge_loader     dispatch()          generate_paths     reporting/ledger

## Components

- **Inventory** — `nmap_analyzer.py` parses nmap into hosts, services, and findings.
- **Knowledge** — `docs/` contains assessment methodologies, NSE/tool mappings, and routing.
- **Workers** — `modules/` dispatches per-service assessment (methodology) modules.
- **Correlation** — `attack_path_engine.py` builds ATT&CK attack paths, staged for manual execution.
- **Handoff** — PySide6 console / dashboard + report, Navigator layer and ledger export.
  Staging only — the engine never runs exploits, payloads or C2.

**Principle**: Fully knowledge-driven; methodology lives in `docs/` as YAML, code stays generic.
The engine plans and stages — a human operator executes each step with their own tooling.