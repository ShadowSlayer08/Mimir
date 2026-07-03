# AGENTS.md

Project context for Codex / other agents. Read this first. This file mirrors
`CLAUDE.md`; if they ever disagree, **`docs/instructions.md` (the constitution)
wins**.

## What this is
A **knowledge-driven pentest / red-team ORCHESTRATION engine** for **authorized
engagements, lab, and CTF use only**.

It ingests nmap output (or a whole evidence folder), builds an inventory +
findings, runs per-service assessment modules, and correlates findings into
MITRE ATT&CK-mapped attack paths that it **stages** for a human operator — with a
PySide6 (Qt6) console for review and execution tracking.

## Hard rules (see docs/instructions.md)
- **Authorized use only.** Targets must be in a written engagement scope or
  authorized lab/CTF environment. Always obtain explicit permission.
- **Methodology, not weaponization.** Modules emit enumeration / authorized
  credential-testing methodology mapped to ATT&CK. The engine does **not** ship
  or auto-launch exploit payloads, exploit runners, or C2. Attack paths are
  *planned* and *staged* for a human operator who executes each step manually
  with their own tooling; staging gates on scope confirmation.
- **Knowledge-driven.** Methodology, routing and mappings live in `docs/` as
  Markdown (fenced ```yaml blocks). The Python is a generic engine that loads
  them. Prefer a doc edit over a code change.
- **ATT&CK is the shared vocabulary.** Every check / path step carries a
  technique/sub-technique id; AppSec checks (web/API/...) additionally carry an
  OWASP (WSTG / API Top 10 / MASVS) reference and a CWE id.

## Layout
```
ciphers.py, ciphers_v4.py     TLS cipher engine + nmap SSL/TLS analyzer (Tkinter)
nmap_analyzer.py              full-spectrum nmap analyzer (Inventory) — Tkinter GUI + --no-gui
attack_path_engine.py         findings -> ATT&CK attack paths (Correlation; staging only)
assess.py                     end-to-end CLI pipeline (scope gate -> scan -> analyse -> stage)
profiles.py / evidence.py     scan profiles (VAPT/Red Team) + evidence-folder ingestion
reporting.py / ledger.py      engagement report + ATT&CK Navigator layer; SQLite ledger
apptargets.py / modules/web_app.py   AppSec: web apps as target-driven OWASP-WSTG objects
pentest_console.py            PySide6 console: Attack Paths + Modules tabs + staging queue
attack_dashboard.py / red_engine.py   dashboard + single GUI entry (.exe)
knowledge_loader.py / validate_kb.py  load + validate the docs/ knowledge base
modules/                      generic doc-backed dispatcher + per-service fallbacks
docs/                         the knowledge base (constitution, registry, maps, module methodology)
tests/                        run_tests.py + sample nmap scans
```

## Run / verify
```
pip install -r requirements.txt
python run_tests.py ; python validate_kb.py
python nmap_analyzer.py tests/fixtures/full_scan.xml --no-gui --json /tmp/r.json
python -m modules tests/fixtures/full_scan.xml          # knowledge-driven methodology
python attack_path_engine.py tests/fixtures/full_scan.xml
python knowledge_loader.py                              # KB summary; run after editing docs/
# GUIs (need a display; headless: xvfb-run … --selftest)
python red_engine.py tests/fixtures/full_scan.xml
```

## Conventions
- CLI-first; every capability has a headless path (`--no-gui` / `--selftest`).
- GUI testing needs a display — use `xvfb-run` and the `--selftest` hooks.
- Cross-platform (Windows/Linux/macOS): pip/pipx install or a per-OS native
  binary (`build_app.py`). Qt6 ≥6.5 needs `libxcb-cursor0` on Linux.
- Keep built-in module fallbacks in sync so the engine runs if `docs/` is absent.
- Methodology modules describe what a human operator runs; they do not execute it.

## Good next tasks
1. pytest/`run_tests.py` coverage from `--selftest` hooks + fixtures (parser, routing,
   attack paths, evidence ingestion, ledger).
2. KB validator in CI (`validate_kb.py`): registry entries resolve to modules; NSE/tool
   maps well-formed; every check carries an ATT&CK id.
3. Surface live EPSS/KEV provenance in the report + a console triage UI (risk model,
   live enrichment via `enrich.py`, and ledger run-diff/triage already done).
4. Phase-2 hardening: scope guard, shared finding schema, per-host concurrency (docs/PHASE2.md).
5. Operator runbook export from the staged queue (the operator executes it; the engine does not).
