# CLAUDE.md
Project context for Claude Code. Read this first.

## What this is
A **knowledge-driven pentest orchestration engine** for **authorized / lab / CTF
use only**. It ingests nmap output (or a whole engagement evidence folder), builds
an inventory + findings, runs per-service assessment modules, correlates findings
into MITRE ATT&CK-mapped attack paths, and **stages** them for a human operator —
with a PySide6 (Qt6) console / dashboard for review and tracking.

## Hard rules (see docs/instructions.md — the constitution)
- **Authorized use only.** Targets must be in a written engagement scope.
- **Methodology, not weaponization.** Modules emit enumeration / authorized
  credential-testing steps mapped to ATT&CK. Do **not** add exploit payloads,
  exploit runners, C2, or auto-exploitation. Attack paths are *staged* for a
  human operator who runs each step manually with their own tooling; staging
  gates on scope confirmation.
- **Knowledge-driven.** Methodology, routing and mappings live in `docs/` as
  Markdown (fenced ```yaml blocks). The Python is a generic engine that loads
  them. Prefer a doc edit over a code change.
- **ATT&CK is the shared vocabulary.** Every check / path step carries a
  technique id; AppSec checks (web/API/...) additionally carry an OWASP
  (WSTG / API Top 10 / MASVS) reference and a CWE id.

## Layout
```
ciphers.py, ciphers_v4.py     TLS cipher engine + nmap SSL/TLS analyzer (Tkinter)
nmap_analyzer.py              full-spectrum nmap analyzer (Inventory) — Tkinter GUI + --no-gui
attack_path_engine.py         findings -> ATT&CK attack paths (Correlation; staging only)
assess.py                     end-to-end CLI pipeline (scope gate -> scan -> analyse -> stage)
profiles.py                   VAPT / Red Team scan profiles (enumeration depth only)
evidence.py                   ingest an engagement evidence folder -> merged inventory
reporting.py                  engagement report (MD/HTML) + ATT&CK Navigator layer
ledger.py                     persistent SQLite engagement ledger (+ run diff, triage)
enrich.py                     live CISA-KEV + FIRST-EPSS feeds (cached, offline-safe) for risk
apptargets.py                 AppSec: web-app targets (auto-promote http/https + operator --web)
pentest_console.py            PySide6 console: Attack Paths + Modules tabs + staging queue
attack_dashboard.py / red_engine.py   target-acquisition dashboard + single GUI entry (.exe)
knowledge_loader.py           parses docs/ yaml knowledge blocks
validate_kb.py                knowledge-base integrity check (CI)
modules/                      generic doc-backed dispatcher + per-service fallbacks
                              (+ web_app / api / mobile / thick: OWASP WSTG / API-Top-10 /
                              MASVS + CWE target-driven AppSec modules)
docs/                         the knowledge base (constitution, registry, maps, module methodology)
tests/                        run_tests.py + fixtures (full_scan.xml, scan.xml, scan.nmap)
```

## Run / verify
```
pip install -r requirements.txt
python run_tests.py ; python validate_kb.py
python nmap_analyzer.py tests/fixtures/full_scan.xml --no-gui --json /tmp/r.json
python -m modules tests/fixtures/full_scan.xml          # knowledge-driven methodology
python assess.py --from-xml tests/fixtures/full_scan.xml --yes
python assess.py --from-xml tests/fixtures/full_scan.xml --yes --web http://target/app --api http://target/api  # AppSec: OWASP WSTG + API Top 10
python assess.py --from-xml tests/fixtures/full_scan.xml --yes --mobile app.apk --thick client.exe  # AppSec: MASVS mobile + thick-client review
python attack_path_engine.py tests/fixtures/full_scan.xml
python knowledge_loader.py                              # KB summary; run after editing docs/
# GUIs (need a display; headless: --selftest)
python red_engine.py tests/fixtures/full_scan.xml
# Packaging (cross-platform): pip/pipx OR a per-OS native binary
pip install .[gui]                                     # redengine / redengine-cli / redengine-scan
python build_app.py                                    # RedEngine.exe | RedEngine | RedEngine.app
# Engagement JSON contract (feeds the read-only flutter/ desktop viewer)
python assess.py --from-xml tests/fixtures/full_scan.xml --yes --emit-json eng.json
# Live risk enrichment + per-asset scoring + engagement ledger (run diff + triage)
python enrich.py                                       # cache/summarise CISA-KEV + FIRST-EPSS
python assess.py --from-xml tests/fixtures/full_scan.xml --yes --enrich --ledger eng.db
python ledger.py eng.db                                # history + diff (new/fixed/muted)
python ledger.py eng.db triage <key> --status false_positive   # disposition a finding
```

## Conventions
- CLI-first; every capability runs headless (`--no-gui` / `--selftest`).
- GUI is PySide6 (Qt6), cross-platform (Windows/Linux/macOS). Ship via pip/pipx
  (`pip install .[gui]` → `redengine`) or a native binary (`python build_app.py`).
- Windows + Python 3.11: force UTF-8 stdio; avoid 3.12-only f-string syntax.
- Keep built-in module fallbacks in sync so the engine runs if `docs/` is absent.
- Validate after editing docs (`python validate_kb.py`).

## Good next tasks
1. Per-check risk tags (safe|intrusive) so VAPT hides lockout-risky steps.
2. Surface live EPSS/KEV provenance in the report + a console triage UI (the risk
   model, live enrichment via `enrich.py`, and ledger run-diff/triage already land in Phase 1).
3. Operator runbook export from the staged queue (methodology checklist; operator runs it).
4. Phase-2 hardening: scope guard, shared finding schema, per-host concurrency (see docs/PHASE2.md).
