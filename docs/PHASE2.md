# Phase 2 — Orchestration Core

The engine that schedules Phase-1 modules over the inventory.

| Component | Role | Implementation | Status |
| --- | --- | --- | --- |
| Inventory engine | parse scan → hosts/services/findings | `nmap_analyzer.py` | done |
| Knowledge / Registry | service → module routing | `service_registry.md` + `knowledge_loader.py` | done |
| Dispatcher | route each host through matching modules | `modules.dispatch()` | done |
| Workers | render per-service methodology | `modules/` (generic, doc-backed) | done |
| Execution queue | track operator-run steps | `pentest_console.py` | done (tracking only) |

## Remaining hardening
These are the gaps to close before unattended runs (flagged earlier):
```yaml
todo:
  scope_guard:   "allowlist + intensity gate between queue and execution"
  finding_schema:"promote the finding dict to a shared, versioned contract"
  event_loop:    "make inventory append-able; re-dispatch on new assets"
  state:         "persistent job ledger + checkpointing + resumability"
  concurrency:   "per-host worker limits to avoid IDS trips / corrupt results"
  kb_validator:  "CI check: every registry entry resolves; mappings well-formed"
  secrets_store: "vault for creds/hashes/keys, kept out of the knowledge files"
```

## Notes
The dispatcher is synchronous today (one pass over hosts). A queue/worker pool
with the ledger above is the path to long-running, resumable engagements.
