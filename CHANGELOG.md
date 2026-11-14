# Changelog

All notable changes to Mimir land here. Older entries are condensed into
"phase" headings; the versions used by the Python package are documented in
`pyproject.toml`.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project tracks [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **Mimir SLM reinforcement learning + mutual teacher training (Phase 24)** —
  the SLM pipeline from Phase 23 gains a reward signal, a GRPO-ready data
  builder, and a bidirectional teacher bridge with Crucible.
  * `slm/reward.py` — scalar reward in `[-1, 1]` per trace from lessons.py
    outcomes + autopilot verdicts + curator label + shape-validator pass
    + optional peer-SLM agreement. Operator-tunable weights via
    `MIMIR_SLM_REWARD_WEIGHTS=` or CLI `--weight k=v`.
  * `slm/distill.py` — teacher-student SFT dataset builder (big local
    model teaches qwen2.5:3b / phi-3-mini student).
  * `slm/rl.py` — GRPO group-sampling + z-score advantage normalisation +
    full trainer recipe (`mimir-slm rl recipe`).
  * `slm/bridge.py` — mutual-teacher bridge with Crucible's SLM over
    the existing HMAC-signed `crucible_bridge`. `export_dump`/`import_dump`
    exchange curated corpora; `query_peer` returns cross-SLM agreement
    `{+1, 0, -1, None}` folded into the reward. Imported rows land as
    `kind=peer:*` with `outcome=NULL` — the peer never curates our data.
  * CLI gains: `mimir-slm reward`, `mimir-slm distill`, `mimir-slm rl export`,
    `mimir-slm rl recipe`, `mimir-slm peer-sync status`/`export`/`import`.
  * Cloud models remain excluded; all RL stays local to the operator's GPU.
- **Mimir SLM training-data pipeline (Phase 23 groundwork)** — `slm/` package
  + `mimir_slm.py` CLI (`mimir-slm`). Opt-in via `MIMIR_SLM_TRACE_DB=/path/to.db`
  (zero cost when unset). Every `qualia.decide` / `qualia.prose` call now emits
  a secondary-scrubbed trace row (prompt, system, LLM output, fallback output,
  `used_fallback`, `validator_passed`, model tag, optional engagement id).
  `vault.redact` scrubs secret-shaped tokens before write.
  * `mimir-slm status`  — corpus snapshot + readiness score (target 500
    curator-labelled `worked` traces).
  * `mimir-slm trace`   — tail recent decisions, filterable by kind.
  * `mimir-slm curate`  — label a trace (`worked` / `no_signal` / `muted`).
  * `mimir-slm export`  — emit curated training JSONL for QLoRA.
  * `mimir-slm train / eval / promote` are documented placeholders (print the
    recipe + prereqs); the engine does not ship a trainer until a curated
    corpus exists. Cloud models remain excluded — all SLM work is local.
- **Autopilot v2 — observe-decide-run loop** (`autopilot_loop.py` /
  `mimir-autopilot-loop`; also `mimir-autopilot --loop N`). Wraps v1 in an
  iteration loop that parses each executed step's stdout via `parsers/`,
  merges new hosts / services / findings back into the engagement JSON,
  re-ranks the queue via `copilot.recommend_from_engagement`, and iterates
  up to `--max-iterations` (default 3) with early-exit when nothing new
  is learned. The gate chain is reused unchanged — every iteration still
  gates on institutional-TLD / ROE / noise / risk / command-safety /
  per-step timeout. `--loop-log FILE` writes a per-iteration JSONL audit
  record; `--lessons DB` applies lessons bias in re-ranking.
- **`parsers/` package** — tool-output parsers feeding Autopilot v2's
  observe step. Ships `parsers.nmap` (default text + grepable `-oG` +
  delegation to `nmap_analyzer` for XML), `parsers.nuclei` (JSONL →
  findings), and `parsers.generic` (regex fallback for IPs, hostnames,
  URLs, CVE references). Every parser is pure, non-raising, and routed by
  command prefix via `parsers._ROUTES` — add a parser by appending a row.
- **Autopilot v1** (`autopilot.py` / `mimir-autopilot`) — the opt-in one-pass
  executor for the staged plan. Default behaviour is unchanged: Mimir still
  stages. Pass `--yes-i-am-authorized` to let it run. Each step passes a
  seven-stage gate chain before fire: institutional-TLD block → ROE scope →
  ROE allowed-window → ROE forbidden-techniques → noise ceiling (opsec.py) →
  risk-tag accept list (default: `safe` only) → command-safety grep
  (belt-and-braces). Verdict per step is one of `executed_ok`,
  `executed_nonzero`, `timeout`, `dry_run`, `skipped_institutional`,
  `skipped_scope`, `skipped_window`, `skipped_forbidden_technique`,
  `skipped_noise`, `skipped_risk`, `skipped_user_declined`,
  `skipped_resume`, `skipped_max_steps`, `aborted`. Supports `--dry-run`,
  `--confirm` (interactive y/N per step), `--resume FILE` (skips steps that
  executed OK on the prior run), `--log FILE` (JSONL tailable log),
  `--ledger DB` (persists to `autopilot_runs` + `autopilot_log` tables),
  `--only-phase` (restrict to one or more phases), per-step `--timeout`,
  `--max-steps` cap, OPSEC-profile pacing between loud steps, SIGINT-safe
  abort (the running subprocess finishes, then the run halts).
- WeasyPrint `pdf` optional extra (`pip install mimir[pdf]`) wiring the PDF
  export path in `reporting.py`; falls back to HTML with a notice when absent.
- `pypdf` `roe-pdf` optional extra so `roe_parse` reads `.pdf` ROE docs.

### Removed
- Legacy `exploits/` dispatcher package (deprecated; conflicted with the
  "no exploit runners" constitution; was already excluded from packaging).

### Fixed
- Force-directed attack graph in `webapi.py` now renders — the inline SVG was
  built but never `appendChild`'d to the host container.

---

## [6.0.0] — Mimir rebrand · public GitHub release

Three themes: unified brand, operator-workflow web app, and the recon /
adversary / knowledge-coverage lifts from four open-source signals.

### Added — operator-workflow web app (`mimir-ops`)
- `mimir_web/` — stdlib-only HTTP app, zero new runtime deps:
  - **Auth**: scrypt-hashed passwords (OWASP 2024+ params; `maxmem=64 MB`);
    HMAC-SHA256 signed session cookies with a server-rotated key; CSRF
    double-submit token; HttpOnly cookies with `SameSite=Lax`.
  - **RBAC**: `admin > lead > operator > viewer` with role-at-least gates.
  - **DB**: SQLite (WAL) — users / engagements / jobs / audit / kv.
  - **Pages**: `/bootstrap` (first setup) · `/login` · `/engagements` list ·
    `/engagements/new` (scope + out-of-scope + windows + noise profile + ROE
    paste → auto-parsed) · `/engagements/<id>` (scope summary + attack-
    initiation form + jobs + audit) · `/engagements/<id>/view` (read-only
    engagement dashboard) · `/engagements/<id>/launch` (background subprocess
    runs `assess.py`) · `/recon` · `/modules` · `/users` · `/audit`.
- `mimir_app.py` — PySide6 (Qt6) desktop console entrypoint.

### Added — intelligence layer
- `advisor.py` — local-Ollama **Planner / Narrator / Adviser**; full operator
  tradecraft (no content filtering — authorized red-team scope).
- `qualia.py` — single routing layer for every qualitative decision; LLM-first
  with deterministic fallback (same output shape).
- `copilot.py` — ranked next-best-actions with reasoning trace; **goal-directed
  strategy** (`--goal domain_admin|full_compromise|foothold|data_exfil|
  ransomware_resilience|wifi_breach`) with bounded ±25 bonus; **lessons bias**
  from past engagements (bounded ±20).
- `llm.py` — stdlib Ollama client; role picks (planner / narrator / adviser /
  embed); cloud models excluded unless `MIMIR_LLM_ALLOW_CLOUD=1`; role-aware
  timeouts.
- `mcp_server.py` — read-only MCP surface over an engagement.
- `crucible_bridge.py` — HMAC-signed bidirectional bridge to Crucible (the
  operator's AI-red-team tool); offline-safe.

### Added — target-driven AppSec coverage
- `web_recon` — subdomain enum + takeover, hidden vhost, CDN/WAF origin,
  GraphQL, web-cache-poisoning.
- `ai_target` — OWASP LLM Top 10 methodology (prompt injection, jailbreak,
  output handling, tool/RAG abuse, model extraction, MCP surface).
- `kubernetes` (ATT&CK Containers), `hypervisor` (ESXi/vCenter/Proxmox/Xen/
  Hyper-V), `identity` (Entra/Okta/Workspace/ADFS), `source` (SAST/SCA/SBOM/
  IaC/CI-CD), `wireless` (Wi-Fi/BLE/Zigbee/sub-GHz).
- `thick_client` extended to macOS (.app/.dmg/.pkg, Mach-O, codesign,
  entitlements, dylib hijack, Keychain) and Linux (ELF, checksec, SUID).

### Added — governance + boundary
- `roe.py` — ROE hard-gates (scope CIDR / hostname / windows / forbidden
  techniques / risk tags / jurisdiction). **Institutional TLD block**
  (`.gov`/`.mil`/`.edu`/`.int` + country variants) wins over operator in-scope;
  override only via `MIMIR_ALLOW_INSTITUTIONAL=1`.
- `roe_parse.py` — regex + LLM dual-extractor over `.md`/`.txt`/`.pdf` → YAML.
- `opsec.py` — per-step noise score 0-10 by ATT&CK id; profiles
  `stealth` (≤3) / `normal` (≤7) / `aggressive` (≤10).
- `vault.py` — AES-256-GCM credential vault with PBKDF2 (600k iter);
  `vault.redact()` log scrubber; **never auto-fills into staged commands**.

### Added — risk + enrichment + lifecycle
- `enrich.py` — CISA-KEV + FIRST-EPSS live feeds, cached + offline-safe.
- `cvss4.py` — CVSS 4.0 vector + band per finding; `/E:A` auto-promoted when a
  public exploit ref exists.
- `exploit_refs.py` — CVE → public exploit **references** (never payloads);
  11 bundled canonical CVEs + optional ExploitDB CSV cache.
- `ct_monitor.py` — Certificate Transparency lookup (crt.sh; cached).
- `lessons.py` — what-worked bias store feeding copilot ranking.
- `ledger.py` — persistent SQLite engagement history + run-diff + triage +
  **checkpoint/replay** (gzipped snapshots across shift hand-offs).
- `timeline.py` — Markdown + SVG stripe from the ledger.

### Added — recon + adversary emulation
- `recon_chain.py` — **5-phase passive-first recon pipeline** (reconftw-
  inspired): passive OSINT → active subdomain → hosts → web → vuln reference.
  22 staged steps, every step carries ATT&CK + risk + noise score + rate-
  limit hints. Tools referenced: subfinder, puredns, naabu, nmap, httpx,
  katana, ffuf, nuclei, dalfox, sqlmap, trufflehog.
- `adversary.py` — **8 Caldera-style adversary profiles** (APT29, APT28,
  FIN7, Volt Typhoon, Lazarus, Conti/LockBit, plus two synthetic
  profiles). `apply_overlay()` non-destructively up-weights copilot actions
  that match an actor's TTP sequence.

### Added — extensibility
- `sdk/` — plugin API: `BaseModule`, `ModuleParams` (stdlib dataclasses),
  `TestHarness` (mock scope + synthetic vault); third parties register under
  entry-point group `mimir.modules`; built-ins win on collision; a broken
  plugin never breaks the engine.

### Added — measurement + quality
- `evals/` — CI-friendly eval harness; 7 scenarios / 102 assertions / 100%
  recall; A/B deterministic vs LLM; non-zero exit on any miss.

### Added — public-release files
- `LICENSE` (AGPL-3.0-or-later), `SECURITY.md`, `CONTRIBUTING.md`,
  `.github/workflows/ci.yml`.

### Changed
- Rebrand across 35 files (`redengine` → `vantage` → `mimir`). Env-var chain
  `MIMIR_* → VANTAGE_* → REDENGINE_*` for backward compat.

---

## [5.x] — Vantage phases 1 – 15

Established the knowledge-driven engine: nmap analyzer, attack-path engine,
46 modules (34 service + 12 AppSec), MITRE ATT&CK Navigator export, 220+
tests, cross-platform packaging (pip/pipx + PyInstaller), ledger + triage.

## [4.x] — Redengine foundation

Initial public-sources inception. CLI-first; staging-only boundary codified.
