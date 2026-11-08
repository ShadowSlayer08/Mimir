# Instructions

Platform constitution and development rules.

These are the non-negotiable principles for the pentest orchestration engine.
Everything in this repo follows them.

## 1. Authorized use only
This tooling is for **authorized penetration testing, lab and CTF use**. Every
target must be inside a written engagement scope. The engine helps plan and
track; the operator is responsible for authorization.

## 2. Methodology, not weaponization
Modules emit **enumeration and authorized credential-testing methodology** mapped
to MITRE ATT&CK. The engine does **not** ship or auto-launch exploit payloads.
Attack paths are *planned* and *staged* for a human operator who executes each
step manually — see `attack_paths.md`. Staging requires explicit scope
confirmation.

## 3. Knowledge-driven
Methodology, routing and mappings live in `docs/` as Markdown, not in code (see
`knowledge.md`, `developer_guide.md`). The Python is a generic engine that loads
and renders the knowledge. Prefer a doc edit over a code change.

## 4. MITRE ATT&CK is the backbone
Every check and attack-path step carries an ATT&CK technique id, so findings,
modules and paths share one vocabulary. AppSec checks (web/API/mobile) additionally
carry an OWASP (WSTG / API Top 10 / MASVS) reference and a CWE id alongside it.

## 5. Engineering conventions
- CLI-first; every capability runs headless (`--no-gui` / `--selftest`).
- Modular Python; GUI is PySide6 (Qt6).
- Cross-platform install: pip/pipx (`pip install .`) or a per-OS native binary
  (`python build_app.py`); no fixed install path.
- Keep built-in fallbacks working if the knowledge base is absent.
- Validate knowledge after edits (`python3 knowledge_loader.py`).

## 6. Autopilot mode (opt-in)
The default flow is still **stage + hand to a human operator**. Rule 2 stands.
Autopilot v1 (`autopilot.py` / `mimir-autopilot`) is an **explicit, per-run
opt-in** that lets the engine *run* the steps it has already staged, one pass,
under the same safety layers that gate every subprocess spawn:

1. **Explicit authorization flag.** `autopilot.py` refuses to do anything
   without `--yes-i-am-authorized`. This is the operator's attestation that
   the engagement is in scope and the written authorization covers automated
   execution of the planned methodology.
2. **Institutional-TLD hard-block.** `.gov`, `.mil`, `.edu`, `.int`
   (and country variants like `.gov.uk`) are refused unless
   `MIMIR_ALLOW_INSTITUTIONAL=1` is set in the environment — same rule as
   the staging pipeline.
3. **ROE hard-gates.** Scope (in / out of scope), allowed-window, and
   forbidden-technique lists apply to every step.
4. **Noise ceiling (opsec.py).** A step whose noise score (0–10) exceeds the
   active `--noise-ceiling` is skipped. Default ceiling is 5 — safe recon
   only. Operator raises it (7 for normal, 10 for aggressive) consciously.
5. **Risk-tag accept list.** Only steps whose `risk` is in `--accept-risk`
   run. Default is `safe` only. Opt in to `intrusive` explicitly.
6. **Command-safety grep.** A belt-and-braces last-mile deny list refuses to
   pass known-destructive shell patterns (`rm -rf /`, fork bombs, firewall
   resets, anti-forensics / log clearing, kernel-module ops) to a subprocess
   even if an earlier stage emitted one.
7. **Per-step hard timeout.** Every subprocess runs under `subprocess.run(...,
   timeout=...)`; on expiry the process is killed and the verdict is `timeout`.
8. **Auditable.** Every step writes a JSONL log entry and a row in the
   engagement ledger (`autopilot_runs` + `autopilot_log` tables), including
   exit code, stdout/stderr tails, verdict, and gate reason.
9. **No new tools shipped.** Autopilot runs the tools the operator installed
   (nmap, nuclei, …). The engine never bundles exploit payloads, C2 agents,
   or implants. Rule 2 is not relaxed.
10. **Resumable + abortable.** `--resume` replays the prior log and skips
    steps already executed OK. SIGINT lets the running step finish, then
    halts the run cleanly.

Autopilot is still a **methodology executor**: it runs what the staged queue
contains — nmap probes, HTTP enumeration, auth-protocol checks, authorised
credential tests — not exploitation primitives. The engine does not plan
offensive tradecraft inside autopilot that the staging pass itself wouldn't
have produced.
