# Instructions

Platform constitution and development rules.

These are the non-negotiable principles for the pentest orchestration engine.
Everything in this repo follows them.

## 1. Authorized use only
This tooling is for **authorized penetration testing, lab and CTF use**. Every
target must be inside a written engagement scope. The engine helps plan and
track; the operator is responsible for authorization.

## 2. Methodology-driven autonomous testing
Modules emit **enumeration and authorized credential-testing methodology**
mapped to MITRE ATT&CK. The engine now ships **two first-class execution
modes**, and the operator picks per run:

* **Staging mode** — the engine assesses, correlates, ranks, narrates, and
  hands the operator a runbook. A human runs each step with their own
  tooling. This is the default when no autonomous flag is set.
* **Autonomous mode** — the operator passes `--yes-i-am-authorized` and
  `mimir-autopilot` (v1) or `mimir-autopilot-loop` (v2) *runs* the staged
  methodology. The gate chain described in rules 6–7 enforces authorization
  at every subprocess spawn; autonomy without those gates is never
  permitted.

What stays off-limits in both modes, without exception:

* The engine does **not** ship or bundle exploit payloads, implants, C2
  agents, or offensive primitives. `mimir-autopilot` invokes the TOOLS
  the operator installed (nmap, nuclei, httpx, burp, msfconsole from the
  operator's own Metasploit install, etc.); it does not host them.
* No module may author a step that would weaponize a finding into an
  implant; staging and autonomous execution both operate on the same
  methodology shape (recon, authorized credential testing, authorized
  misconfiguration checks).
* The constitution's rule 1 (written authorization) applies identically
  to both modes. Autonomous mode is more dangerous, not less authorized.

Autonomous mode is layered: **fact-driven**, **verified-only**, **budget-
bounded**, **argv-allow-listed**, and **attribution-stamped** — see rule
6 and rule 8.

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

## 6. Autopilot — the gate chain (first-class autonomous mode)
Autopilot v1 (`autopilot.py` / `mimir-autopilot`) and v2
(`autopilot_loop.py` / `mimir-autopilot-loop`) run the staged methodology
under a layered gate chain that enforces authorization at every subprocess
spawn:

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

Autopilot is a **methodology executor**: it runs what the staged queue
contains — nmap probes, HTTP enumeration, auth-protocol checks, authorised
credential tests — not exploitation primitives. The engine does not plan
offensive tradecraft inside autopilot that the staging pass itself wouldn't
have produced.

## 8. Autonomous-mode hardening (Phase 28, borrowed from ARTEX + Cairn)
Autonomous mode is dangerous enough to deserve its own layer of safety on
top of the gate chain. These rules apply to every autopilot subprocess and
every v2 loop iteration:

1. **Argv allow-list** — on top of the deny-list command-safety grep, the
   operator may supply an *allow-list* of permitted argv prefixes via
   `--allow-bin nmap --allow-bin curl ...` or
   `MIMIR_AUTOPILOT_ALLOWED_BINS=nmap,curl,dig,...`. When set, any command
   whose first token isn't in the list is skipped with
   `skipped_argv_not_allowed`. Pipes, redirects, and shell wrappers
   (`sudo`, `env`, `xargs`, `find -exec`, backticks, `$(...)`) never
   inherit the allow — each simple command inside the chain must itself
   pass the gate.
2. **Dial-time scope re-check** — ROE's scope gate is enforced at step-
   emit time, but DNS can change between emit and fire. Before each
   subprocess spawn, the engine resolves every hostname in the command
   and refuses execution if any resolved address falls outside the ROE's
   in-scope CIDRs. This defeats rebinding and short-TTL drift. Managed
   by `scope_guard.py`; only kicks in when ROE supplies an explicit
   in-scope IP list.
3. **Budget caps** — the loop tracks cumulative token spend (LLM-using
   steps) and turns across iterations. `--budget-tokens N` and
   `--budget-turns N` cap the run; the next step after the cap lands
   `skipped_budget`. Default: unbounded; `--budget auto` applies
   sensible ceilings per OPSEC profile (stealth=low, aggressive=high).
4. **Approver attribution** — every verdict in the ledger carries an
   `approved_by` field, one of `rule` (gate chain passed on its own),
   `human` (`--confirm` answered yes), `model` (an LLM-based gate
   endorsed it), or `system` (dry-run or auto-approved by env). The
   ledger is append-only and signed-off audit evidence.
5. **Verified findings** — when a parser emits a finding, the engine
   requires a verbatim evidence quote tying the claim to captured
   output. Findings without a quote land as `verified=false` and the
   co-pilot deprioritizes them in ranking.
6. **Fact ledger** — every autopilot step produces an immutable Fact
   (`fact_ledger.py`); state changes are append-only. A corrective
   Fact can `reopen` a prior conclusion (lessons.py outcomes, external
   judges, or `mimir-facts reopen`). The engagement JSON stays the
   mutable summary; the Fact ledger is the source of truth for replay,
   SLM training, and audit.

### 6a. Autopilot v2 — observe-decide-run loop
Autopilot v2 (`autopilot_loop.py` / `mimir-autopilot-loop`, also reachable via
`mimir-autopilot --loop N`) wraps v1 in an outer loop that:

* **Observes.** After each v1 pass it reads the stdout/stderr tail of every
  executed step and dispatches it to a parser (`parsers/nmap.py`,
  `parsers/nuclei.py`, `parsers/generic.py` fallback). Each parser returns a
  `ParseResult` with new hosts, services, findings and (never passwords)
  credential pointers.
* **Decides.** Merges every ParseResult into the engagement JSON — dedup'd
  by (host, port) for services and (host, title, cve) for findings — then
  re-ranks the queue via `copilot.recommend_from_engagement`.
* **Runs again.** Up to `--max-iterations` passes (default 3). The loop
  exits early when an iteration both produces no new intel AND executes no
  steps.

The gate chain is reused unchanged — every iteration still gates on
institutional TLD, ROE, allowed-window, forbidden-techniques, noise
ceiling, risk accept list and command-safety. v2 never relaxes v1 safety.

The parser contract is PURE: no network, no filesystem writes, no raise on
malformed input. Dispatch is command-prefix routing (`_ROUTES` in
`parsers/__init__.py`); add a parser by appending a `(("prefix",), fn)` row.

### 6b. Mimir SLM — specialised brain (Phase 23 groundwork LANDED)
Mimir already routes every qualitative decision through `qualia.decide` /
`qualia.prose`. Phase 23 lands the TRAINING-DATA PIPELINE around those
calls; the first LoRA ships only after a curated corpus exists.

Shipped in Phase 23:
* `slm/trace.py` — opt-in append-only SQLite sink. Set
  `MIMIR_SLM_TRACE_DB=/path/to.db` to start capturing; unset for zero
  cost. Every row is secondary-scrubbed via `vault.redact` before write.
  `MIMIR_SLM_TRACE_ENGAGEMENT=<id>` tags rows for later per-engagement
  filtering.
* `qualia.decide` and `qualia.prose` emit exactly one trace per call —
  LLM output when the model won, fallback output otherwise, with a
  `validator_passed` flag.
* `mimir_slm.py` (`mimir-slm` CLI): `status` (corpus snapshot +
  readiness score), `trace` (tail), `export` (curated training JSONL),
  `curate` (label a row `worked` / `no_signal` / `muted`).
* `train`, `eval`, `promote` are DOCUMENTED PLACEHOLDERS: they print the
  recipe + prereqs rather than shipping a trainer in-tree. The engine
  will not ship a trainer until the first corpus exists (avoids the
  "elaborate pipeline with no data" trap).

Training recipe (operator-driven, when ready):
1. Export: `mimir-slm export train.jsonl --only-outcome worked`.
2. Base:   `qwen2.5:3b-instruct` (planner / adviser) or
           `phi-3-mini-4k-instruct` (narrator).
3. Train:  QLoRA (trl.SFTTrainer or unsloth) on a local GPU; rank 16
           adapter; 1–3 epochs; lr 2e-4; seq-len 2048.
4. Convert + quantise to GGUF via llama.cpp (Q5_K_M).
5. Serve via an Ollama Modelfile tagged `mimir-slm:<yyyymmdd>`;
   `qualia.decide` picks it up automatically through the existing
   `llm.py` role abstraction.

Cloud models stay excluded (`MIMIR_LLM_ALLOW_CLOUD=1` escape hatch
unchanged). Fine-tuning is local-only.

## 7. Autopilot v2 — observe-decide-run loop (Phase 21+22)
`mimir-autopilot --loop N` (or `mimir-autopilot-loop`) wraps v1 in an outer
loop: each iteration parses every executed step's stdout via `parsers/`,
merges new hosts / services / URLs / subdomains / findings back into the
engagement JSON, re-dispatches the knowledge-driven modules against the
new discoveries (plan GROWS mid-loop), re-ranks via copilot, and
iterates with early-exit convergence.

The gate chain from rule 6 is reused unchanged. Every iteration passes
through institutional / ROE / noise / risk / command-safety / argv-
allow-list / dial-time-scope gates, with the per-step timeout and
cumulative budget caps. v2 never relaxes v1 safety.

### 6c. Reinforcement learning + mutual teacher training (Phase 24)
Phase 24 adds a reward signal, a GRPO-ready data pipeline, and a mutual-
teacher bridge with Crucible — the paired AI-red-team engine — so both
SLMs can train against each other's judgment.

Shipped in Phase 24:

* **`slm/reward.py`** — scalar reward in `[-1, 1]` per trace. Weighted
  sum of: curator outcome (worked / no_signal / muted), lessons ledger
  outcome (`lessons.py` → technique worked / burned in this context),
  autopilot verdict for the derived step (executed_ok / nonzero /
  timeout / skipped), shape-validator pass, and an optional peer-SLM
  agreement signal. Weights are operator-tunable via
  `MIMIR_SLM_REWARD_WEIGHTS=k1=.., k2=..` or the CLI `--weight k=v`
  flag. Writes `reward` + `reward_breakdown` columns.
* **`slm/distill.py`** — teacher-student dataset builder. For each
  curated trace, re-asks the strongest *local* model (chosen via
  `llm.info().picks`) for a reference answer, then emits
  `{prompt, student, teacher, reward, role, kind, outcome, source}`
  rows for SFT warm-up. Cloud models stay excluded.
* **`slm/rl.py`** — GRPO (group-relative policy optimisation) support.
  Samples N candidate responses per curated prompt from the teacher,
  scores each via `slm.reward.compute_reward`, and z-scores rewards
  inside each group to produce `advantage` values the GRPO trainer
  consumes. Emits one JSONL row per prompt. `recipe()` prints the full
  trainer script (base model, QLoRA knobs, llama.cpp conversion,
  Ollama Modelfile).
* **`slm/bridge.py`** — Mimir ↔ Crucible mutual-teacher bridge.
  * `export_dump` emits a JSONL dump Crucible can ingest.
  * `import_dump` ingests Crucible's dumps as `kind=peer:*` rows with
    `outcome=NULL` — operator curates them explicitly; the peer never
    labels our data.
  * `query_peer(prompt, response)` asks Crucible's SLM whether the
    response is reasonable, returns `{+1, 0, -1, None}` — folded into
    `slm.reward.compute_reward(..., peer_signal=...)` for training.
  * Transport reuses `crucible_bridge._request` (HMAC-SHA256 over the
    operator's `CRUCIBLE_API_KEY`). Offline-safe: no URL / no key
    means `None` signal, never a crash.

Operator flow — from captured traces to a mutually-trained SLM:

1. Capture: `export MIMIR_SLM_TRACE_DB=~/mimir-slm.db` then run
   engagements normally.
2. Curate: `mimir-slm curate <id> worked` on decisions that produced
   real findings.
3. Score: `mimir-slm reward --lessons eng.db --ledger eng.db --with-peer`
   (the `--with-peer` flag queries Crucible for cross-SLM agreement).
4. Exchange: `mimir-slm peer-sync export dump.jsonl` (send to Crucible)
   and `mimir-slm peer-sync import crucible-dump.jsonl` (ingest its
   curated corpus).
5. Build GRPO dataset: `mimir-slm rl export train.grpo.jsonl
   --samples-per-prompt 4 --lessons eng.db --ledger eng.db --with-peer`.
6. Train (outside the engine): run the GRPO script from
   `mimir-slm rl recipe` on a local GPU.
7. Promote: tag the resulting GGUF `mimir-slm:<yyyymmdd>` in Ollama;
   set `MIMIR_LLM_PLANNER` / `_ADVISER` / `_NARRATOR` env vars.
   `qualia.decide` picks up the SLM transparently.

The engine still ships NO trainer in-tree; the actual GRPO script runs
on the operator's GPU host. The engine is the data factory + reward
designer + mutual-teacher transport.

### 6d. Phase 25 — closing the gaps from Phase 24
Four weak spots were called out at end of Phase 24 and shipped as Phase 25:

* **Autopilot v2 grows mid-loop.** `autopilot_loop._restage_from_discoveries`
  re-runs `modules.dispatch` against each iteration's newly-discovered
  services; new checks land on a synthetic `AUTOPILOT-V2-SYNTH` attack
  path. The loop is now a true growing agent, not a re-ranker.
* **SLM readiness is non-zero from day 1.** `mimir-slm seed` walks
  `docs/` + fixtures + evals and emits canonical `kind=seed:*`,
  `outcome=worked` rows. `mimir-slm export` includes them in the SFT
  corpus; `mimir-slm train --dry-run` can build DPO pairs without a
  single real engagement.
* **Crucible peer round-trip works end-to-end.** `tools/crucible_peer_mock.py`
  stands up the `/slm/peer-opinion` endpoint over the same HMAC bridge
  so `slm.bridge.query_peer` exercises the full path before the real
  Crucible endpoint deploys. Deterministic verdict heuristic; fully
  tested.
* **An actual DPO trainer ships.** `slm/train_dpo.py` + `mimir-slm train`
  (not just a recipe). Heavy deps are gated: the module imports fine
  without `torch`; `--dry-run` validates the pair dataset without a GPU;
  real training only requires `pip install torch transformers trl
  datasets peft accelerate bitsandbytes`.

The GRPO recipe in `slm.rl.recipe()` stays as the on-policy option. DPO
is the faster first step — offline, pair-based, uses the reward scores
we already compute.

### 6e. Phase 26 — AppSec in Autopilot v2
Autopilot v2 was designed around infra step shapes (host, port, service).
Phase 26 extends the observe-decide-run loop to AppSec:

* `parsers/httpx.py`, `parsers/subfinder.py`, `parsers/feroxbuster.py`
  (routed from `feroxbuster` / `gobuster` / `dirsearch` / `ffuf`), plus
  `parsers/subfinder.py` (routed from `subfinder` / `assetfinder` /
  `amass`) all produce `new_urls` + `new_subdomains` on the ParseResult.
* `autopilot_loop._observe_results` now tracks the AppSec surface
  alongside hosts/services/findings.
* `autopilot_loop._restage_from_discoveries` builds synthetic
  `{"kind":"web", "host":..., "ref":<url>}` app_targets from the new
  URLs and subdomains, then calls `modules.dispatch_apps` — the same
  entry point `assess.py` uses for `--web`/`--api`. Discovered subdomains
  spawn both `http://` and `https://` probes.
* All v2 gate chain safeguards (institutional TLD, ROE, noise ceiling,
  risk accept list, command safety) apply uniformly to infra + AppSec.

### 6f. Phase 27 — `mimir-slm promote`
The pin manager is the "ship it" moment for Phases 23–26: the first time
a trained Mimir SLM actually drives qualia decisions in live engagements.

* `slm/promote.py` reads/writes `~/.mimir/llm-pins.json` (override with
  `MIMIR_LLM_PINS=`).
* `llm.pick(role)` resolves in this order:
    1. env override (`MIMIR_LLM_MODEL` / `MIMIR_LLM_<ROLE>`) — temporary.
    2. **pin file** — operator-persistent (survives restarts).
    3. preference table.
    4. first local model that exists.
* Cloud guardrail (`_is_cloud` + `_ALLOW_CLOUD`) still applies to pins.
* CLI:
    `mimir-slm promote mimir-slm:20261123`           # planner + adviser
    `mimir-slm promote mimir-slm:20261123 --role all`  # all four roles
    `mimir-slm promote --show`                        # current pin map
    `mimir-slm promote --rollback --role planner`     # un-pin one role
    `mimir-slm promote --rollback`                    # clear the file

Flow: train with DPO/GRPO → tag the GGUF in Ollama → `mimir-slm promote`.
`qualia.decide` picks the SLM up on the next call. No code change needed.
