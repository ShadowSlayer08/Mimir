# Pentest Engine

**Knowledge-driven pentest / red-team ORCHESTRATION engine** — authorized
engagements, lab, and CTF use **only**.

It plans and stages an engagement: **Recon → Enumeration → Findings → MITRE
ATT&CK attack-path _staging_ → report**.

**Boundary (non-negotiable — see `docs/instructions.md`)**: methodology and
staging only. The engine does **not** run exploits, generate payloads, or
operate C2. Every attack step is staged with its ATT&CK technique for a human
operator to execute **manually**, with their own tooling, inside an authorized,
scope-confirmed engagement.

See `docs/instructions.md` (the constitution), **CLAUDE.md** / **AGENTS.md**, and
`docs/developer_guide.md`.

## Install (Windows / Linux / macOS)

Python 3.11+. Install with pip/pipx, or build a native binary — both are
OS-independent.

```
# pip / pipx — works on any OS
pip install .[gui]          # GUI thick client + CLI   (or: pipx install ".[gui]")
pip install .               # headless CLI engine only

# native binary (no Python needed to run) — build on each target OS
python build_app.py         # -> dist/RedEngine.exe | dist/RedEngine | dist/RedEngine.app
```

Console scripts: **`redengine`** (GUI), **`redengine-cli`** (assess pipeline),
**`redengine-scan`** (inventory). Live scanning needs **nmap** on `PATH` (Windows
also needs Npcap); offline ingest works without it. See `docs/packaging.md` for
details and the optional read-only `flutter/` desktop viewer.

## Quickstart

```
redengine-cli --from-xml tests/fixtures/full_scan.xml --yes \
    --report engagement.html --emit-json engagement.json
redengine-cli --from-xml scan.xml --yes --web http://target/app   # AppSec: web-app OWASP-WSTG methodology
redengine                   # launch the GUI thick client
```

**AppSec pillar:** web apps are first-class, target-driven assessment objects.
Discovered http/https services are auto-promoted (and `--web URL` adds explicit
ones), then assessed with an OWASP **WSTG** methodology — each check tagged with
its ATT&CK technique plus an OWASP (WSTG) ref and a CWE. A web app is staged as a
**T1190** initial-access entry that chains into the host's onward paths.

## Risk enrichment & engagement ledger

```
# Live, current risk: CISA-KEV + FIRST-EPSS (public feeds only — no target is contacted),
# cached + offline-safe. --offline uses the cache only.
redengine-cli --from-xml scan.xml --yes --enrich

# Per-asset scoring: host -> {exposure, business} (level names or 0-1 floats)
redengine-cli --from-xml scan.xml --yes --enrich --assets assets.yaml

# Engagement ledger: re-runs accrete; see what changed and triage findings
redengine-cli --from-xml scan.xml --yes --ledger eng.db      # records the run
python ledger.py eng.db                                      # history + diff (new / fixed / muted)
python ledger.py eng.db triage <key> --status false_positive --owner you
```

Enrichment makes severity reflect what's **actually exploited in the wild** (EPSS
per finding = max over its CVEs; any KEV CVE forces critical). The ledger turns
repeat assessments into a **re-test diff** (new / fixed / still-open + grade
deltas) and lets you **triage** findings (false-positive / accepted findings are
muted from future diffs; a severity override is applied). Enrichment pulls public
vulnerability feeds only; the engine still contacts no target outside the scan.
