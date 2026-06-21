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
redengine                   # launch the GUI thick client
```
