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
modules and paths share one vocabulary.

## 5. Engineering conventions
- CLI-first; every capability runs headless (`--no-gui` / `--selftest`).
- Modular Python; GUI is PySide6 (Qt6).
- Cross-platform install: pip/pipx (`pip install .`) or a per-OS native binary
  (`python build_app.py`); no fixed install path.
- Keep built-in fallbacks working if the knowledge base is absent.
- Validate knowledge after edits (`python3 knowledge_loader.py`).
