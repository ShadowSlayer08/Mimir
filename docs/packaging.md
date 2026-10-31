# Packaging — cross-platform thick client

`mimir.py` is the single entry point for the GUI thick client (PySide6/Qt6,
which runs natively on **Windows, Linux and macOS**). The Attack Dashboard
(target form + VAPT/Red Team mode) connects to the operations console where
**every op runs in-process**: acquire/scan, ingest an evidence folder, analyse,
per-service methodology, ATT&CK attack-path staging, and export **report /
Navigator layer / runbook / kill-chain / engagement ledger**.

Two ways to ship it — pick either or both.

## 1. pip / pipx (OS-independent, needs Python 3.11+)

```
pip install .            # core CLI engine
pip install .[gui]       # + PySide6 thick client (the GUI)
pip install .[all]       # + operator toolkit (impacket, …) and rich CLI
# or, isolated per-app:
pipx install ".[gui]"
```

Installs three console scripts on every OS:

| command          | what it launches                                    |
|------------------|-----------------------------------------------------|
| `mimir`      | the PySide6 thick-client GUI (needs the `[gui]` extra) |
| `mimir-cli`  | the `assess.py` end-to-end CLI pipeline             |
| `mimir-scan` | the `nmap_analyzer` inventory analyzer             |

The `docs/` knowledge base ships as a data package and is resolved at runtime by
`knowledge_loader` (dev tree → frozen bundle → installed package via
`importlib.resources` → `MIMIR_DOCS` / per-OS config dir → built-in
fallbacks). `exploits/` and `tests/` are deliberately **not** shipped.

## 2. Native binary (PyInstaller, no Python needed to run it)

```
pip install pyinstaller         # or: pip install .[build]
python build_app.py             # or:  pyinstaller mimir.spec
```

One spec builds the right artifact for the OS you run it on:

| OS      | output                 |
|---------|------------------------|
| Windows | `dist/Mimir.exe`   |
| Linux   | `dist/Mimir` (ELF) |
| macOS   | `dist/Mimir.app`   |

**PyInstaller cannot cross-compile** — build on each target OS (or wire a CI
matrix: windows-latest / ubuntu-latest / macos-latest). The `docs/` tree is
bundled (loaded from `sys._MEIPASS`); the hidden-imports list auto-syncs with
`modules/`. UPX and an app icon are used only if present. `build_exe.py` remains
as a deprecated alias for `build_app.py`.

## 3. Flutter desktop viewer (optional, read-only)

`flutter/` is a separate, **read-only** desktop frontend (Dart/Flutter; runs on
Windows/Linux/macOS). It opens an engagement JSON exported by the engine and
displays the dashboard + attack paths, copying staged commands to the clipboard.
It **executes nothing**. Produce its input with:

```
mimir-cli --from-xml scan.xml --yes --emit-json engagement.json
```

See `flutter/README.md` for SDK setup and per-OS build steps.

## Runtime notes (all OSes)

- **nmap** is an external dependency — install it and keep it on `PATH` for live
  scanning (Windows also needs **Npcap**). Without nmap the app still works fully
  offline: **Open scan** / **Ingest folder** load existing nmap XML / `.nmap` /
  `.gnmap` / evidence.
- `-A` / `-O` (OS detection) need elevated privileges: **Administrator** on
  Windows, **root/sudo** on Linux/macOS — otherwise those steps are skipped with
  a warning.
- **Linux GUI:** Qt6 ≥6.5 needs `libxcb-cursor0`; headless/CI use `xvfb-run` plus
  the `--selftest` hooks.
- Containerized enumeration (`--run-containers`) uses `--network=host` on Linux
  and falls back to `bridge` on Windows/macOS (Docker Desktop / Podman machine
  don't support host networking).
- Wordlist/tool paths default to a Kali layout on Linux and to `~/.mimir/<…>`
  elsewhere; override with `MIMIR_SECLISTS` / `MIMIR_WORDLISTS` or a
  `mimir.toml` (see `config.py`).
- First launch of a onefile native build self-extracts to a temp dir (slightly
  slow); switch the spec to `--onedir` if you prefer faster startup.

## What ships in the GUI binary
`mimir.py` → `attack_dashboard` → `pentest_console.Console`, pulling in
`assess`, `profiles`, `evidence`, `reporting`, `ledger`, `killchain`,
`device_profile`, `abuse`, `containers`, `modules/*`, `nmap_analyzer`,
`attack_path_engine`, `knowledge_loader`, `ciphers`, plus the `docs/` data tree.
