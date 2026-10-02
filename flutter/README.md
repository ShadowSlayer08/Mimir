# vantage viewer (Flutter desktop)

A **read-only** desktop frontend for the vantage pentest orchestration engine.

> **Authorized / lab / CTF use only.** This app **executes nothing** — no scans,
> no exploits, no tooling. It **displays** an exported engagement and **copies**
> staged operator commands to the clipboard. The Python engine performs the
> scope-gated, detection-only nmap scanning; a **human operator** runs each
> staged command manually, in authorized scope, with their own tooling. This is
> methodology + staging only (see `docs/instructions.md` — the constitution).

There is intentionally no process-execution code path in this app: the only
side effect it has is writing a command string to the system clipboard.

## Where this fits

`vantage` (the PySide6 thick client) and `vantage-cli` (`assess.py`) are the
operator's working tools — they hold the network position and shell out to nmap.
This Flutter app is a **portable viewer** for the engagement they produce: open
it anywhere (a teammate's laptop, a reporting box) to review hosts, findings,
ATT&CK attack paths and the kill-chain, and to copy staged commands. It never
talks to the network.

## The bridge: a JSON contract

The app renders a single JSON document — the **engagement contract** — produced
by the engine:

```
vantage-cli <target | --from-xml scan.xml | --from-dir evidence/> --yes \
    --emit-json engagement.json
```

(`vantage-cli` is the installed console script for `assess.py`. The engine
runs the scope gate + detection-only scan + analysis + staging and writes the
contract.) Then, in the app: **Open engagement JSON** and pick `engagement.json`.
You can also open any previously exported engagement file offline. The app never
invokes the CLI itself.

Top-level shape: `meta`, `hosts[]`, `findings[]`, `attack_paths[]`,
`killchain.stages[]`. Each attack-path step carries `technique_id`, `technique`,
`command` (the ready, staged command) and `abuse { impact, how, opsec }`.

## What you see

- **Dashboard** — severity metric cards (critical/high/medium/low/info), a hosts
  table with **device class** + letter **grade** + OS + port/finding counts, and
  a kill-chain coverage summary.
- **Attack paths** — one scenario card per staged path; each step shows its
  ATT&CK technique, abuse insight, and a **Copy command** button. Copy it and
  run it yourself, in scope.

## Prerequisites

- Flutter SDK 3.27+ (`flutter --version`).
- Desktop toolchain for your OS:
  - **Windows:** Visual Studio with the "Desktop development with C++" workload.
  - **Linux:** `clang cmake ninja-build pkg-config libgtk-3-dev liblzma-dev`.
  - **macOS:** Xcode + CocoaPods.

## Enable desktop support (run once per platform)

```
flutter config --enable-windows-desktop
flutter config --enable-linux-desktop
flutter config --enable-macos-desktop
```

Verify the target shows up:

```
flutter devices
```

## First-time project setup

This folder contains `pubspec.yaml` and `lib/main.dart`. Generate the native
desktop runner directories (`windows/`, `linux/`, `macos/`) once:

```
cd flutter
flutter create --platforms=windows,linux,macos .
flutter pub get
```

(`flutter create .` in an existing directory adds the platform scaffolding
without overwriting `lib/main.dart` or `pubspec.yaml`.)

## Run (debug)

```
flutter run -d windows
flutter run -d linux
flutter run -d macos
```

## Build (release)

```
flutter build windows --release   # -> build/windows/x64/runner/Release/
flutter build linux   --release   # -> build/linux/x64/release/bundle/
flutter build macos   --release   # -> build/macos/Build/Products/Release/*.app
```

Notes:
- macOS distribution requires code-signing with an Apple Developer ID; an
  unsigned `.app` runs locally for testing.
- Linux release bundles depend on GTK3 at runtime; `file_picker` uses the native
  dialog (zenity/kdialog) on some distros.

## Boundary reminder

If you ever extend this app to invoke `vantage-cli` directly, it must only
ever call it with `--emit-json` (the engine keeps its own scope gate). Never let
the frontend call `nmap` or any tooling, and never add an exploit runner — that
would violate the project constitution (`docs/instructions.md`).
