#!/usr/bin/env python3
"""
build_app.py — build the standalone Mimir thick-client binary with PyInstaller.

Cross-platform: produces the right native artifact for the OS you run it on, from
the single mimir.spec —
    Windows -> dist/Mimir.exe
    Linux   -> dist/Mimir        (ELF)
    macOS   -> dist/Mimir.app    (bundle)

PyInstaller CANNOT cross-compile: run this once on each target OS (or wire a CI
build matrix — windows-latest / ubuntu-latest / macos-latest). docs/ knowledge
base is bundled; live scanning still needs nmap on PATH at runtime, while offline
ingest / open-scan work without it. See docs/packaging.md.

    pip install pyinstaller        # or: pip install mimir[build]
    python build_app.py
"""
from __future__ import annotations

import os
import subprocess
import sys


def _artifact():
    if sys.platform.startswith("win"):
        return os.path.join("dist", "Mimir.exe")
    if sys.platform == "darwin":
        return os.path.join("dist", "Mimir.app")
    return os.path.join("dist", "Mimir")


def main():
    try:
        import PyInstaller  # noqa: F401
    except Exception:
        print("PyInstaller not installed. Run:  pip install pyinstaller  (or pip install mimir[build])")
        return 1
    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "mimir.spec"]
    print("$ " + " ".join(cmd))
    rc = subprocess.run(cmd).returncode
    if rc == 0:
        print(f"\n[+] Built {_artifact()}")
        print("    PyInstaller does not cross-compile - build on each target OS "
              "(or via a CI matrix).")
    return rc


if __name__ == "__main__":
    sys.exit(main())
