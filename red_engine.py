#!/usr/bin/env python3
"""
red_engine.py - single entry point for the Pentest Engine thick client.

Authorized / lab / CTF use only.

This is the one app to launch (and the one the native binary is built from). It
opens the Attack Dashboard front door (target form + VAPT/Red Team mode), which
connects to the operations console where every op is done in-process: acquire/
scan, ingest an evidence folder, analyse, per-service methodology, ATT&CK
attack-path staging, and export report / Navigator layer / engagement ledger.

    python red_engine.py            # launch the GUI
    python red_engine.py scan.xml   # launch + preload a scan/target
    redengine                       # same, via the installed console script

The GUI needs the [gui] extra (PySide6):  pip install redengine[gui]
Build a standalone native binary:  python build_app.py   (see docs/packaging.md)
Note: live scanning still needs nmap on PATH; offline ingest/open-scan work without it.
"""
from __future__ import annotations

import sys


def main():
    """Console-script entry point (redengine). Launches the Attack Dashboard GUI.

    PySide6 is an optional extra, so import the GUI lazily and give a clear
    install hint instead of an opaque ImportError on a core-only install.
    """
    try:
        from attack_dashboard import main as _gui_main
    except ImportError as exc:
        sys.stderr.write(
            "RedEngine GUI requires PySide6. Install the GUI extra:\n"
            "    pip install redengine[gui]\n"
            f"(import error: {exc})\n"
        )
        return 2
    return _gui_main()


if __name__ == "__main__":
    sys.exit(main())
