#!/usr/bin/env python3
"""
build_exe.py — deprecated alias for build_app.py.

The build is now cross-platform (Windows .exe / Linux ELF / macOS .app) and lives
in build_app.py. This shim is kept so existing docs/commands keep working.

    python build_exe.py   ==   python build_app.py
"""
from __future__ import annotations

import sys

from build_app import main

if __name__ == "__main__":
    sys.exit(main())
