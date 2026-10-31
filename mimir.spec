# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the Mimir pentest-engine thick client.
#
# Cross-platform from ONE spec — run it on the TARGET OS (PyInstaller cannot
# cross-compile):
#     Windows -> dist/Mimir.exe
#     Linux   -> dist/Mimir        (ELF)
#     macOS   -> dist/Mimir.app    (bundle)
#
# Build:  python build_app.py          (or: pyinstaller mimir.spec)
# docs/ is bundled so the knowledge base loads from sys._MEIPASS at runtime.

import os
import sys
import glob
import shutil

block_cipher = None

# Auto-collect every per-service module so lazy imports resolve in the frozen
# app (kept in sync with modules/ automatically — no manual list to drift).
_modules_hidden = [
    "modules." + os.path.splitext(os.path.basename(f))[0]
    for f in glob.glob(os.path.join("modules", "*.py"))
    if not os.path.basename(f).startswith("__")
]
_engine_hidden = [
    "modules", "nmap_analyzer", "attack_path_engine", "knowledge_loader",
    "profiles", "evidence", "reporting", "ledger", "assess", "ciphers",
    "ciphers_v4", "killchain", "device_profile", "abuse", "containers",
    "config", "findings", "pentest_console", "attack_dashboard", "validate_kb",
]
hiddenimports = _engine_hidden + _modules_hidden

# Optional app icon, only if one is present in the repo root.
_icon = None
for _cand in ("Mimir.ico", "Mimir.icns", "mimir.ico", "mimir.icns"):
    if os.path.exists(_cand):
        _icon = _cand
        break

# UPX shrinks the binary; skip if not installed, and on macOS where it can break
# code-signing / the bundle.
_use_upx = shutil.which("upx") is not None and sys.platform != "darwin"

a = Analysis(
    ['mimir.py'],
    pathex=[],
    binaries=[],
    datas=[('docs', 'docs')],          # ship the whole knowledge base
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'PyQt5', 'PyQt6'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [],
    name='Mimir',                  # -> Mimir.exe on Windows, Mimir elsewhere
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=_use_upx,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,                     # windowed GUI app (no console window)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=_icon,
)

# macOS: wrap the onefile binary in a .app bundle so it launches like a native app.
if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='Mimir.app',
        icon=_icon,
        bundle_identifier='com.mimir.thickclient',
    )
