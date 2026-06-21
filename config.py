#!/usr/bin/env python3
"""
config.py — environment / portability config: wordlist & tool paths, per-OS
application directories, tool checks.

Authorized / lab / CTF use only.

Module command templates reference {seclists}/{wordlists}/{users}/{passwords}.
These resolve, in precedence order, from (1) REDENGINE_* env vars, (2) an
optional redengine.toml / redengine.json config file, (3) OS-aware defaults — so
the staged methodology is portable across Windows, Linux and macOS instead of
assuming a Kali layout. `missing_tools()` flags operator tools not on PATH.
`platform_dirs()` / `app_path()` give per-OS locations (%APPDATA% / $XDG_* /
~/Library) for the ledger, exports and an out-of-tree knowledge base.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

APP_NAME = "RedEngine"


# --------------------------------------------------------------------------- #
# Per-OS application directories
# --------------------------------------------------------------------------- #
def platform_dirs():
    """(config_dir, data_dir) for this OS. Honors APPDATA / LOCALAPPDATA / XDG_*."""
    home = Path.home()
    if sys.platform.startswith("win"):
        cfg = os.environ.get("APPDATA") or str(home / "AppData" / "Roaming")
        data = os.environ.get("LOCALAPPDATA") or str(home / "AppData" / "Local")
        return os.path.join(cfg, APP_NAME), os.path.join(data, APP_NAME)
    if sys.platform == "darwin":
        sup = str(home / "Library" / "Application Support" / APP_NAME)
        return sup, sup
    cfg = os.environ.get("XDG_CONFIG_HOME") or str(home / ".config")
    data = os.environ.get("XDG_DATA_HOME") or str(home / ".local" / "share")
    return os.path.join(cfg, "redengine"), os.path.join(data, "redengine")


CONFIG_DIR, DATA_DIR = platform_dirs()


def config_dir(create=False):
    if create:
        os.makedirs(CONFIG_DIR, exist_ok=True)
    return CONFIG_DIR


def data_dir(create=False):
    if create:
        os.makedirs(DATA_DIR, exist_ok=True)
    return DATA_DIR


def app_path(name, create_parent=False):
    """Absolute path under the per-OS data dir (ledger.db, exports, …)."""
    if create_parent:
        os.makedirs(DATA_DIR, exist_ok=True)
    return os.path.join(DATA_DIR, name)


# --------------------------------------------------------------------------- #
# Optional config file: redengine.toml | redengine.json holding {seclists: ...}
# or {"paths": {seclists: ...}}. Searched: REDENGINE_CONFIG, CWD, per-OS config.
# --------------------------------------------------------------------------- #
def _load_config_file():
    candidates = []
    env = os.environ.get("REDENGINE_CONFIG")
    if env:
        candidates.append(env)
    candidates += ["redengine.toml", "redengine.json",
                   os.path.join(CONFIG_DIR, "redengine.toml"),
                   os.path.join(CONFIG_DIR, "redengine.json")]
    for path in candidates:
        try:
            if not path or not os.path.isfile(path):
                continue
            if path.lower().endswith(".toml"):
                import tomllib                       # stdlib in Python 3.11+
                with open(path, "rb") as fh:
                    data = tomllib.load(fh)
            else:
                import json
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
            if isinstance(data, dict):
                paths = data.get("paths")
                return paths if isinstance(paths, dict) else data
        except Exception:
            continue
    return {}


_FILE = _load_config_file()


# --------------------------------------------------------------------------- #
# OS-aware default wordlist / tool locations. These are STAGED command TEXT
# (where the operator's box keeps wordlists), overridable per environment.
# --------------------------------------------------------------------------- #
def _os_default(subdir, kali_path):
    # Kali/Linux standard location when it actually exists; else a portable
    # home-dir path the operator can populate or override.
    if not sys.platform.startswith("win") and os.path.isdir(kali_path):
        return kali_path
    return str(Path.home() / ".redengine" / subdir)


def _resolve(key, env_key, default):
    # precedence: env var > config file > OS-aware default
    return os.environ.get(env_key) or _FILE.get(key) or default


SECLISTS = _resolve("seclists", "REDENGINE_SECLISTS", _os_default("seclists", "/usr/share/seclists"))
WORDLISTS = _resolve("wordlists", "REDENGINE_WORDLISTS", _os_default("wordlists", "/usr/share/wordlists"))
USERS = _resolve("users", "REDENGINE_USERS", "users.txt")
PASSWORDS = _resolve("passwords", "REDENGINE_PASSWORDS", "passwords.txt")

# template vars injected into module command rendering
PATHS = {"seclists": SECLISTS, "wordlists": WORDLISTS, "users": USERS, "passwords": PASSWORDS}


def missing_tools(tools):
    """Of the given tool names, return those not found on PATH (order-preserving, deduped)."""
    seen, out = set(), []
    for t in tools:
        if t and t not in seen:
            seen.add(t)
            if shutil.which(t) is None:
                out.append(t)
    return out
