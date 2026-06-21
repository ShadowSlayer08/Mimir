#!/usr/bin/env python3
"""
knowledge_loader.py - load the platform knowledge base from the docs/ tree.

Authorized / lab / CTF use only.

The engine is knowledge-driven: routing, NSE/tool mappings, risk config and the
per-module methodology live in the Markdown docs as fenced yaml blocks. This
loader extracts and merges them. Edit a doc, change the engine - no code change.

Docs resolution (first existing wins):
  1. REDENGINE_DOCS         - explicit operator override (absolute path).
  2. dev / source checkout  - docs/ sitting next to this file.
  3. frozen (PyInstaller)   - sys._MEIPASS/docs inside the onefile bundle.
  4. pip / pipx install     - importlib.resources.files('docs') (docs is a
                              shipped data package; see pyproject.toml).
  5. per-OS user config dir - APPDATA/redengine/docs, ~/Library/Application
                              Support/redengine/docs, or XDG_CONFIG_HOME (or
                              ~/.config)/redengine/docs - out-of-tree drop-in.
If none resolve, DEFAULT_DOCS is None and the dispatcher falls back to its
built-in module methodology (the engine still runs without docs/).
"""
from __future__ import annotations

import glob
import os
import re
import sys

import yaml

_YAML_BLOCK = re.compile(r"```ya?ml\s*\n(.*?)```", re.DOTALL)


def _is_docs_dir(path):
    """A usable docs dir exists and holds at least one .md knowledge file."""
    try:
        if not path or not os.path.isdir(path):
            return False
        return bool(glob.glob(os.path.join(path, "**", "*.md"), recursive=True))
    except Exception:
        return False


def _user_config_docs():
    """Per-OS user config location for an out-of-tree KB: <config>/redengine/docs."""
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "redengine", "docs")


def _safe_exit(cm):
    try:
        cm.__exit__(None, None, None)
    except Exception:
        pass


def _resource_docs():
    """Resolve the docs/ data package shipped in a pip/pipx wheel.

    'docs' is declared as a data package in pyproject.toml, so on an installed
    wheel importlib.resources can locate it. Use the plain filesystem path when
    the install is unzipped (the common case); fall back to as_file extraction
    for a zipped distribution. Returns a real, existing directory or None.
    """
    try:
        from importlib.resources import files, as_file
        res = files("docs")
    except Exception:
        return None
    try:
        p = os.fspath(res)
        if _is_docs_dir(p):
            return p
    except Exception:
        pass
    try:
        import atexit
        cm = as_file(res)
        p = os.fspath(cm.__enter__())
        atexit.register(lambda: _safe_exit(cm))
        if _is_docs_dir(p):
            return p
    except Exception:
        return None
    return None


def _resolve_docs():
    env = os.environ.get("REDENGINE_DOCS")
    if env and _is_docs_dir(env):
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    cand = os.path.join(here, "docs")
    if _is_docs_dir(cand):
        return cand
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.executable)))
        cand = os.path.join(base, "docs")
        if _is_docs_dir(cand):
            return cand
    cand = _resource_docs()
    if cand:
        return cand
    cand = _user_config_docs()
    if _is_docs_dir(cand):
        return cand
    return None


DEFAULT_DOCS = _resolve_docs()
# Back-compat: some callers referenced _BASE (the dir the docs tree lives under).
_BASE = os.path.dirname(DEFAULT_DOCS) if DEFAULT_DOCS else os.path.dirname(os.path.abspath(__file__))


def _match(name, frag):
    name = (name or "").lower()
    return name == frag or name.startswith(frag) or frag in name


def _match_rank(name, frag):
    """0=no match, 1=substring, 2=prefix, 3=exact. Used to pick the most
    specific fragment so e.g. 'tftp' resolves to the tftp entry, not 'ftp'."""
    name = (name or "").lower()
    if name == frag:
        return 3
    if name.startswith(frag):
        return 2
    if frag in name:
        return 1
    return 0


class Knowledge:
    def __init__(self, docs_dir=None):
        self.docs_dir = docs_dir or DEFAULT_DOCS
        self.registry = {}      # service-fragment -> [module names]
        self.nse = {}           # service-fragment -> [scripts]
        self.tools = {}         # service-fragment -> [tools]
        self.risk = {}          # risk config
        self.kill_chain = {}    # kill-chain stage model
        self.containers = {}    # container arsenal (images / runtime)
        self.abuse_info = {}    # ATT&CK technique -> exploitation insight
        self.modules = {}       # module name -> def dict
        self.sources = []       # files that contributed knowledge
        self._load()

    def _load(self):
        # No docs dir resolved (e.g. a bare pip install missing the KB): leave
        # the stores empty so available() is False and callers use fallbacks.
        if not self.docs_dir or not os.path.isdir(self.docs_dir):
            return
        for path in sorted(glob.glob(os.path.join(self.docs_dir, "**", "*.md"), recursive=True)):
            try:
                text = open(path, encoding="utf-8").read()
            except Exception:
                continue
            contributed = False
            for m in _YAML_BLOCK.finditer(text):
                try:
                    data = yaml.safe_load(m.group(1))
                except Exception:
                    continue
                if not isinstance(data, dict):
                    continue
                for key, store in (("registry", self.registry), ("nse", self.nse),
                                   ("tools", self.tools), ("risk", self.risk),
                                   ("kill_chain", self.kill_chain),
                                   ("containers", self.containers),
                                   ("abuse_info", self.abuse_info)):
                    if isinstance(data.get(key), dict):
                        store.update(data[key]); contributed = True
                if "module" in data:
                    self.modules[data["module"]] = data; contributed = True
            if contributed:
                self.sources.append(os.path.relpath(path, self.docs_dir))

    # -- queries ----------------------------------------------------------
    def available(self):
        return bool(self.modules and self.registry)

    def _lookup(self, table, svc):
        best, best_key = (None, None), (0, 0)
        for frag, val in table.items():
            r = _match_rank(svc, frag)
            if r and (r, len(frag)) > best_key:
                best_key, best = (r, len(frag)), (val, frag)
        return best if best[0] is not None else ([], None)

    def modules_for(self, svc):
        return self._lookup(self.registry, svc)[0]

    def nse_for(self, svc):
        return self._lookup(self.nse, svc)[0]

    def tools_for(self, svc):
        return self._lookup(self.tools, svc)[0]

    def summary(self):
        return (f"{len(self.modules)} modules, {len(self.registry)} routed services, "
                f"{len(self.nse)} NSE maps, {len(self.tools)} tool maps "
                f"from {len(self.sources)} doc(s)")


_CACHE = {}


def load_knowledge(docs_dir=None):
    key = docs_dir or DEFAULT_DOCS
    if key not in _CACHE:
        _CACHE[key] = Knowledge(docs_dir)
    return _CACHE[key]


if __name__ == "__main__":
    import sys
    kb = Knowledge(sys.argv[1] if len(sys.argv) > 1 else None)
    print("docs dir:", kb.docs_dir)
    print(kb.summary())
    print("sources:", ", ".join(kb.sources))
    print("modules:", ", ".join(kb.modules))
    print("registry sample:", dict(list(kb.registry.items())[:5]))
