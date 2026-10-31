#!/usr/bin/env python3
"""
llm.py — optional LOCAL LLM layer (Ollama) for the co-pilot.

Authorized / lab / CTF use only.

A thin, offline-safe client for a locally-running Ollama daemon. It powers the
Planner / Narrator / Adviser — features that PLAN, NARRATE and SUGGEST over data
the engine has already computed. The LLM never executes a step and never reaches
the target network: the engagement data stays on the operator's own machine.

SECURITY / PRIVACY (why local-only is the point):
  * Local only. Cloud-backed Ollama models (name ends ':cloud') are EXCLUDED from
    automatic selection so engagement data never leaves the box. Opt in with
    MIMIR_LLM_ALLOW_CLOUD=1 if you really mean to.
  * Optional. If Ollama is not running, every call degrades gracefully (returns
    None / []), and the engine behaves exactly as it did before.
  * Staging only. This is an authorized red-team tool: the model gives real operator
    tradecraft. The engine has no execution engine — callers stage, the human runs it.

No third-party dependency: talks to Ollama over stdlib urllib so this module is
importable even in a minimal install.

Config (environment):
  OLLAMA_HOST                base url            (default http://localhost:11434)
  MIMIR_LLM_MODEL        force one model for every role
  MIMIR_LLM_PLANNER      per-role model override
  MIMIR_LLM_NARRATOR     per-role model override
  MIMIR_LLM_ADVISER      per-role model override
  MIMIR_LLM_EMBED        per-role model override
  MIMIR_LLM_TIMEOUT      seconds per request (default 60)
  MIMIR_LLM_ALLOW_CLOUD  set to 1 to allow ':cloud' models (default off)
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

def _normalize_host(h):
    """Accept Ollama's scheme-less OLLAMA_HOST (e.g. 127.0.0.1:11434) too."""
    h = (h or "http://localhost:11434").strip().rstrip("/")
    if "://" not in h:
        h = "http://" + h
    return h


DEFAULT_HOST = _normalize_host(os.environ.get("OLLAMA_HOST"))
# If the operator sets MIMIR_LLM_TIMEOUT it wins for every role; otherwise we
# use role-aware defaults, because a 27B narrator on CPU/partial-GPU is minutes-slow
# while a 7B planner/adviser answers in seconds.
_ENV_TIMEOUT = os.environ.get("MIMIR_LLM_TIMEOUT", os.environ.get("VANTAGE_LLM_TIMEOUT", os.environ.get("MIMIR_LLM_TIMEOUT", os.environ.get("VANTAGE_LLM_TIMEOUT"))))
_ENV_TIMEOUT = float(_ENV_TIMEOUT) if (_ENV_TIMEOUT or "").strip() else None
_ROLE_TIMEOUT = {"narrator": 900.0, "planner": 300.0, "adviser": 180.0, "embed": 120.0}
_TIMEOUT = _ENV_TIMEOUT or 180.0                       # generic fallback (discovery calls)
_ALLOW_CLOUD = os.environ.get("MIMIR_LLM_ALLOW_CLOUD", os.environ.get("VANTAGE_LLM_ALLOW_CLOUD", os.environ.get("MIMIR_LLM_ALLOW_CLOUD", ""))) not in ("", "0", "false", "no")


def _role_timeout(role):
    return _ENV_TIMEOUT or _ROLE_TIMEOUT.get(role, 180.0)


def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                          # pragma: no cover
            pass


_force_utf8_stdio()

# role -> ordered list of model-name substrings we prefer, best first. Selection
# is by substring so it adapts to whatever the operator has pulled locally.
_PREF = {
    "planner":  ["qwen2.5", "qwen3", "llama3", "mistral", "gemma", "cybersec", "phi"],
    "narrator": ["cybersec", "hauhau", "qwen2.5", "gemma", "llama3", "mistral"],
    "adviser":  ["qwen2.5", "cybersec", "qwen3", "llama3", "gemma", "mistral"],
    "embed":    ["bge", "nomic", "embed", "minilm", "mxbai"],
}
_ENV_ROLE = {
    "planner":  "MIMIR_LLM_PLANNER",
    "narrator": "MIMIR_LLM_NARRATOR",
    "adviser":  "MIMIR_LLM_ADVISER",
    "embed":    "MIMIR_LLM_EMBED",
}


# --------------------------------------------------------------------------- #
# transport — every failure is swallowed so the engine stays offline-safe.
def _request(path, payload=None, method=None, timeout=None):
    url = DEFAULT_HOST + path
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    method = method or ("POST" if data is not None else "GET")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout or _TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
        return json.loads(body) if body else {}
    except (urllib.error.URLError, urllib.error.HTTPError, OSError,
            ValueError, TimeoutError):
        return None


def _is_cloud(name):
    return (name or "").strip().lower().endswith(":cloud")


# --------------------------------------------------------------------------- #
# discovery
def available():
    """True if a local Ollama daemon answers."""
    return _request("/api/tags", timeout=min(_TIMEOUT, 5)) is not None


def list_models():
    """All models Ollama reports (name + metadata)."""
    data = _request("/api/tags", timeout=min(_TIMEOUT, 8))
    if not data:
        return []
    return data.get("models", []) or []


def local_models():
    """Model names usable without egress (cloud models excluded unless allowed)."""
    names = [m.get("name", "") for m in list_models() if m.get("name")]
    if _ALLOW_CLOUD:
        return names
    return [n for n in names if not _is_cloud(n)]


def pick(role="planner"):
    """Choose the best locally-available model for a role (None if none/offline)."""
    forced = os.environ.get("MIMIR_LLM_MODEL", os.environ.get("VANTAGE_LLM_MODEL", os.environ.get("MIMIR_LLM_MODEL", os.environ.get("VANTAGE_LLM_MODEL")))) or os.environ.get(_ENV_ROLE.get(role, ""), "")
    if forced:
        if _is_cloud(forced) and not _ALLOW_CLOUD:
            return None                                    # refuse a cloud model by default
        return forced
    names = local_models()
    if not names:
        return None
    low = [(n, n.lower()) for n in names]
    for want in _PREF.get(role, _PREF["planner"]):
        for orig, lo in low:
            if want in lo:
                return orig
    return names[0]                                        # fall back to whatever exists


# --------------------------------------------------------------------------- #
# generation
def generate(prompt, role="planner", system=None, model=None, options=None,
             timeout=None):
    """One-shot completion. Returns the text, or None if unavailable/failed."""
    model = model or pick(role)
    if not model or not prompt:
        return None
    opts = {"temperature": 0.2, "num_ctx": 8192}
    if options:
        opts.update(options)
    payload = {"model": model, "prompt": prompt, "stream": False, "options": opts}
    if system:
        payload["system"] = system
    data = _request("/api/generate", payload, timeout=timeout or _role_timeout(role))
    if not data:
        return None
    text = (data.get("response") or "").strip()
    return text or None


def chat(messages, role="planner", model=None, options=None, timeout=None):
    """Multi-turn chat. `messages` = [{role, content}, ...]. Text or None."""
    model = model or pick(role)
    if not model or not messages:
        return None
    opts = {"temperature": 0.2, "num_ctx": 8192}
    if options:
        opts.update(options)
    payload = {"model": model, "messages": messages, "stream": False, "options": opts}
    data = _request("/api/chat", payload, timeout=timeout or _role_timeout(role))
    if not data:
        return None
    text = ((data.get("message") or {}).get("content") or "").strip()
    return text or None


def generate_json(prompt, role="planner", system=None, model=None, timeout=None):
    """Completion constrained to JSON (Ollama format=json). Parsed dict/list or None."""
    model = model or pick(role)
    if not model or not prompt:
        return None
    payload = {"model": model, "prompt": prompt, "stream": False, "format": "json",
               "options": {"temperature": 0.1, "num_ctx": 8192}}
    if system:
        payload["system"] = system
    data = _request("/api/generate", payload, timeout=timeout or _role_timeout(role))
    if not data:
        return None
    raw = (data.get("response") or "").strip()
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return None


def embed(texts, model=None, timeout=None):
    """Embed a list of strings with a local embedding model. list[list[float]] or None."""
    model = model or pick("embed")
    if not model or not texts:
        return None
    out = []
    for t in texts:
        data = _request("/api/embeddings", {"model": model, "prompt": t}, timeout=timeout)
        if not data or "embedding" not in data:
            return None
        out.append(data["embedding"])
    return out


# --------------------------------------------------------------------------- #
def info():
    """Snapshot of the local LLM setup — for diagnostics / selftest."""
    up = available()
    models = local_models() if up else []
    return {
        "host": DEFAULT_HOST,
        "available": up,
        "allow_cloud": _ALLOW_CLOUD,
        "models": models,
        "picks": {role: (pick(role) if up else None)
                  for role in ("planner", "narrator", "adviser", "embed")},
    }


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="llm.py",
                                 description="local Ollama LLM layer for the co-pilot "
                                             "(offline-safe; plan/narrate/suggest only)")
    ap.add_argument("--selftest", action="store_true",
                    help="print setup + a tiny generation if a model is present")
    ap.add_argument("--prompt", help="run a one-shot completion and print it")
    ap.add_argument("--role", default="planner",
                    choices=["planner", "narrator", "adviser", "embed"])
    args = ap.parse_args(argv)

    nfo = info()
    print(f"[llm] host        : {nfo['host']}")
    print(f"[llm] available   : {nfo['available']}")
    print(f"[llm] allow-cloud : {nfo['allow_cloud']}")
    print(f"[llm] local models: {', '.join(nfo['models']) or '(none)'}")
    for role, m in nfo["picks"].items():
        print(f"[llm]   {role:<9}-> {m or '(none)'}")

    if args.prompt:
        out = generate(args.prompt, role=args.role)
        print("\n" + (out or "(no response — is Ollama running with a model pulled?)"))
        return 0
    if args.selftest:
        if not nfo["available"]:
            print("\n[llm] Ollama not reachable — engine still runs; LLM features stay off.")
            return 0
        if not nfo["picks"]["planner"]:
            print("\n[llm] reachable, but no usable local model. Pull one, e.g. `ollama pull qwen2.5:7b`.")
            return 0
        out = generate("Reply with exactly: mimir-llm-ok", role="planner",
                       options={"temperature": 0})
        print("\n[llm] generation test:", out or "(no response)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
