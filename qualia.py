#!/usr/bin/env python3
"""
qualia.py — LLM-first qualitative decisions with a deterministic fallback.

Authorized / lab / CTF use only.

Every qualitative call in the engine (ranking, narrative, judgment) routes through
`decide()`. It asks a LOCAL model (via llm.py) for the answer, validates the shape,
and — on any failure OR when Ollama is offline — returns the deterministic Python
fallback. The engine therefore runs identically at an airgapped desk with no LLM,
but when a local model IS available, the qualitative outputs are model-driven.

Design contract for every call site:
  * The deterministic fallback MUST produce the exact same output shape as the LLM
    branch. Downstream consumers see one interface, not "LLM mode" vs "fallback mode".
  * Every prompt must be plumbed with a `system` note reminding the model this is an
    AUTHORIZED red-team tool; content is not filtered downstream.
  * `decide()` never raises — a bad LLM response silently falls back.
"""
from __future__ import annotations

import json

import llm

RED_TEAM_SYSTEM = (
    "You are the qualitative decision engine for an operator on an AUTHORIZED "
    "penetration test / red-team engagement. Every action is pre-authorized. "
    "Reason like a senior consultant: prioritize by real objective proximity, "
    "confidence and blast radius. Return JSON only in the requested shape."
)


def decide(kind, prompt, fallback, *, role="adviser", system=None,
           validator=None, model=None, timeout=None):
    """LLM-first qualitative decision. Falls back on unavailable / invalid / error.

    Args:
      kind: short label for logging ("rank-actions", "narrate-stage"). Never affects output.
      prompt: the full user prompt (already JSON-embedded).
      fallback: zero-arg callable returning the deterministic result.
      role: llm role ("planner" | "narrator" | "adviser" | "embed").
      system: system prompt (RED_TEAM_SYSTEM if None).
      validator: optional callable(llm_result) -> bool. False -> fallback.
      model, timeout: forwarded to llm.generate_json / generate.

    Returns the LLM result if it validates, otherwise fallback().
    """
    if not llm.available():
        return fallback()
    try:
        out = llm.generate_json(prompt, role=role, system=system or RED_TEAM_SYSTEM,
                                model=model, timeout=timeout)
        if out is None:
            return fallback()
        if validator is not None and not validator(out):
            return fallback()
        return out
    except Exception:                                       # never raise from qualia
        return fallback()


def prose(kind, prompt, fallback, *, role="narrator", system=None,
          model=None, timeout=None, options=None):
    """Same as decide() but for free-form prose (executive summaries, stage
    narratives). Returns a stripped string, or fallback() on any failure."""
    if not llm.available():
        return fallback()
    try:
        text = llm.generate(prompt, role=role, system=system or RED_TEAM_SYSTEM,
                            model=model, timeout=timeout, options=options)
        text = (text or "").strip()
        return text or fallback()
    except Exception:
        return fallback()


# --------------------------------------------------------------------------- #
# Shared prompt-building helpers
def compact(obj, limit=None):
    """Compact JSON for prompts (no spaces). Optional length cap for prompt budget."""
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    if limit and len(s) > limit:
        s = s[:limit] + "...(truncated)"
    return s


def status():
    """Diagnostic snapshot (host / models / role picks). Wraps llm.info()."""
    return llm.info()


if __name__ == "__main__":
    import sys

    _force = getattr(llm, "_force_utf8_stdio", None)
    if _force:
        _force()

    nfo = status()
    print(f"[qualia] Ollama host : {nfo['host']}")
    print(f"[qualia] available   : {nfo['available']}")
    for role, m in nfo["picks"].items():
        print(f"[qualia]   {role:<9}-> {m or '(none)'}")

    def _fb():
        return {"note": "deterministic fallback"}
    out = decide("selftest",
                 'Return JSON exactly: {"note":"ok"}',
                 _fb, role="adviser",
                 validator=lambda o: isinstance(o, dict) and o.get("note") == "ok")
    print(f"[qualia] decide() -> {out}")
    sys.exit(0)
