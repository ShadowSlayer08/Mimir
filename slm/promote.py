"""slm.promote — persistent LLM role pins (Phase 27).

The "ship it" moment for the Mimir SLM pipeline. After an operator trains
a model (via `slm.train_dpo`, or the documented GRPO recipe, or anything
else) and tags it in Ollama as e.g. `mimir-slm:20261123`, this module
PINS that tag to one or more `llm.py` roles so every `qualia.decide` call
routes to the SLM from then on, across restarts.

File: `~/.mimir/llm-pins.json`, schema:
    {
      "planner":  "mimir-slm:20261123",
      "adviser":  "mimir-slm:20261123",
      "narrator": "hauhaucs-cybersec-27b",
      "embed":    "bge-m3"
    }

Resolution order in `llm.pick(role)`:
  1. MIMIR_LLM_MODEL / MIMIR_LLM_<ROLE>  (env override — temporary, wins)
  2. ~/.mimir/llm-pins.json              (operator-persistent — Phase 27)
  3. preference-order match over local_models()
  4. first local model that exists

The pin file is operator-controlled. `mimir-slm promote` writes it,
`--rollback` clears a role (or the whole file), `--show` prints it.
"""
from __future__ import annotations

import json
import os


_ROLES = ("planner", "narrator", "adviser", "embed")


def _default_path():
    home = os.path.expanduser("~")
    return os.path.join(home, ".mimir", "llm-pins.json")


def _pins_path():
    return (os.environ.get("MIMIR_LLM_PINS")
            or os.environ.get("VANTAGE_LLM_PINS")
            or _default_path())


def load_pins(path=None):
    """Return the pin map ({} if the file is missing or malformed)."""
    p = path or _pins_path()
    if not os.path.exists(p):
        return {}
    try:
        with open(p, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {}
        # Keep only known roles; strip anything else silently.
        return {k: str(v) for k, v in data.items()
                if k in _ROLES and isinstance(v, str) and v.strip()}
    except (OSError, json.JSONDecodeError):
        return {}


def save_pins(pins, path=None):
    """Write the pin map atomically. Creates parent dir if missing."""
    p = path or _pins_path()
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    tmp = p + ".tmp"
    pruned = {k: str(v) for k, v in (pins or {}).items()
              if k in _ROLES and isinstance(v, str) and v.strip()}
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(pruned, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, p)
    return pruned


def pin_for(role, path=None):
    """Return the pinned tag for `role`, or None. Used by llm.pick()."""
    pins = load_pins(path=path)
    return pins.get(role) or None


def promote(tag, roles=None, path=None):
    """Pin `tag` for the listed roles (default: planner + adviser, since
    those are the decision-heavy roles the SLM targets). Returns the full
    post-write pin map."""
    if not tag or not isinstance(tag, str) or not tag.strip():
        raise ValueError("tag must be a non-empty string")
    roles = tuple(roles) if roles else ("planner", "adviser")
    for r in roles:
        if r not in _ROLES:
            raise ValueError(f"unknown role {r!r}; must be in {_ROLES}")
    pins = load_pins(path=path)
    for r in roles:
        pins[r] = tag
    return save_pins(pins, path=path)


def rollback(role=None, path=None):
    """Remove a single role's pin, or (role=None) clear the whole file.
    Returns the post-rollback pin map."""
    p = path or _pins_path()
    if role is None:
        if os.path.exists(p):
            try:
                os.unlink(p)
            except OSError:                                        # pragma: no cover
                pass
        return {}
    if role not in _ROLES:
        raise ValueError(f"unknown role {role!r}; must be in {_ROLES}")
    pins = load_pins(path=path)
    pins.pop(role, None)
    return save_pins(pins, path=path)


def show(path=None):
    """Return a stable, printable snapshot."""
    pins = load_pins(path=path)
    return {"path": path or _pins_path(),
            "present": os.path.exists(path or _pins_path()),
            "pins": pins}
