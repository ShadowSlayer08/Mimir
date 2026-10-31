#!/usr/bin/env python3
"""mimir.sdk.base — contract for third-party modules.

ARES-inspired `BaseModule[P, R]` + typed `ModuleParams`, implemented on stdlib
dataclasses to keep the engine dependency-light. A third-party module declares:

    from dataclasses import dataclass
    from mimir.sdk import BaseModule, ModuleParams, module_result

    @dataclass
    class HelloParams(ModuleParams):
        target: str = ""
        depth: int = 1

    class HelloModule(BaseModule):
        name  = "example.hello"
        title = "Example hello module"
        params_type = HelloParams

        def assess_target(self, target, findings):
            p = self.params(target)   # validated HelloParams
            return [module_result(
                self, target.get("ref", ""), service="hello",
                summary="Hello " + p.target,
                checks=[{"name": "say-hello", "command": "echo hi " + p.target,
                         "attack": "T1595", "owasp": "", "cwe": "", "risk": "safe",
                         "purpose": "Trivial example."}])]

    # entry_points section in pyproject.toml:
    #   [project.entry-points."mimir.modules"]
    #   example_hello = "mypkg:HelloModule"

The host (mimir) applies ROE / lessons / qualia / opsec on top; the operator
runs each staged step by hand. **No module ever executes a payload** — the SDK
has no `run()` method, only `assess_target(target, findings)`.
"""
from __future__ import annotations

import dataclasses as _dc
from typing import Any, Iterable, Mapping


SDK_VERSION = "1.0.0"
"""Stable SDK semver — bumps when the module contract changes incompatibly."""


# --------------------------------------------------------------------------- #
# Parameter base class — stdlib dataclass with simple runtime type coercion.
@_dc.dataclass
class ModuleParams:
    """Subclass + add fields with type hints + defaults.

    `from_target()` reads values from the engagement target dict with coercion
    (int / float / bool / str, list of str). Unknown fields on the target are
    ignored. Missing fields fall back to the dataclass default.
    """

    @classmethod
    def from_target(cls, target):
        """Build a validated params instance from a target dict."""
        target = target or {}
        kwargs = {}
        for f in _dc.fields(cls):
            if f.name not in target:
                continue
            val = target[f.name]
            try:
                kwargs[f.name] = _coerce(val, f.type)
            except (TypeError, ValueError):
                # On a bad value: fall back to the default (defensive; never raises).
                pass
        return cls(**kwargs)


def _coerce(val, type_hint):
    """Minimal stdlib-only coercion: handles int, float, bool, str, list[str]."""
    if val is None:
        return val
    name = getattr(type_hint, "__name__", str(type_hint)).lower()
    origin = str(type_hint).lower()
    if "list" in origin or "list" in name:
        if isinstance(val, (list, tuple)):
            return [str(x) for x in val]
        return [s.strip() for s in str(val).split(",") if s.strip()]
    if name == "bool":
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("1", "true", "yes", "on", "y")
    if name == "int":
        return int(val)
    if name == "float":
        return float(val)
    return str(val)


# --------------------------------------------------------------------------- #
# Convenience: build a ModuleResult-shaped dict from inside a plugin, so plugin
# authors don't need to import the private `modules.base.ModuleResult`.
def module_result(module, target, *, service="", summary="", severity="info",
                  techniques=(), attack_surface=(), checks=(), findings=()):
    """Return the dict shape dispatch_apps() will consume.

    Mirrors `modules.base.ModuleResult.to_dict()`. Plugins import ONLY this
    helper so they don't take a dependency on the engine internals.
    """
    name = getattr(module, "name", "") or module.__class__.__name__
    title = getattr(module, "title", "") or name
    return {
        "module": name, "title": title, "target": str(target or ""),
        "service": service, "summary": summary, "severity": severity,
        "techniques": list(techniques), "attack_surface": list(attack_surface),
        "checks": list(checks), "findings": list(findings),
    }


# --------------------------------------------------------------------------- #
class BaseModule:
    """Subclass to publish a module.

    Required class attributes:
      * `name`  — stable id (`example.hello`, use lowercase + dots for hierarchy)
      * `title` — human-readable one-liner
      * `params_type` (optional) — a ModuleParams subclass

    Required instance method:
      * `assess_target(target: dict, findings: list[dict]) -> list[dict]`
          returns a list of result dicts (use `module_result(...)` to build them).
          Called once per operator-supplied target of this module's kind.

    Lifecycle hooks (optional, called by the host if present):
      * `on_register(host)`      — the host just loaded the module.
      * `on_scope_change(roe)`   — the engagement's ROE changed.
    """

    name = ""
    title = ""
    params_type = ModuleParams
    sdk = SDK_VERSION

    def __init__(self, docs_dir=None):
        self.docs_dir = docs_dir

    def params(self, target):
        """Return a validated ModuleParams instance from `target`."""
        return self.params_type.from_target(target)

    def assess_target(self, target, findings):              # pragma: no cover (abstract)
        raise NotImplementedError("subclass BaseModule and implement assess_target()")


# --------------------------------------------------------------------------- #
# Entry-point group used by the host (if setuptools entry-points are discovered).
ENTRY_POINT_GROUP = "mimir.modules"


def discover(docs_dir=None):
    """Yield (name, module_instance) for every third-party module registered
    under the entry-point group. Never raises on a bad plugin — logs + skips.

    The host wires discovered modules into `dispatch_apps` under their `kind`
    (which must match target.kind the operator supplies). A module whose
    `kind` collides with a built-in is skipped (built-ins win)."""
    try:
        from importlib.metadata import entry_points
    except Exception:                                               # pragma: no cover
        return
    try:
        eps = entry_points().select(group=ENTRY_POINT_GROUP)        # py 3.10+
    except AttributeError:                                          # pragma: no cover
        eps = entry_points().get(ENTRY_POINT_GROUP, [])
    for ep in eps:
        try:
            cls = ep.load()
            inst = cls(docs_dir) if not isinstance(cls, BaseModule) else cls
            if not getattr(inst, "name", ""):
                continue
            yield inst.name, inst
        except Exception as exc:                                    # pragma: no cover
            print(f"[sdk] skipped plugin {ep.name}: {exc}")
