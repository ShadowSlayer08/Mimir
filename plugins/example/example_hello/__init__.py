"""example_hello — a minimal Mimir plugin.

Shows the stable third-party contract:
  * subclass `BaseModule`
  * declare typed parameters via `ModuleParams`
  * return a list of result dicts built with `module_result(...)`
  * NEVER execute a payload — the engine stages, the operator runs

Register in your plugin's pyproject under:

    [project.entry-points."mimir.modules"]
    example_hello = "example_hello:HelloModule"

Mimir's `sdk.discover()` picks it up on next launch.
"""
from __future__ import annotations

import dataclasses as _dc

# `mimir.sdk` is the stable surface. It ships with the mimir package.
from sdk import BaseModule, ModuleParams, module_result


@_dc.dataclass
class HelloParams(ModuleParams):
    """Typed parameters for the HelloModule. Values coerce automatically from
    the target dict — strings for `url`, ints for `timeout`."""
    url: str = ""
    timeout: int = 10


class HelloModule(BaseModule):
    """A trivial example — stage one methodology step against a URL target.

    This module demonstrates every required piece of the plugin contract:
      * class-level `name` + `title` + `params_type`
      * `assess_target(target, findings)` returning result dicts
      * `module_result(...)` to build the shape without importing engine
        internals
      * NO execution — the step is for the operator to run manually
    """

    name = "example.hello"
    title = "Example hello module"
    params_type = HelloParams

    def assess_target(self, target, findings):
        p = self.params(target)                                 # validated HelloParams
        host = p.url or target.get("ref", "")

        checks = [{
            "name": "Fingerprint via curl",
            "command": f"curl -sI --max-time {p.timeout} {host}",
            "purpose": "Grab server/response headers for triage.",
            "attack": "T1595.002",            # Active Scanning — Vuln scanning
            "owasp": "WSTG-INFO-02",
            "cwe": "CWE-200",
            "risk": "safe",                   # non-intrusive — pure recon
        }]
        return [module_result(
            self, host, service="example",
            summary=f"example.hello staging for {host}",
            severity="info",
            techniques=["T1595.002"],
            attack_surface=["Example plugin — illustrative only."],
            checks=checks)]
