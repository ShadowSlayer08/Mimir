"""mimir.sdk — contract for third-party modules.

Shipped surface (stable API across minor versions):
  * ModuleParams        — stdlib-dataclass base for typed module parameters
  * BaseModule          — subclass this to publish a module
  * TestHarness         — isolated unit-test environment: mock ROE scope + synthetic vault
  * registry entry-point group:   `mimir.modules`

Pattern adopted from ARES (Mafifrizi/ARES) and adapted to Mimir's staging-only
boundary: a module declares its parameter schema, returns ModuleResult(s), and
NEVER executes a payload. The host (mimir) applies ROE / lessons / qualia on
top; the operator runs each staged step by hand.
"""
from .base import BaseModule, ModuleParams, module_result, SDK_VERSION
from .testharness import TestHarness

__all__ = ["BaseModule", "ModuleParams", "module_result", "TestHarness", "SDK_VERSION"]
