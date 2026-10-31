#!/usr/bin/env python3
"""mimir.sdk.testharness — isolated test environment for a plugin module.

ARES-inspired `ModuleTestHarness`: lets a plugin author unit-test a module in
full isolation — mock ROE scope + synthetic vault + capture of stage events —
without needing the whole mimir engine running.

Typical use:

    from mimir.sdk import TestHarness
    from mypkg.hello import HelloModule

    def test_hello_runs_in_scope():
        with TestHarness(scope=["10.0.0.0/24"]) as h:
            results = h.run(HelloModule, {"kind": "example.hello",
                                          "ref": "10.0.0.5", "host": "10.0.0.5",
                                          "target": "x"})
        assert results and results[0]["checks"]
        assert h.staged_count >= 1
"""
from __future__ import annotations

import ipaddress
import os
import tempfile
from contextlib import contextmanager


class TestHarness:
    """Context-manager wrapper around a mock scope + synthetic vault.

    Fields after .run():
      * results      — the list of ModuleResult dicts the plugin returned
      * staged_count — total checks across all results
      * out_of_scope — list of (host, reason) tuples the mock scope rejected
    """

    def __init__(self, scope=None, vault_items=None):
        self.scope = list(scope or [])                          # list of CIDR / host
        self.vault_items = dict(vault_items or {})
        self.results = []
        self.staged_count = 0
        self.out_of_scope = []
        self._tmp_vault = None

    # ---- context manager ------------------------------------------------
    def __enter__(self):
        if self.vault_items:
            try:
                import vault
                fd, path = tempfile.mkstemp(suffix=".json", prefix="th-vault-")
                os.close(fd); os.unlink(path)                    # vault creates fresh
                self._pass = "test-harness-passphrase-xx"
                vault.init_vault(self._pass, path)
                for k, v in self.vault_items.items():
                    vault.set_item(k, v, self._pass, path)
                self._tmp_vault = path
            except Exception:                                   # pragma: no cover
                self._tmp_vault = None
        return self

    def __exit__(self, *_exc):
        if self._tmp_vault and os.path.exists(self._tmp_vault):
            try:
                os.unlink(self._tmp_vault)
            except OSError:
                pass

    # ---- scope check ----------------------------------------------------
    def _in_scope(self, host):
        if not self.scope:
            return True
        if not host:
            return False
        host_l = host.lower().strip()
        for rule in self.scope:
            r = rule.lower().strip()
            try:
                net = ipaddress.ip_network(r, strict=False)
                try:
                    if ipaddress.ip_address(host_l) in net:
                        return True
                except ValueError:
                    pass
            except ValueError:
                pass
            if r.startswith(".") and host_l.endswith(r):
                return True
            if host_l == r:
                return True
        return False

    def vault_get(self, key):
        """Synthetic retrieval — never persisted, never crosses process boundary."""
        return self.vault_items.get(key)

    def vault_keys(self):
        return sorted(self.vault_items.keys())

    # ---- run the module -------------------------------------------------
    def run(self, module_or_cls, target, findings=None):
        """Instantiate the module (if a class), run assess_target, record results.
        Target.host is checked against the mock scope; if OOS, the module is NOT
        called and the harness records the rejection — same contract as roe.py."""
        try:
            mod = module_or_cls() if isinstance(module_or_cls, type) else module_or_cls
        except TypeError:
            mod = module_or_cls(None)                            # (docs_dir) signature
        host = (target or {}).get("host", "") or (target or {}).get("ref", "")
        if host.startswith(("http://", "https://")):
            host_probe = host.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        else:
            host_probe = host
        if host_probe and not self._in_scope(host_probe):
            self.out_of_scope.append((host_probe, "not_in_scope"))
            return []
        results = mod.assess_target(target or {}, findings or [])
        results = list(results or [])
        self.results.extend(results)
        for r in results:
            self.staged_count += len(r.get("checks") or [])
        return results

    def reset(self):
        self.results.clear()
        self.staged_count = 0
        self.out_of_scope.clear()


@contextmanager
def harness(scope=None, vault_items=None):
    """Convenience: `with harness(scope=...) as h: ...`."""
    with TestHarness(scope=scope, vault_items=vault_items) as h:
        yield h
