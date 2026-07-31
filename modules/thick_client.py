#!/usr/bin/env python3
"""modules.thick_client — desktop / thick-client binary methodology (target-driven).

Authorized / lab / CTF use only.

Assesses a THICK-CLIENT target (a desktop binary: .exe/.dll/.jar/native). There is
no single OWASP standard for desktop apps, so checks are **CWE-mapped** (owasp left
blank) but still carry an ATT&CK technique and a safe|intrusive risk tag.
Methodology + STAGING only; the engine runs nothing. Tooling: strings, dnSpy/ILSpy/
jadx, Ghidra, procmon, accesschk, mitmproxy, frida (see docs/appsec/arsenal.md).

Checks load from docs/appsec/thick.md (`module: thick`) when present, else the
built-in set below. Placeholders: {app} {host}.
"""
from __future__ import annotations

import string

from .base import Check, ModuleResult, worst

_A = "always"
# (name, attack, owasp, cwe, risk, when, command, purpose) — owasp blank (CWE-mapped)
BUILTIN_CHECKS = [
    ("Triage strings / imports", "T1592.002", "", "CWE-200", "safe", _A,
     "strings -n 8 {app}   # + review imports/sections (Detect It Easy, PE-bear)",
     "Fingerprint the binary, language/runtime and obvious secrets."),
    ("Decompile", "T1592.002", "", "CWE-656", "safe", _A,
     "# .NET: dnSpy/ILSpy {app} | Java: jadx {app} | native: Ghidra {app}",
     "Recover source/IL for logic and secret review."),
    ("Hardcoded secrets / config", "T1552.001", "", "CWE-798", "safe", _A,
     "# trufflehog filesystem . ; search binary + config for creds/keys/connection-strings",
     "Recover embedded credentials, keys and connection strings."),
    ("Insecure local storage", "T1005", "", "CWE-312", "safe", _A,
     "# inspect files + registry (HKCU/HKLM) for cleartext secrets; procmon to trace access",
     "Test for sensitive data stored in the clear locally."),
    ("IPC / named pipes / RPC", "T1559", "", "CWE-419", "safe", _A,
     "# enumerate named pipes / COM / RPC / local sockets; test authz on the IPC endpoints",
     "Test local IPC surface and its authorization."),
    ("DLL search-order hijack", "T1574.001", "", "CWE-427", "safe", _A,
     "# procmon for 'NAME NOT FOUND' on DLL loads -> plant a proxy DLL on the search path",
     "Test for DLL/library search-order hijacking."),
    ("Privilege & service config", "T1574.010", "", "CWE-276", "safe", _A,
     "# accesschk: service permissions, unquoted service paths, writable install dir",
     "Test for local privilege-escalation via weak config."),
    ("Update mechanism integrity", "T1195", "", "CWE-494", "intrusive", _A,
     "# authorized only: MITM the update channel - is it signed + TLS-pinned?",
     "Test update integrity (code-signing + transport)."),
    ("Traffic interception", "T1557", "", "CWE-319", "safe", _A,
     "# proxy the client through mitmproxy/Burp; review protocol, TLS validation, secrets on the wire",
     "Test client-server transport and trust."),
    ("Backend authorization (thick-client trust)", "T1078", "", "CWE-602", "safe", _A,
     "# replay/modify client->server calls via the proxy; test server-side authz "
     "(thick clients often over-trust the client)",
     "Test whether security decisions are enforced server-side."),
    ("Runtime secrets", "T1003", "", "CWE-316", "safe", _A,
     "# dump process memory for tokens/keys; frida to hook the running client (authorized)",
     "Recover secrets held in memory at runtime."),
]


class _SafeDict(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(s, ctx):
    return string.Formatter().vformat(s or "", (), _SafeDict(ctx))


class ThickClientModule:
    name = "thick"
    title = "Thick Client (Desktop Binary)"

    def __init__(self, docs_dir=None):
        try:
            from knowledge_loader import load_knowledge
            self._mdef = load_knowledge(docs_dir).modules.get("thick")
        except Exception:                                              # pragma: no cover
            self._mdef = None

    def _checks(self):
        if self._mdef and self._mdef.get("checks"):
            return self._mdef["checks"]
        return [{"name": n, "attack": a, "owasp": o, "cwe": w, "risk": rk,
                 "when": wh, "command": cmd, "purpose": pp}
                for (n, a, o, w, rk, wh, cmd, pp) in BUILTIN_CHECKS]

    def assess_target(self, target, findings):
        ctx = {"app": target.get("ref", ""), "host": target.get("host", ""),
               "label": target.get("label", "")}
        try:
            from config import PATHS as _PATHS
            ctx.update(_PATHS)
        except Exception:                 # pragma: no cover
            pass

        checks, techs = [], set()
        for c in self._checks():
            checks.append(Check(c["name"], _fmt(c["command"], ctx), c.get("purpose", ""),
                                c.get("attack", ""), c.get("owasp", ""), c.get("cwe", ""),
                                c.get("risk", "")).to_dict())
            if c.get("attack"):
                techs.add(c["attack"])

        surface = ["Thick-client binary - inspect local storage, IPC, update path and "
                   "the client->server trust boundary (secrets/logic often client-side)."]
        return [ModuleResult(
            self.name, self.title, target.get("ref", ""), "binary",
            f"Thick client {target.get('host', '')} (desktop binary review).",
            worst([]), techniques=sorted(techs), attack_surface=surface,
            checks=checks, findings=[])]
