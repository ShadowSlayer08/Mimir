#!/usr/bin/env python3
"""modules.thick_client — desktop / thick-client binary methodology (target-driven).

Authorized / lab / CTF use only.

Assesses a THICK-CLIENT target (a desktop binary) across platforms: Windows
(.exe/.dll/.msi), Linux (ELF/.so) and macOS (.app/.dmg/.pkg, Mach-O). There is no
single OWASP standard for desktop apps, so checks are **CWE-mapped** (owasp blank)
but still carry an ATT&CK technique and a safe|intrusive risk tag. Platform-specific
checks are gated with `when: windows|linux|macos`; cross-platform ones are `always`.
Methodology + STAGING only; the engine runs nothing. Tooling: strings, dnSpy/ILSpy/
jadx, Ghidra, Hopper, otool/class-dump, procmon, accesschk, mitmproxy, frida.

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
     "# inspect files, registry (HKCU/HKLM on Windows) and app config for cleartext secrets; procmon/strace",
     "Test for sensitive data stored in the clear locally."),
    ("Traffic interception", "T1557", "", "CWE-319", "safe", _A,
     "# proxy the client through mitmproxy/Burp; review protocol, TLS validation, secrets on the wire",
     "Test client-server transport and trust."),
    ("Backend authorization (thick-client trust)", "T1078", "", "CWE-602", "safe", _A,
     "# replay/modify client->server calls via the proxy; test server-side authz "
     "(thick clients often over-trust the client)",
     "Test whether security decisions are enforced server-side."),
    ("Update mechanism integrity", "T1195", "", "CWE-494", "intrusive", _A,
     "# authorized only: MITM the update channel - is it signed + TLS-pinned?",
     "Test update integrity (code-signing + transport)."),
    ("Runtime secrets", "T1003", "", "CWE-316", "safe", _A,
     "# dump process memory for tokens/keys; frida to hook the running client (authorized)",
     "Recover secrets held in memory at runtime."),
    # --- Windows ---
    ("IPC / named pipes / RPC", "T1559", "", "CWE-419", "safe", "windows",
     "# enumerate named pipes / COM / RPC / local sockets; test authz on the IPC endpoints",
     "Test the local IPC surface and its authorization."),
    ("DLL search-order hijack", "T1574.001", "", "CWE-427", "safe", "windows",
     "# procmon for 'NAME NOT FOUND' on DLL loads -> plant a proxy DLL on the search path",
     "Test for DLL search-order hijacking."),
    ("Privilege & service config", "T1574.010", "", "CWE-276", "safe", "windows",
     "# accesschk: service permissions, unquoted service paths, writable install dir",
     "Test for local privilege-escalation via weak config."),
    # --- macOS ---
    ("macOS signing & notarization", "T1553.001", "", "CWE-347", "safe", "macos",
     "codesign -dv --verbose=4 {app}; spctl -a -vv {app}   # signature, notarization, Gatekeeper",
     "Assess code-signing, notarization and Gatekeeper."),
    ("macOS entitlements & TCC", "T1548", "", "CWE-250", "safe", "macos",
     "codesign -d --entitlements :- {app}   # entitlements, hardened runtime, TCC/privacy scope",
     "Review entitlements, hardened runtime and TCC exposure."),
    ("Mach-O analysis", "T1592.002", "", "CWE-656", "safe", "macos",
     "otool -L {app}; class-dump {app}   # + Hopper/Ghidra: dylibs, ObjC/Swift symbols",
     "Decompile the Mach-O binary and map dylibs."),
    ("Dylib hijack / injection", "T1574.004", "", "CWE-427", "safe", "macos",
     "# check @rpath/@loader_path dylib load order for hijack; DYLD_INSERT_LIBRARIES",
     "Test for dylib hijacking / injection."),
    ("macOS Keychain / local secrets", "T1555.001", "", "CWE-522", "safe", "macos",
     "# inspect Keychain items, plist/preferences and app-support files for cleartext secrets",
     "Test for secrets in the Keychain and local files."),
    # --- Linux ---
    ("ELF analysis & hardening", "T1592.002", "", "CWE-656", "safe", "linux",
     "file {app}; checksec --file={app}   # + Ghidra: RELRO/NX/PIE/canary, imports",
     "Decompile the ELF and check binary hardening."),
    ("SUID / capabilities / RPATH", "T1548.001", "", "CWE-732", "safe", "linux",
     "# check SUID/SGID, file capabilities (getcap), RPATH/RUNPATH for library hijack",
     "Test for local privilege-escalation via ELF permissions."),
    ("Linux local IPC", "T1559", "", "CWE-419", "safe", "linux",
     "# enumerate D-Bus / unix sockets; test authz on the local IPC endpoints",
     "Test the local IPC surface on Linux."),
]

_PLATFORMS = ("windows", "linux", "macos")


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
        platform = (target.get("platform") or "windows").lower()
        if platform not in _PLATFORMS:
            platform = "windows"
        ctx = {"app": target.get("ref", ""), "host": target.get("host", ""),
               "label": target.get("label", ""), "platform": platform}
        try:
            from config import PATHS as _PATHS
            ctx.update(_PATHS)
        except Exception:                 # pragma: no cover
            pass

        flags = {"always": True}
        for p in _PLATFORMS:
            flags[p] = (platform == p)
        checks, techs = [], set()
        for c in self._checks():
            when = c.get("when", "always") or "always"
            if not flags.get(when, when == "always"):
                continue
            checks.append(Check(c["name"], _fmt(c["command"], ctx), c.get("purpose", ""),
                                c.get("attack", ""), c.get("owasp", ""), c.get("cwe", ""),
                                c.get("risk", "")).to_dict())
            if c.get("attack"):
                techs.add(c["attack"])

        surface = [f"Thick-client binary ({platform}) - inspect local storage, IPC, update path "
                   "and the client->server trust boundary (secrets/logic often client-side)."]
        return [ModuleResult(
            self.name, self.title, target.get("ref", ""), platform,
            f"Thick client {target.get('host', '')} ({platform} binary review).",
            worst([]), techniques=sorted(techs), attack_surface=surface,
            checks=checks, findings=[])]
