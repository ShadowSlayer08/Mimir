#!/usr/bin/env python3
"""modules.mobile — OWASP MASVS/MASTG mobile-app methodology (target-driven).

Authorized / lab / CTF use only.

Assesses a MOBILE APP target (an APK/IPA file), OWASP **MASVS**-structured. Each
check carries its ATT&CK technique plus a MASVS reference and a CWE, and a
safe|intrusive risk tag (intrusive dynamic instrumentation is hidden in VAPT).
Methodology + STAGING only; the engine runs nothing. Tooling: apktool, jadx,
MobSF/mobsfscan, frida, objection, trufflehog (see docs/appsec/arsenal.md).

Checks load from docs/appsec/mobile.md (`module: mobile`) when present, else the
built-in set below. Placeholders: {app} {host} {platform}.
"""
from __future__ import annotations

import string

from .base import Check, ModuleResult, worst

_A = "always"
# (name, attack, owasp, cwe, risk, when, command, purpose)
BUILTIN_CHECKS = [
    ("Unpack / decompile", "T1592.002", "MASVS-CODE-1", "CWE-656", "safe", _A,
     "# android: apktool d {app} -o out/ && jadx -d src/ {app}   |  ios: unzip {app}",
     "Unpack the app and decompile to source for review."),
    ("Static MASVS scan", "T1595.002", "MASVS-CODE-2", "CWE-1395", "safe", _A,
     "# MobSF: upload {app} for static analysis  (or: mobsfscan out/)",
     "Run an automated MASVS static analysis pass."),
    ("Hardcoded secrets", "T1552.001", "MASVS-STORAGE-2", "CWE-798", "safe", _A,
     "# trufflehog filesystem out/ ; grep decompiled src for keys/tokens/URLs",
     "Recover API keys, tokens and endpoints baked into the app."),
    ("Manifest / exported components", "T1592.002", "MASVS-PLATFORM-1", "CWE-926", "safe", _A,
     "# review AndroidManifest.xml: exported activities/services/receivers/providers, "
     "permissions, debuggable, allowBackup (Info.plist / entitlements on iOS)",
     "Enumerate the app's attack surface and dangerous flags."),
    ("Insecure data storage", "T1005", "MASVS-STORAGE-1", "CWE-312", "safe", _A,
     "# inspect shared_prefs / sqlite / files / Keychain for cleartext PII or credentials",
     "Test for sensitive data stored in the clear."),
    ("Cryptography", "T1600", "MASVS-CRYPTO-1", "CWE-327", "safe", _A,
     "# review crypto use: hardcoded keys, ECB, weak/deprecated algorithms, static IVs",
     "Test for weak or misused cryptography."),
    ("Network security / TLS pinning", "T1557", "MASVS-NETWORK-1", "CWE-295", "safe", _A,
     "# check cleartext traffic (usesCleartextTraffic/ATS), cert & hostname validation, pinning",
     "Test transport security and certificate validation."),
    ("Authentication & session", "T1078", "MASVS-AUTH-1", "CWE-287", "safe", _A,
     "# review auth flows, token storage, and local/biometric-auth bypass",
     "Test authentication and session handling."),
    ("Platform interaction / IPC", "T1190", "MASVS-PLATFORM-2", "CWE-927", "safe", _A,
     "# test exported components, deep links, and WebView (JS bridge / file access)",
     "Test IPC, deep links and WebView exposure."),
    ("Anti-tamper / RASP", "T1622", "MASVS-RESILIENCE-1", "CWE-693", "safe", _A,
     "# assess root/jailbreak detection, debugger/emulator checks, obfuscation",
     "Review resilience controls (informational for most engagements)."),
    ("Dynamic instrumentation", "T1055", "MASVS-RESILIENCE-2", "CWE-489", "intrusive", _A,
     "# authorized only: frida/objection to hook runtime, bypass pinning/root, dump secrets",
     "Run-time analysis: hook, bypass controls, dump secrets (on a test device)."),
    ("Backend API surface", "T1590", "MASVS-NETWORK-2", "CWE-200", "safe", _A,
     "# extract the API endpoints/keys the app uses, then assess them with:  assess --api <url>",
     "Pivot to the app's backend API (feeds the api module)."),
]


class _SafeDict(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(s, ctx):
    return string.Formatter().vformat(s or "", (), _SafeDict(ctx))


class MobileModule:
    name = "mobile"
    title = "Mobile App (OWASP MASVS)"

    def __init__(self, docs_dir=None):
        try:
            from knowledge_loader import load_knowledge
            self._mdef = load_knowledge(docs_dir).modules.get("mobile")
        except Exception:                                              # pragma: no cover
            self._mdef = None

    def _checks(self):
        if self._mdef and self._mdef.get("checks"):
            return self._mdef["checks"]
        return [{"name": n, "attack": a, "owasp": o, "cwe": w, "risk": rk,
                 "when": wh, "command": cmd, "purpose": pp}
                for (n, a, o, w, rk, wh, cmd, pp) in BUILTIN_CHECKS]

    def assess_target(self, target, findings):
        platform = target.get("platform", "android")
        ctx = {"app": target.get("ref", ""), "host": target.get("host", ""),
               "platform": platform, "label": target.get("label", "")}
        try:
            from config import PATHS as _PATHS
            ctx.update(_PATHS)
        except Exception:                 # pragma: no cover
            pass

        flags = {"always": True, "android": platform == "android", "ios": platform == "ios"}
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

        surface = [f"Mobile app ({platform}) - client-side + backend attack surface; "
                   "secrets/endpoints recovered here feed the API/infra assessment."]
        return [ModuleResult(
            self.name, self.title, target.get("ref", ""), platform,
            f"Mobile app {target.get('host', '')} (OWASP MASVS methodology).",
            worst([]), techniques=sorted(techs), attack_surface=surface,
            checks=checks, findings=[])]
