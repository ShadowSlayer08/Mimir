#!/usr/bin/env python3
"""modules.api — OWASP API Security Top 10 methodology (target-driven).

Authorized / lab / CTF use only.

Sibling of web_app for APIs (REST / GraphQL). Assesses an API TARGET (a base URL
or a spec), spec-driven where possible (OpenAPI/Swagger discovery, GraphQL
introspection). Each check carries its ATT&CK technique plus an OWASP API-Top-10
reference and a CWE, and a safe|intrusive risk tag (intrusive hidden in VAPT).
Methodology + STAGING only; the engine runs nothing. Tooling references the
WebHackersWeapons arsenal (see docs/appsec/arsenal.md).

Checks load from docs/appsec/api.md (`module: api`) when present, else the
built-in set below.
"""
from __future__ import annotations

import string

from .base import Check, ModuleResult, worst

_A = "always"
# (name, attack, owasp, cwe, risk, when, command, purpose)
BUILTIN_CHECKS = [
    ("Spec / schema discovery", "T1595", "API9:2023", "CWE-1059", "safe", _A,
     "curl -sk {url}/openapi.json; curl -sk {url}/swagger.json; curl -sk {url}/v3/api-docs",
     "Locate the OpenAPI/Swagger spec (drives everything else)."),
    ("Endpoint enumeration", "T1595.003", "API9:2023", "CWE-1059", "safe", _A,
     "kr scan {url} -w routes-large.kite -x 20",
     "Brute API routes when no spec is exposed (kiterunner)."),
    ("Improper inventory (old/undoc versions)", "T1595", "API9:2023", "CWE-1059", "safe", _A,
     "# probe /v1 /v2 /internal /docs /graphql; diff behaviour across versions",
     "Find deprecated/undocumented API versions and hosts."),
    ("GraphQL introspection", "T1595", "API8:2023", "CWE-16", "safe", _A,
     "# graphw00f {url}; then clairvoyance / InQL to dump the schema via introspection",
     "Fingerprint GraphQL and recover the schema if introspection is open."),
    ("Auth mechanism & JWT", "T1078", "API2:2023", "CWE-287", "safe", _A,
     "# identify auth (Bearer/JWT/API-key); test JWTs with jwt_tool (alg:none, weak/HS256 key)",
     "Review the auth scheme and token handling."),
    ("Broken authentication", "T1110.001", "API2:2023", "CWE-307", "intrusive", _A,
     "# authorized only: credential-stuff / rate-test the token endpoint",
     "Test the auth endpoints for weak/guessable credentials."),
    ("BOLA (object-level authz)", "T1190", "API1:2023", "CWE-639", "safe", _A,
     "# swap object IDs across two accounts (Burp Autorize) to reach other users' objects",
     "Test broken object-level authorization / IDOR."),
    ("BFLA (function-level authz)", "T1190", "API5:2023", "CWE-285", "safe", _A,
     "# call admin/privileged methods & routes as a low-priv token",
     "Test broken function-level authorization."),
    ("BOPLA / mass assignment", "T1190", "API3:2023", "CWE-915", "safe", _A,
     "# add unexpected properties (e.g. role=admin, isVerified=true) to requests",
     "Test object-property-level authz, mass assignment & excessive data exposure."),
    ("Unrestricted resource consumption", "T1499", "API4:2023", "CWE-770", "intrusive", _A,
     "# authorized only: test missing rate-limits / unbounded pagination / large payloads",
     "Test for resource-consumption / DoS controls (watch impact)."),
    ("Sensitive business flow abuse", "T1190", "API6:2023", "CWE-799", "safe", _A,
     "# script a sensitive flow (signup/checkout/reset) to test anti-automation",
     "Test unrestricted access to sensitive business flows."),
    ("SSRF (OOB)", "T1190", "API7:2023", "CWE-918", "safe", _A,
     "# inject interactsh OAST payloads into URL/webhook/import params; watch for callbacks",
     "Test server-side request forgery, incl. blind via out-of-band."),
    ("Injection", "T1190", "API8:2023", "CWE-89", "intrusive", _A,
     "# authorized only: sqlmap / NoSQLi against API parameters and JSON bodies",
     "Test SQL/NoSQL/command injection on API inputs."),
    ("Schema-based fuzzing", "T1595", "API8:2023", "CWE-20", "safe", _A,
     "schemathesis run {url}/openapi.json --checks all",
     "Property-test every operation against its schema (authorized)."),
    ("Security misconfiguration", "T1595.002", "API8:2023", "CWE-16", "safe", _A,
     "nuclei -u {url} -tags misconfig,api,exposure",
     "CORS, verbose errors, missing headers, debug endpoints."),
    ("Unsafe consumption of upstream APIs", "T1190", "API10:2023", "CWE-20", "safe", _A,
     "# review trust in third-party/upstream APIs and validation of their responses",
     "Test unsafe consumption of integrated APIs."),
]


class _SafeDict(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(s, ctx):
    return string.Formatter().vformat(s or "", (), _SafeDict(ctx))


class APIModule:
    name = "api"
    title = "API (OWASP API Top 10)"

    def __init__(self, docs_dir=None):
        try:
            from knowledge_loader import load_knowledge
            self._mdef = load_knowledge(docs_dir).modules.get("api")
        except Exception:                                              # pragma: no cover
            self._mdef = None

    def _checks(self):
        if self._mdef and self._mdef.get("checks"):
            return self._mdef["checks"]
        return [{"name": n, "attack": a, "owasp": o, "cwe": w, "risk": rk,
                 "when": wh, "command": cmd, "purpose": pp}
                for (n, a, o, w, rk, wh, cmd, pp) in BUILTIN_CHECKS]

    def assess_target(self, target, findings):
        tls = bool(target.get("tls"))
        ctx = {"url": target.get("ref", ""), "ip": target.get("ip") or target.get("host", ""),
               "host": target.get("host", ""), "port": target.get("port", 0),
               "scheme": target.get("scheme", "http"), "label": target.get("label", ""),
               "domain": target.get("host", "")}
        try:
            from config import PATHS as _PATHS
            ctx.update(_PATHS)
        except Exception:                 # pragma: no cover
            pass

        flags = {"always": True, "tls": tls, "not_tls": not tls}
        rel = [f for f in findings if f.get("port") == target.get("port")]
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

        surface = ["API endpoint - staged initial-access surface (T1190); broken "
                   "object/function authorization (BOLA/BFLA) is the top API risk."]
        if not tls:
            surface.append("Cleartext HTTP - API tokens and data exposed on-path.")

        return [ModuleResult(
            self.name, self.title, target.get("ref", ""), target.get("scheme", "http"),
            f"API at {target.get('ref', '')} (OWASP API Security Top 10).",
            worst(rel), techniques=sorted(techs), attack_surface=surface,
            checks=checks, findings=rel)]
