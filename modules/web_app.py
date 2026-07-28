#!/usr/bin/env python3
"""modules.web_app — OWASP WSTG web-application methodology (target-driven).

Authorized / lab / CTF use only.

A target-driven AppSec module: it assesses a WEB APP (a URL), not a port. Checks
are OWASP WSTG-structured and carry OWASP + CWE refs alongside the ATT&CK id and a
safe|intrusive risk tag (intrusive is hidden in VAPT). Methodology + STAGING only:
it emits the steps a human operator runs with their own tooling, in scope.

Checks load from docs/appsec/web.md (`module: web_app`) when the knowledge base is
present; otherwise the built-in set below keeps the module working offline.
"""
from __future__ import annotations

import string

from .base import Check, ModuleResult, worst

# Built-in fallback methodology (mirrors docs/appsec/web.md). Tuple:
# (name, attack, owasp, cwe, risk, when, command, purpose)
_A = "always"
# Tooling references the WebHackersWeapons arsenal (github.com/hahwul/
# WebHackersWeapons) — see docs/appsec/arsenal.md. Staged for the operator; the
# engine runs nothing. Tuple: (name, attack, owasp, cwe, risk, when, command, purpose)
BUILTIN_CHECKS = [
    ("Fingerprint", "T1592.002", "WSTG-INFO-02", "CWE-200", "safe", _A,
     "whatweb {url}", "Identify server, framework, CMS and technologies."),
    ("Crawl / map", "T1595", "WSTG-INFO-01", "CWE-200", "safe", _A,
     "katana -u {url} -jc -silent", "Map endpoints, JS and the attack surface (katana)."),
    ("Passive URL gathering", "T1594", "WSTG-INFO-01", "CWE-200", "safe", _A,
     "gau {domain}", "Collect known URLs/params from archives (gau/waymore)."),
    ("Content discovery", "T1595.003", "WSTG-INFO-07", "CWE-538", "safe", _A,
     "feroxbuster -u {url} -k -w {seclists}/Discovery/Web-Content/raft-medium-directories.txt",
     "Enumerate hidden directories and files."),
    ("Parameter discovery", "T1595", "WSTG-INFO-07", "CWE-200", "safe", _A,
     "arjun -u {url}", "Mine hidden request parameters (arjun/paramspider) as injection points."),
    ("Robots / sitemap", "T1593", "WSTG-INFO-03", "CWE-200", "safe", _A,
     "curl -sk {url}/robots.txt", "Surface disallowed or listed paths."),
    ("JS secret mining", "T1552.001", "WSTG-INFO-05", "CWE-200", "safe", _A,
     "# harvest JS, then: SecretFinder -i <app.js> -o cli  (or trufflehog/gitleaks)",
     "Extract API keys/tokens/endpoints leaked in client-side JS."),
    ("Security headers", "T1595.002", "WSTG-CONF-12", "CWE-693", "safe", _A,
     "curl -skI {url}", "Check HSTS, CSP, X-Frame-Options and cookie flags."),
    ("HTTP methods", "T1595", "WSTG-CONF-06", "CWE-650", "safe", _A,
     "curl -skX OPTIONS {url} -i", "Detect risky verbs (PUT/DELETE/TRACE/WebDAV)."),
    ("Exposed VCS / config / backups", "T1213", "WSTG-CONF-04", "CWE-538", "safe", _A,
     "nuclei -u {url} -tags exposure,config,backup",
     "Find .git/.env/backups/admin consoles."),
    ("Template / known-CVE scan", "T1595.002", "WSTG-INFO-08", "CWE-1395", "safe", _A,
     "nuclei -u {url}", "Run known-CVE and misconfiguration templates."),
    ("TLS posture", "T1595", "WSTG-CRYP-01", "CWE-326", "safe", "tls",
     "sslscan {host}:{port}", "Enumerate protocols, ciphers and certificate issues."),
    ("Auth default/weak creds", "T1110.001", "WSTG-ATHN-02", "CWE-307", "intrusive", _A,
     "# authorized only: hydra -L {users} -P {passwords} {host} http-post-form '<path>:<body>:<fail>'",
     "Test the login for default/weak credentials (in scope)."),
    ("Session & JWT", "T1539", "WSTG-SESS-02", "CWE-614", "safe", _A,
     "# inspect Set-Cookie flags (Secure/HttpOnly/SameSite); test tokens with jwt_tool",
     "Review session-cookie flags and token handling."),
    ("Authorization / IDOR", "T1190", "WSTG-ATHZ-04", "CWE-639", "safe", _A,
     "# replay object refs across roles/users (Burp Autorize / autorize) to find IDOR/BOLA",
     "Test access control on object and function references."),
    ("SQL injection", "T1190", "WSTG-INPV-05", "CWE-89", "intrusive", _A,
     "# authorized only: sqlmap -u '{url}/?id=1' --batch --level 2   (alt: ghauri)",
     "Test parameters for SQL injection (sqlmap/ghauri)."),
    ("XSS", "T1059.007", "WSTG-INPV-01", "CWE-79", "safe", _A,
     "dalfox url {url}", "Test reflected/stored/DOM XSS on inputs and sinks (dalfox)."),
    ("SSTI", "T1190", "WSTG-INPV-18", "CWE-1336", "safe", _A,
     "# probe template injection with polyglot payloads on server-rendered inputs (tplmap)",
     "Test for server-side template injection."),
    ("SSRF (OOB)", "T1190", "WSTG-INPV-19", "CWE-918", "safe", _A,
     "# inject interactsh OAST payloads into URL/host params; watch interactsh-client "
     "for callbacks (SSRFmap for exploitation)",
     "Test for server-side request forgery, incl. blind via out-of-band."),
    ("Command injection", "T1190", "WSTG-INPV-12", "CWE-78", "intrusive", _A,
     "# authorized only: commix -u '{url}?p=1' --batch",
     "Test for OS command injection (commix)."),
    ("Deserialization / XXE / upload", "T1190", "WSTG-INPV-13", "CWE-502", "safe", _A,
     "# test insecure deserialization, XXE and unrestricted file upload",
     "Test object/XML/upload handling."),
    ("CRLF / open redirect", "T1595", "WSTG-CLNT-04", "CWE-601", "safe", _A,
     "# test CRLF injection and open redirect on redirect/next params (crlfuzz, oralyzer)",
     "Test header/response splitting and unvalidated redirects."),
    ("Business logic", "T1190", "WSTG-BUSL-01", "CWE-840", "safe", _A,
     "# test workflow, rate-limit and price/quantity-tampering abuse",
     "Test business-logic and anti-automation controls."),
    ("CORS misconfiguration", "T1539", "WSTG-CLNT-07", "CWE-942", "safe", _A,
     "corsy -u {url}", "Check for permissive/broken CORS policy (corsy)."),
]


class _SafeDict(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(s, ctx):
    return string.Formatter().vformat(s or "", (), _SafeDict(ctx))


class WebAppModule:
    name = "web_app"
    title = "Web App (OWASP WSTG)"

    def __init__(self, docs_dir=None):
        try:
            from knowledge_loader import load_knowledge
            self._mdef = load_knowledge(docs_dir).modules.get("web_app")
        except Exception:                                              # pragma: no cover
            self._mdef = None

    def _checks(self):
        """Doc-backed checks if the KB has web_app; else the built-in tuples
        normalised to the same dict shape."""
        if self._mdef and self._mdef.get("checks"):
            return self._mdef["checks"]
        return [{"name": n, "attack": a, "owasp": o, "cwe": w, "risk": rk,
                 "when": wh, "command": cmd, "purpose": pp}
                for (n, a, o, w, rk, wh, cmd, pp) in BUILTIN_CHECKS]

    def assess_target(self, target, findings):
        """Assess one web target -> [ModuleResult]. `findings` are the report
        findings for the target's host (related TLS/CVE issues inform severity)."""
        tls = bool(target.get("tls"))
        ctx = {"url": target.get("ref", ""), "ip": target.get("ip") or target.get("host", ""),
               "host": target.get("host", ""), "port": target.get("port", 0),
               "scheme": target.get("scheme", "http"), "label": target.get("label", ""),
               "domain": target.get("host", "")}
        try:
            from config import PATHS as _PATHS
            ctx.update(_PATHS)            # {seclists}/{wordlists}/{users}/{passwords}
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

        surface = ["Public-facing web application - staged initial-access surface "
                   "(T1190); a confirmed app flaw chains into this host's onward paths."]
        if not tls:
            surface.append("Cleartext HTTP - credentials and sessions exposed on-path.")
        if any(f.get("category") == "CVE (vulners)" for f in rel):
            surface.append("Underlying server version has known CVEs (see findings).")

        return [ModuleResult(
            self.name, self.title, target.get("ref", ""), target.get("scheme", "http"),
            f"Web application at {target.get('ref', '')} (OWASP WSTG methodology).",
            worst(rel), techniques=sorted(techs), attack_surface=surface,
            checks=checks, findings=rel)]
