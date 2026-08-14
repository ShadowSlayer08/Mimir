#!/usr/bin/env python3
"""modules.identity — SaaS identity-provider methodology (target-driven).

Authorized / lab / CTF use only.

Assesses a SaaS IDENTITY target (Entra ID / M365, Okta, Google Workspace, ADFS) —
the cloud-identity attack surface that sits above individual apps. Checks are ATT&CK
+ CWE-mapped with a `safe|intrusive` risk tag: recon / user-enum / MFA-coverage review
are safe; password spray, MFA fatigue, SAML forgery and phishing are intrusive
(VAPT-hidden, lockout-aware). Methodology + STAGING only; the engine runs nothing.

Tooling: roadrecon/ROADtools, AADInternals, GraphRunner, o365spray, MFASweep,
TeamFiltration, trevorspray, GAT/GAM (Workspace), okta-recon.

Checks load from docs/appsec/identity.md (`module: identity`) when present, else
built-in. Providers: --identity entra|m365|okta|gworkspace|adfs[:tenant].
Placeholders: {provider} {tenant} {domain}.
"""
from __future__ import annotations

import string

from .base import Check, ModuleResult, worst

_A = "always"
# (name, attack, owasp, cwe, risk, when, command, purpose)
BUILTIN_CHECKS = [
    ("Tenant / federation recon", "T1590", "", "CWE-200", "safe", _A,
     "# check /{domain}/.well-known/openid-configuration; getuserrealm (managed vs federated); autodiscover",
     "Fingerprint the IdP and federation type."),
    ("User enumeration", "T1589.002", "", "CWE-203", "safe", _A,
     "o365spray --enum -d {domain}   # or Okta /api/v1 response + timing user-enum",
     "Enumerate valid accounts."),
    ("Password spray", "T1110.003", "", "CWE-307", "intrusive", _A,
     "# authorized: TeamFiltration / trevorspray - low-and-slow single-password spray (lockout-aware)",
     "Test for weak / reused passwords."),
    ("MFA coverage & legacy auth", "T1078.004", "", "CWE-308", "safe", _A,
     "MFASweep   # find legacy/basic-auth endpoints (EWS/IMAP/SMTP AUTH) that bypass MFA",
     "Find accounts and protocols without MFA."),
    ("MFA fatigue / push bombing", "T1621", "", "CWE-287", "intrusive", _A,
     "# authorized: repeated push prompts to a consented test account (measure user response)",
     "Test MFA-fatigue susceptibility."),
    ("Entra / M365 recon (authed)", "T1526", "", "", "safe", "entra",
     "roadrecon gather && roadrecon gui   # or AADInternals / GraphRunner (read-only)",
     "Enumerate tenant, roles, apps and Conditional Access policies."),
    ("OAuth app / consent surface", "T1528", "", "CWE-287", "safe", "entra",
     "# review app registrations, over-privileged Graph scopes, illicit-consent-grant risk",
     "Find token / consent-grant attack surface."),
    ("Conditional Access gaps", "T1078.004", "", "CWE-284", "safe", "entra",
     "# review CAPs for excluded users, legacy-auth allowances, device/location gaps",
     "Find Conditional-Access policy bypasses."),
    ("Okta configuration & policy", "T1526", "", "", "safe", "okta",
     "# enumerate org apps, auth/sign-on policies, ThreatInsight, factor enrollment, API tokens",
     "Assess Okta configuration and policy."),
    ("Google Workspace recon", "T1526", "", "", "safe", "gworkspace",
     "# GAT/GAM: enumerate users, OAuth tokens, super-admins, less-secure-app / OAuth scopes",
     "Assess Google Workspace configuration."),
    ("Federation / SAML forgery", "T1606.002", "", "CWE-347", "intrusive", _A,
     "# authorized: with the token-signing key, forge SAML (Golden SAML) to test federation trust",
     "Test federation trust and token forgery (ADFS / Entra)."),
    ("Credential phishing / device code", "T1566", "", "CWE-1021", "intrusive", _A,
     "# authorized red-team: device-code or evilginx AiTM to capture tokens (with consent)",
     "Test credential-phishing and token-theft resilience."),
]

# provider token -> internal flag
_PROV = {"entra": "entra", "azuread": "entra", "azure-ad": "entra", "m365": "entra",
         "o365": "entra", "office365": "entra", "okta": "okta",
         "gworkspace": "gworkspace", "google": "gworkspace", "gsuite": "gworkspace",
         "adfs": "entra"}


class _SafeDict(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(s, ctx):
    return string.Formatter().vformat(s or "", (), _SafeDict(ctx))


class IdentityModule:
    name = "identity"
    title = "SaaS Identity (Entra / Okta / Workspace)"

    def __init__(self, docs_dir=None):
        try:
            from knowledge_loader import load_knowledge
            self._mdef = load_knowledge(docs_dir).modules.get("identity")
        except Exception:                                              # pragma: no cover
            self._mdef = None

    def _checks(self):
        if self._mdef and self._mdef.get("checks"):
            return self._mdef["checks"]
        return [{"name": n, "attack": a, "owasp": o, "cwe": w, "risk": rk,
                 "when": wh, "command": cmd, "purpose": pp}
                for (n, a, o, w, rk, wh, cmd, pp) in BUILTIN_CHECKS]

    def assess_target(self, target, findings):
        raw = (target.get("provider") or "entra").lower()
        prov = _PROV.get(raw, "entra")
        ctx = {"provider": raw, "tenant": target.get("tenant") or "<tenant>",
               "domain": target.get("domain") or target.get("host") or "<domain>",
               "label": target.get("label", "")}
        try:
            from config import PATHS as _PATHS
            ctx.update(_PATHS)
        except Exception:                 # pragma: no cover
            pass

        flags = {"always": True, "entra": prov == "entra",
                 "okta": prov == "okta", "gworkspace": prov == "gworkspace"}
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

        surface = [f"SaaS identity ({raw}) - user-enum, weak/reused passwords, MFA gaps, "
                   "OAuth consent and federation trust drive tenant-wide compromise."]
        return [ModuleResult(
            self.name, self.title, target.get("ref", raw), raw,
            f"SaaS identity posture ({raw}).",
            worst([]), techniques=sorted(techs), attack_surface=surface,
            checks=checks, findings=[])]
