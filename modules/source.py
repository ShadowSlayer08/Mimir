#!/usr/bin/env python3
"""modules.source — source code / supply-chain methodology (target-driven).

Authorized / lab / CTF use only.

Assesses a SOURCE target (a repository path or URL): SAST, secret scanning, SCA /
SBOM, IaC and CI/CD review. Checks are ATT&CK + CWE-mapped with a `safe|intrusive`
risk tag (static review is safe). Methodology + STAGING only; the engine runs nothing
and never exfiltrates code.

Tooling: semgrep, gitleaks, trufflehog, grype, osv-scanner, dependency-check, syft,
checkov, trivy, bandit/gosec/brakeman/retire.js, cosign.

Checks load from docs/appsec/source.md (`module: source`) when present, else built-in.
Placeholders: {path} {repo}.
"""
from __future__ import annotations

import string

from .base import Check, ModuleResult, worst

_A = "always"
# (name, attack, owasp, cwe, risk, when, command, purpose)
BUILTIN_CHECKS = [
    ("Secret & key scan", "T1552.001", "", "CWE-798", "safe", _A,
     "gitleaks detect --source {path}; trufflehog filesystem {path} --only-verified",
     "Find hardcoded secrets across the tree and git history."),
    ("SAST code weaknesses", "T1190", "", "CWE-707", "safe", _A,
     "semgrep --config auto {path}   # + language linters: bandit / gosec / brakeman",
     "Find injection, authz and crypto bugs in source."),
    ("Dependency CVEs (SCA)", "T1195.001", "", "CWE-1104", "safe", _A,
     "grype dir:{path}   # or: osv-scanner -r {path}; dependency-check",
     "Flag vulnerable third-party dependencies."),
    ("SBOM generation", "T1195", "", "CWE-1104", "safe", _A,
     "syft {path} -o cyclonedx-json > sbom.json",
     "Produce a software bill of materials for the component inventory."),
    ("Dependency confusion / typosquat", "T1195.002", "", "CWE-1357", "safe", _A,
     "# check internal package names claimable on public registries; lockfile integrity; typosquats",
     "Test for dependency-confusion and typosquat exposure."),
    ("IaC misconfiguration", "T1610", "", "CWE-1032", "safe", _A,
     "checkov -d {path}; trivy config {path}   # Terraform / Kubernetes / Dockerfile",
     "Find infrastructure-as-code misconfigurations."),
    ("CI/CD pipeline security", "T1195", "", "CWE-284", "safe", _A,
     "# review GitHub Actions / GitLab CI for pull_request_target, unpinned actions, secret leakage",
     "Assess the build-pipeline attack surface."),
    ("Insecure crypto & defaults", "T1552", "", "CWE-327", "safe", _A,
     "# grep for weak crypto (MD5/DES/ECB), disabled TLS verification, debug flags",
     "Find weak cryptography and unsafe defaults."),
    ("Repository OSINT", "T1213.003", "", "CWE-200", "safe", _A,
     "# search public forks / gists / commits for leaked internal code and credentials",
     "Find exposed code and secrets outside the repository."),
    ("Malicious code review", "T1195.002", "", "CWE-506", "safe", _A,
     "# review for obfuscated code, suspicious postinstall scripts, unexpected network calls",
     "Detect implanted or backdoored code."),
]


class _SafeDict(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(s, ctx):
    return string.Formatter().vformat(s or "", (), _SafeDict(ctx))


class SourceModule:
    name = "source"
    title = "Source / Supply Chain"

    def __init__(self, docs_dir=None):
        try:
            from knowledge_loader import load_knowledge
            self._mdef = load_knowledge(docs_dir).modules.get("source")
        except Exception:                                              # pragma: no cover
            self._mdef = None

    def _checks(self):
        if self._mdef and self._mdef.get("checks"):
            return self._mdef["checks"]
        return [{"name": n, "attack": a, "owasp": o, "cwe": w, "risk": rk,
                 "when": wh, "command": cmd, "purpose": pp}
                for (n, a, o, w, rk, wh, cmd, pp) in BUILTIN_CHECKS]

    def assess_target(self, target, findings):
        ctx = {"path": target.get("ref") or ".", "repo": target.get("ref", ""),
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

        surface = ["Source & build pipeline - secrets in history, vulnerable dependencies, "
                   "IaC drift and CI/CD weaknesses are a direct supply-chain path (T1195)."]
        return [ModuleResult(
            self.name, self.title, target.get("ref", "source"), "repo",
            "Source code and supply-chain review.",
            worst([]), techniques=sorted(techs), attack_surface=surface,
            checks=checks, findings=[])]
