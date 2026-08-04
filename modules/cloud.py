#!/usr/bin/env python3
"""modules.cloud — AWS / Azure / GCP posture methodology (target-driven).

Authorized / lab / CTF use only.

Assesses a cloud target (a provider + optional account/subscription/project) using
the MITRE **ATT&CK Cloud** matrix as the backbone (no single OWASP standard for
cloud, so checks are ATT&CK + CWE-mapped, like the thick-client module). Each check
carries a `safe|intrusive` risk tag; unauthenticated storage/OSINT recon and
authenticated read-only posture scans are safe, active credential/role abuse is
intrusive (VAPT-hidden). Methodology + STAGING only; the engine runs nothing.

Tooling: cloud_enum, S3Scanner, gcpbucketbrute, ScoutSuite, Prowler, pmapper,
cloudsplaining, ROADtools, AzureHound, MicroBurst, pacu (see docs/appsec/arsenal.md).

Checks load from docs/appsec/cloud.md (`module: cloud`) when present, else built-in.
Placeholders: {provider} {account}.
"""
from __future__ import annotations

import string

from .base import Check, ModuleResult, worst

# (name, attack, owasp, cwe, risk, when, command, purpose)   owasp blank (ATT&CK/CWE-mapped)
BUILTIN_CHECKS = [
    ("Public cloud asset discovery", "T1580", "", "CWE-200", "safe", "always",
     "cloud_enum -k <company> -k <company>-dev -k <company>-prod",
     "OSINT-enumerate public S3/Azure/GCP resources by keyword (unauthenticated)."),
    ("Open storage buckets", "T1619", "", "CWE-284", "safe", "always",
     "# S3: s3scanner scan -b <bucket> | GCS: gcpbucketbrute -k <kw> | Azure: <name>.blob.core.windows.net",
     "Find world-readable/-writable object storage."),
    ("Cloud secrets", "T1552", "", "CWE-798", "safe", "always",
     "# trufflehog over IaC/functions/repos; review env vars and lambda/function config",
     "Recover keys/tokens embedded in cloud code & config."),
    ("AWS posture scan", "T1526", "", "", "safe", "aws",
     "prowler aws   (or: scoutsuite aws)",
     "Full CIS/best-practice posture assessment (read-only)."),
    ("AWS IAM privilege paths", "T1098.001", "", "CWE-269", "safe", "aws",
     "pmapper graph create && pmapper query 'preset privesc *'   (cloudsplaining / enumerate-iam)",
     "Map IAM privilege-escalation paths."),
    ("AWS public exposure", "T1580", "", "CWE-284", "safe", "aws",
     "# review public S3, security groups 0.0.0.0/0, public AMIs/snapshots/RDS/ELB",
     "Find internet-exposed AWS resources."),
    ("EC2 instance metadata (SSRF)", "T1552.005", "", "CWE-918", "safe", "aws",
     "# via app SSRF: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "Abuse IMDS for role creds - chains from a web/API SSRF finding."),
    ("Azure / Entra recon", "T1526", "", "", "safe", "azure",
     "roadrecon gather   (or: scoutsuite azure; azurehound for BloodHound edges)",
     "Enumerate the tenant, roles and resources (read-only)."),
    ("Entra ID privilege paths", "T1078.004", "", "CWE-269", "safe", "azure",
     "# BloodHound Azure edges (AZAddMembers/AZOwns/AZResetPassword) toward Global Admin",
     "Map Entra ID privilege-escalation paths."),
    ("Azure storage public access", "T1530", "", "CWE-284", "safe", "azure",
     "# check blob containers for anonymous access (MicroBurst Invoke-EnumerateAzureBlobs)",
     "Find public Azure blob storage."),
    ("GCP posture scan", "T1526", "", "", "safe", "gcp",
     "scoutsuite gcp   (or: prowler gcp)",
     "Full posture assessment of the project/org (read-only)."),
    ("GCP IAM / service accounts", "T1078.004", "", "CWE-269", "safe", "gcp",
     "# enumerate SA keys, roles, actAs/impersonation paths (gcloud iam; hayat)",
     "Map service-account impersonation / privilege paths."),
    ("Credential / role abuse", "T1098.003", "", "CWE-269", "intrusive", "always",
     "# authorized only: pacu (AWS) or execute the mapped privesc path (assume role / add creds)",
     "Execute the escalation - assume role / add credentials."),
]


class _SafeDict(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(s, ctx):
    return string.Formatter().vformat(s or "", (), _SafeDict(ctx))


class CloudModule:
    name = "cloud"
    title = "Cloud (ATT&CK Cloud)"

    def __init__(self, docs_dir=None):
        try:
            from knowledge_loader import load_knowledge
            self._mdef = load_knowledge(docs_dir).modules.get("cloud")
        except Exception:                                              # pragma: no cover
            self._mdef = None

    def _checks(self):
        if self._mdef and self._mdef.get("checks"):
            return self._mdef["checks"]
        return [{"name": n, "attack": a, "owasp": o, "cwe": w, "risk": rk,
                 "when": wh, "command": cmd, "purpose": pp}
                for (n, a, o, w, rk, wh, cmd, pp) in BUILTIN_CHECKS]

    def assess_target(self, target, findings):
        provider = (target.get("provider") or "aws").lower()
        ctx = {"provider": provider, "account": target.get("account") or "<account>",
               "label": target.get("label", "")}
        try:
            from config import PATHS as _PATHS
            ctx.update(_PATHS)
        except Exception:                 # pragma: no cover
            pass

        flags = {"always": True, "aws": provider == "aws",
                 "azure": provider == "azure", "gcp": provider == "gcp"}
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

        surface = [f"Cloud environment ({provider}) - identity, storage and metadata "
                   "are the primary attack surface; a web/API SSRF often pivots here (IMDS)."]
        return [ModuleResult(
            self.name, self.title, target.get("ref", provider), provider,
            f"Cloud posture ({provider}) - ATT&CK Cloud methodology.",
            worst([]), techniques=sorted(techs), attack_surface=surface,
            checks=checks, findings=[])]
