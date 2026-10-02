#!/usr/bin/env python3
"""modules.web_recon — attack-surface recon methodology (target-driven).

Authorized / lab / CTF use only.

Methodology for the FIVE recon/discovery surfaces redamon ships and we were
missing: subdomain enumeration + takeover, hidden virtual hosts, CDN/WAF origin
discovery, GraphQL misconfiguration, and web cache poisoning. All checks are
ATT&CK + CWE-mapped with a `safe|intrusive` risk tag. STAGING only — the engine
emits the methodology; the operator runs each tool with their own tooling.

Target shape: a domain or URL (`assess --web-recon https://acme.example`),
auto-promoted from any discovered http/https host when `--web-recon-auto` is set.

Tooling the methodology references:
  * subfinder, amass, assetfinder, subjack, nuclei, baddns (subdomain + takeover)
  * ffuf, gobuster, VHostFinder (hidden virtual hosts)
  * CloudFlair, Shodan+favicon, DNSdumpster, host-header checks (CDN origin)
  * graphw00f, graphql-cop, inql, batchQL, Clairvoyance (GraphQL)
  * Web Cache Vulnerability Scanner (WCVS), Nuclei WCP templates, Burp CP+ (cache poisoning)
"""
from __future__ import annotations

import string

from .base import Check, ModuleResult, worst

_A = "always"
# (name, attack, owasp, cwe, risk, when, command, purpose)
BUILTIN_CHECKS = [
    # ---- Subdomain discovery -------------------------------------------
    ("Subdomain enumeration (passive)", "T1590.005", "WSTG-INFO-04", "CWE-200", "safe", _A,
     "subfinder -d {host} -silent -all   # or: amass enum -passive -d {host}; assetfinder {host}",
     "Discover subdomains via CT logs / passive DNS / APIs (no traffic to target)."),
    ("Subdomain enumeration (active)", "T1595.001", "WSTG-INFO-04", "CWE-200", "safe", _A,
     "amass enum -active -d {host} -brute -w ~/.cache/wordlists/subdomains.txt",
     "Brute-force + DNS AXFR / reverse DNS for subdomains the passive sources missed."),
    ("Subdomain takeover (dangling CNAME)", "T1583.001", "WSTG-CONF-10", "CWE-404", "safe", _A,
     "subjack -w subs.txt -t 50 -timeout 30 -ssl -c ~/subjack/fingerprints.json "
     "-o takeovers.txt   # cross-check: baddns -t subs.txt",
     "Find dangling CNAMEs that point at reclaimable third-party services."),
    ("Takeover validation (claimable)", "T1583.001", "WSTG-CONF-10", "CWE-404", "safe", _A,
     "nuclei -l subs.txt -t http/takeovers/ -severity high,critical",
     "Confirm takeover candidates against curated Nuclei templates."),
    # ---- Hidden virtual hosts ------------------------------------------
    ("Hidden vhost discovery", "T1595", "WSTG-CONF-01", "CWE-200", "safe", _A,
     "ffuf -u https://{host}/ -H 'Host: FUZZ.{host}' -w ~/.cache/wordlists/subdomains.txt "
     "-fc 404,400 -fs 0 -t 40",
     "Find virtual hosts the DNS doesn't expose by fuzzing the Host header."),
    ("Vhost confirmation (L7)", "T1595", "WSTG-CONF-01", "CWE-200", "safe", _A,
     "# compare content hashes with and without Host: candidate; filter out same-page responses",
     "Confirm a candidate vhost truly serves distinct content."),
    # ---- CDN / WAF origin discovery ------------------------------------
    ("CDN / WAF fingerprint", "T1596", "WSTG-INFO-01", "CWE-200", "safe", _A,
     "wafw00f https://{host}; whatwaf -u https://{host}   # + review CNAME / headers for CDN provider",
     "Identify which CDN / WAF is in front of the target."),
    ("Origin discovery via CT history", "T1596.001", "", "CWE-200", "safe", _A,
     "crt.sh?q={host}   # historical certs; dig old subdomains / A records that bypass CDN",
     "Find the origin IP in historical CT log data (common CDN-bypass path)."),
    ("Origin discovery via favicon hash", "T1596", "", "CWE-200", "safe", _A,
     "# compute mmh3 favicon hash from https://{host}/favicon.ico; search Shodan "
     "'http.favicon.hash:<N>'",
     "Pivot to the origin by favicon-hash on Shodan / Censys."),
    ("CloudFlair / S3 bypass", "T1596.001", "", "CWE-284", "safe", _A,
     "cloudflair {host}   # Censys-backed Cloudflare origin discovery",
     "Enumerate IPs CloudFlare fronts, test direct origin."),
    # ---- GraphQL -------------------------------------------------------
    ("GraphQL endpoint fingerprint", "T1595.002", "WSTG-APIT-01", "CWE-200", "safe", _A,
     "graphw00f -t https://{host}/graphql; curl -s https://{host}/graphql "
     "-H 'content-type: application/json' -d '{{\"query\":\"query{{__typename}}\"}}'",
     "Confirm GraphQL + fingerprint the implementation (Apollo / Hasura / etc.)."),
    ("GraphQL introspection", "T1595.002", "WSTG-APIT-01", "CWE-306", "safe", _A,
     "graphql-cop -t https://{host}/graphql   # or: inql scan -t https://{host}/graphql",
     "Dump the schema when introspection is enabled (OWASP API Top 10)."),
    ("Schema inference (introspection off)", "T1595.002", "WSTG-APIT-01", "CWE-200", "safe", _A,
     "clairvoyance https://{host}/graphql -w ~/.cache/wordlists/graphql.txt",
     "Reconstruct the schema from field-suggestion error messages when introspection is disabled."),
    ("GraphQL authorization + batching", "T1210", "WSTG-APIT-01", "CWE-285", "intrusive", _A,
     "batchql -t https://{host}/graphql   # test query batching + aliased DoS",
     "Test batch-query DoS, aliased batching, and field-level authz."),
    # ---- Web cache poisoning -------------------------------------------
    ("Cache behaviour discovery", "T1557", "WSTG-CONF-07", "CWE-444", "safe", _A,
     "wcvs -u https://{host}/   # Web Cache Vulnerability Scanner — passes + headers",
     "Map which headers / parameters the cache keys on."),
    ("Unkeyed input poisoning", "T1557", "WSTG-CONF-07", "CWE-444", "intrusive", _A,
     "wcvs -u https://{host}/ -X 'X-Forwarded-Host,X-Original-URL,X-Rewrite-URL'",
     "Test unkeyed header injection that lands in cached responses (classic WCP)."),
    ("CPDoS: HTTP meta character", "T1499.004", "", "CWE-444", "intrusive", _A,
     "# CPDoS variants: HMC, HHO, HMO - deliberately poison the cache to deny",
     "Cache-poisoned denial of service test (noisy; coordinate the window)."),
]


class _SafeDict(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(s, ctx):
    return string.Formatter().vformat(s or "", (), _SafeDict(ctx))


class WebReconModule:
    name = "web_recon"
    title = "Web Attack Surface Recon"

    def __init__(self, docs_dir=None):
        try:
            from knowledge_loader import load_knowledge
            self._mdef = load_knowledge(docs_dir).modules.get("web_recon")
        except Exception:                                              # pragma: no cover
            self._mdef = None

    def _checks(self):
        if self._mdef and self._mdef.get("checks"):
            return self._mdef["checks"]
        return [{"name": n, "attack": a, "owasp": o, "cwe": w, "risk": rk,
                 "when": wh, "command": cmd, "purpose": pp}
                for (n, a, o, w, rk, wh, cmd, pp) in BUILTIN_CHECKS]

    def assess_target(self, target, findings):
        host = (target.get("host") or target.get("ref") or "").strip()
        if host.startswith(("http://", "https://")):
            host = host.split("://", 1)[-1].split("/", 1)[0]
        ctx = {"host": host, "label": target.get("label", "")}

        checks, techs = [], set()
        for c in self._checks():
            checks.append(Check(c["name"], _fmt(c["command"], ctx), c.get("purpose", ""),
                                c.get("attack", ""), c.get("owasp", ""), c.get("cwe", ""),
                                c.get("risk", "")).to_dict())
            if c.get("attack"):
                techs.add(c["attack"])

        surface = [f"Web attack surface recon ({host}) — subdomain enum + takeover, "
                   "hidden vhosts, CDN/WAF origin discovery, GraphQL, cache poisoning."]
        return [ModuleResult(
            self.name, self.title, target.get("ref", host), "web",
            f"Web recon ({host}) — attack-surface discovery methodology.",
            worst([]), techniques=sorted(techs), attack_surface=surface,
            checks=checks, findings=[])]
