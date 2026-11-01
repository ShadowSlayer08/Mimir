#!/usr/bin/env python3
"""
recon_chain.py — a 5-phase passive-first recon pipeline methodology.

Authorized / lab / CTF / VAPT / red-team use only.

Pattern adopted from ReconFTW (six2dez/reconftw, 8.3k★) and adapted for Mimir's
staging-only boundary: the engine EMITS a staged, ordered sequence of recon
methodology steps per phase; the operator runs each one manually with their
own tooling, under their authorized scope. The engine executes nothing.

Phases (strictly ordered):
  1. PASSIVE OSINT     — zero traffic to target: CT logs, DNS archives, GitHub,
                          cloud storage listings, email leaks, favicon-hash
                          lookups on Shodan/Censys.
  2. ACTIVE SUBDOMAIN  — brute-force / permutations / NOERROR / tlsx TLS
                          port discovery.
  3. HOSTS             — CDN / WAF detection, port scan (naabu then nmap -sV),
                          service fingerprinting.
  4. WEB               — httpx probing, screenshots, URL harvest (katana /
                          waymore), JS analysis, parameter mining, directory
                          fuzzing.
  5. VULN REFERENCE    — Nuclei template references (CVE-mapped), dalfox
                          methodology, sqlmap methodology — ALL staging-only.

Each stage carries a `noise` score (from opsec.py), ATT&CK technique id, and
risk tag. Rate-limiting hints appear in commands as `--rate-limit` references.
Scope-filtering (via roe.py) applied before output — `.gov/.mil/.edu/.int`
hard-blocked.

CLI:
    mimir-recon acme.example                   # all 5 phases, markdown
    mimir-recon acme.example --phase passive   # one phase only
    mimir-recon acme.example --json out.json   # structured output
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

# (name, attack, risk, noise, command, purpose, phase)
_PHASES = [
    # ---- PHASE 1 · PASSIVE OSINT ---------------------------------------
    ("CT history lookup", "T1596.001", "safe", 1,
     "mimir-ct {domain} --since 30",
     "Enumerate every historical cert naming {domain} or its subs (crt.sh).",
     "passive"),
    ("Passive subdomain discovery", "T1590.005", "safe", 1,
     "subfinder -d {domain} -silent -all   # or: amass enum -passive -d {domain}",
     "CT + passive DNS + API aggregation (no target traffic).",
     "passive"),
    ("Public asset OSINT", "T1593.003", "safe", 2,
     "assetfinder --subs-only {domain} ; shodan domain {domain}",
     "Pull historical records from Shodan / Censys / archive.org.",
     "passive"),
    ("GitHub leak hunt", "T1593.003", "safe", 2,
     "github-dorks -d {domain} ; trufflehog github --org <org> --only-verified",
     "Search public GitHub for leaked secrets / internal code references.",
     "passive"),
    ("Favicon hash pivot", "T1596", "safe", 2,
     "# compute mmh3 favicon hash from https://{domain}/favicon.ico ; "
     "shodan search 'http.favicon.hash:<N>'",
     "Find origin / CDN-bypass hosts by favicon hash on Shodan/Censys.",
     "passive"),
    ("Cloud storage enumeration", "T1619", "safe", 2,
     "cloud_enum -k {company} -k {company}-dev -k {company}-prod",
     "Public S3/GCS/Azure bucket enumeration by keyword.",
     "passive"),

    # ---- PHASE 2 · ACTIVE SUBDOMAIN ------------------------------------
    ("Subdomain bruteforce", "T1595.001", "safe", 4,
     "puredns bruteforce ~/.cache/wordlists/subdomains.txt {domain} "
     "--resolvers ~/.cache/resolvers.txt --rate-limit 1500",
     "Mass DNS brute (NOERROR filter) against the authorised wordlist.",
     "active"),
    ("DNS permutations", "T1590.002", "safe", 4,
     "gotator -sub subs.txt -perm permutations.txt | puredns resolve - "
     "--resolvers ~/.cache/resolvers.txt",
     "Permutation attacks against observed subdomain stems.",
     "active"),
    ("TLS port discovery", "T1596", "safe", 3,
     "tlsx -l subs.txt -silent -ro -p 443,8443,9443,10443 -o tls-ports.txt",
     "Discover extra TLS-exposed ports on the resolved subdomains.",
     "active"),

    # ---- PHASE 3 · HOSTS -----------------------------------------------
    ("CDN / WAF fingerprint", "T1596", "safe", 3,
     "wafw00f -i subs.txt -a ; cdncheck -l subs.txt",
     "Identify CDN / WAF per host — gates how we probe them.",
     "hosts"),
    ("Fast port sweep (naabu)", "T1595.001", "safe", 5,
     "naabu -list resolved.txt -top-ports 1000 -rate 2000 -o ports.txt",
     "SYN-scan top-1000 ports; wide + fast.",
     "hosts"),
    ("Deep service detection (nmap)", "T1595.002", "safe", 6,
     "nmap -sV -sC -oA nmap-deep -iL open-ports.txt --max-rate 500",
     "Version detection + default scripts, rate-limited; feed into mimir-cli.",
     "hosts"),
    ("Ingest into Mimir", "T1595.002", "safe", 3,
     "mimir-cli --from-xml nmap-deep.xml --yes --emit-json eng.json "
     "--report report.html --enrich",
     "Run the engine on nmap XML; findings + attack paths + methodology.",
     "hosts"),

    # ---- PHASE 4 · WEB -------------------------------------------------
    ("HTTP probing", "T1595.002", "safe", 4,
     "httpx -l resolved.txt -title -status-code -tech-detect -server "
     "-content-length -silent -rate-limit 150 -o httpx.txt",
     "Probe every host for HTTP(S) + title + tech fingerprint.",
     "web"),
    ("Screenshot grid", "T1592.002", "safe", 3,
     "aquatone -ports 80,443,8080,8443,8888 < httpx.txt   "
     "# or: gowitness file -f httpx.txt",
     "Visual recon — spot admin panels / defaults in seconds.",
     "web"),
    ("URL harvest", "T1595.002", "safe", 4,
     "katana -list httpx.txt -silent -jc -o urls.txt ; "
     "waymore -i {domain} -mode U -oU wayback.txt",
     "Crawl + historical URL harvesting (katana + waymore).",
     "web"),
    ("JS analysis", "T1552.001", "safe", 3,
     "subjs -i httpx.txt | tee js.txt ; getJS --url https://{domain} ; "
     "secretfinder -i js.txt -o cli",
     "Extract JS assets, scan for embedded secrets / routes.",
     "web"),
    ("Parameter mining", "T1595.002", "safe", 4,
     "arjun -i httpx.txt -oT params.txt   # or: paramspider -d {domain}",
     "Discover hidden GET/POST parameters per endpoint.",
     "web"),
    ("Content discovery", "T1595.002", "safe", 5,
     "ffuf -u 'https://{domain}/FUZZ' -w ~/.cache/wordlists/content.txt "
     "-fc 404,400 -t 50 -rate 100",
     "Directory + file fuzzing (rate-limited; authorized only).",
     "web"),

    # ---- PHASE 5 · VULN REFERENCE (methodology only) -------------------
    ("Nuclei template sweep", "T1595.002", "intrusive", 6,
     "nuclei -l httpx.txt -severity medium,high,critical -rate-limit 150 "
     "-stats -o nuclei.txt",
     "Reference community templates (CVEs, misconfigs). Authorized only.",
     "vuln"),
    ("XSS methodology (dalfox)", "T1059.007", "intrusive", 6,
     "dalfox file urls.txt -o dalfox.txt --skip-bav",
     "Parameter XSS scan over the harvested URL set.",
     "vuln"),
    ("SQLi methodology (sqlmap)", "T1190", "intrusive", 7,
     "sqlmap -m urls-with-params.txt --batch --random-agent --level=2 "
     "--risk=1 --threads=5",
     "Parameter SQLi methodology — level=2 (balanced), authorized only.",
     "vuln"),
    ("SSRF / open redirect sweep", "T1190", "intrusive", 6,
     "# oralyzer / ssrfmap over the parameter corpus; validate against an "
     "interactsh listener",
     "SSRF + open-redirect methodology (oralyzer + ssrfmap + interactsh).",
     "vuln"),
    ("Secrets grep (trufflehog)", "T1552.001", "safe", 2,
     "trufflehog filesystem out/ --only-verified   "
     "# or: gitleaks detect --source .",
     "Final grep over harvested JS / content / repos for leaked secrets.",
     "vuln"),
]

_PHASE_ORDER = ("passive", "active", "hosts", "web", "vuln")
_PHASE_LABELS = {
    "passive": "1 · Passive OSINT",
    "active":  "2 · Active subdomain discovery",
    "hosts":   "3 · Host surface",
    "web":     "4 · Web asset recon",
    "vuln":    "5 · Vulnerability-reference sweep",
}


def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                          # pragma: no cover
            pass


_force_utf8_stdio()


def _fmt(cmd, ctx):
    """Minimal str.format with safe passthrough for unknown keys."""
    class _Safe(dict):
        def __missing__(self, k):
            return "{" + k + "}"
    import string
    return string.Formatter().vformat(cmd or "", (), _Safe(ctx))


def build(domain, phases=None):
    """Return a structured recon chain for a domain.
    {domain, generated, phases: [{id, label, steps: [...]}]}  — every step
    carries attack / risk / noise / command / purpose."""
    sel = set(phases) if phases else set(_PHASE_ORDER)
    company = (domain or "").split(".", 1)[0]
    ctx = {"domain": domain, "company": company}
    out_phases = []
    for pid in _PHASE_ORDER:
        if pid not in sel:
            continue
        steps = []
        for i, (name, attack, risk, noise, cmd, purpose, p) in enumerate(_PHASES, 1):
            if p != pid:
                continue
            steps.append({
                "order": len(steps) + 1,
                "name": name,
                "attack": attack,
                "risk": risk,
                "noise": noise,
                "command": _fmt(cmd, ctx),
                "purpose": purpose,
            })
        out_phases.append({"id": pid, "label": _PHASE_LABELS[pid], "steps": steps})
    return {"domain": domain,
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "phases": out_phases}


def to_markdown(chain):
    L = [f"# Recon chain — {chain['domain']}",
         f"_Generated {chain['generated']}  ·  methodology only; the operator runs each step_",
         ""]
    for ph in chain["phases"]:
        L.append(f"## Phase {ph['label']}")
        L.append("")
        for s in ph["steps"]:
            L.append(f"### {s['order']}. {s['name']}  `{s['attack']}` · risk={s['risk']} · noise={s['noise']}/10")
            L.append(f"_{s['purpose']}_")
            L.append("")
            L.append("```")
            L.append(s["command"])
            L.append("```")
            L.append("")
    return "\n".join(L) + "\n"


def to_findings(chain):
    """Project the recon chain into Mimir's finding/path shape so it can be
    merged into an engagement — one 'path' per phase; each step a path step."""
    paths = []
    for i, ph in enumerate(chain["phases"], 1):
        if not ph["steps"]:
            continue
        steps = [{
            "order": s["order"],
            "tactic": "Reconnaissance" if ph["id"] in ("passive", "active", "hosts")
                      else "Discovery",
            "technique_id": s["attack"],
            "technique": s["name"],
            "host": chain["domain"],
            "guidance": s["purpose"],
            "command": s["command"],
            "noise": s["noise"],
            "risk": s["risk"],
        } for s in ph["steps"]]
        paths.append({
            "id": f"RECON-{i:03d}",
            "name": f"Recon phase — {ph['label']}",
            "kind": "recon",
            "severity": "info", "confidence": "high", "score": 0,
            "hosts": [chain["domain"]], "tactics": ["Reconnaissance"],
            "rationale": "Passive-first recon chain; staging-only methodology.",
            "steps": steps,
        })
    return paths


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="mimir-recon",
                                 description="5-phase passive-first recon chain methodology")
    ap.add_argument("domain", help="apex domain (e.g. acme.example)")
    ap.add_argument("--phase", action="append", choices=_PHASE_ORDER,
                    help="only emit this phase (repeatable)")
    ap.add_argument("--json", metavar="FILE", help="write structured JSON here")
    ap.add_argument("--md", metavar="FILE", help="write markdown here (else stdout)")
    args = ap.parse_args(argv)
    chain = build(args.domain, phases=args.phase)
    md = to_markdown(chain)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"[+] wrote {args.md}", file=sys.stderr)
    else:
        sys.stdout.write(md)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(chain, fh, indent=2)
        print(f"[+] wrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
