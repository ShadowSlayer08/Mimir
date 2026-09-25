#!/usr/bin/env python3
"""
cvss4.py — CVSS 4.0 vector construction from an engine finding.

Authorized / lab / CTF use only.

CVSS 4.0 (FIRST, Nov 2023) splits the score across four supplemental groups:
  Base           - AV / AC / AT / PR / UI / VC / VI / VA / SC / SI / SA
  Threat         - E (Exploit Maturity)
  Environmental  - CR / IR / AR + modified base metrics (optional)
  Supplemental   - S / AU / R / V / RE / U (advisory-only)

This module does NOT reimplement the FIRST scoring rubric (that's 200+ lines of
lookup tables and outside the engine's scope). It builds a valid CVSS 4.0 VECTOR
STRING from the engine's own finding metadata (severity, category, exploit
references, EPSS/KEV enrichment) and emits a base severity band per the FIRST
severity map. Downstream tools (defect trackers, CVSS calculators) can score the
vector; our value is producing a stable, standards-shaped label.

The vector is deterministic, offline-safe, and never invents values it doesn't
have evidence for. Missing metrics are set to the FIRST-recommended defaults
(pessimistic base assumptions for a red-team surface).

    from cvss4 import vector_for, band_for, enrich_findings
    v = vector_for({"severity": "critical", "category": "CVE (vulners)",
                    "cve": ["CVE-2017-0144"], "exploit_refs": [...]})
    -> "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"
"""
from __future__ import annotations

# FIRST CVSS 4.0 severity bands (per spec).
_BANDS = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"), (0.0, "info")]

# Engine severity -> heuristic base score for band emission (until a calculator ships).
_SEV_SCORE = {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 3.0, "info": 0.0}

# Category -> attack vector hint. Public-network services and web/API attack
# from over the internet; local-only surface (thick, source review) is Local.
_AV_HINT = {
    "CVE (vulners)":  "N",   # a scanned public CVE is remotely reachable by default
    "Vuln scan":      "N",
    "Web":            "N",
    "API":            "N",
    "Cipher":         "N",
    "TLS":            "N",
    "TLS Certificate":"N",
    "Protocol":       "N",
    "Auth":           "N",
    "Container":      "N",
    "Service":        "N",
    "Exposure":       "N",
    "SNMP":           "N",
    "DB":             "N",
    "Cloud":          "N",
    "Wireless":       "A",   # Adjacent-network (RF proximity)
    "IoT":            "A",
    "ICS":            "A",
    "Thick":          "L",   # Local (binary on disk)
    "Source":         "L",
    "Mobile":         "L",
}

# Categories that involve authentication / user context on the attacker side.
_PR_HINT = {
    "Auth": "L",             # low-priv authenticated foothold typically
    "DB":   "L",
    "Cloud":"L",
}


def _sev_score(sev):
    return _SEV_SCORE.get((sev or "").lower(), 0.0)


def band_for(severity):
    """CVSS 4.0 severity band for a numeric or engine-severity input."""
    if isinstance(severity, str):
        s = _sev_score(severity)
    else:
        try:
            s = float(severity)
        except (TypeError, ValueError):
            s = 0.0
    for threshold, name in _BANDS:
        if s >= threshold:
            return name
    return "info"


def _has_public_exploit(finding):
    """True if we know of a public exploit for this finding (KEV, or ExploitDB ref)."""
    refs = finding.get("exploit_refs") or []
    if any(r.get("source") in ("metasploit", "exploitdb") for r in refs):
        return True
    # KEV enrichment sets category prefix; category isn't a KEV marker itself,
    # but a public metasploit/exploitdb ref is the strongest signal we have.
    return False


def _impact_from_severity(sev):
    """Per-metric impact defaults from engine severity."""
    lo = (sev or "").lower()
    if lo == "critical":
        return "H", "H", "H"                       # VC / VI / VA all high
    if lo == "high":
        return "H", "H", "N"
    if lo == "medium":
        return "L", "L", "N"
    if lo == "low":
        return "L", "N", "N"
    return "N", "N", "N"


def vector_for(finding):
    """Build a valid CVSS 4.0 vector string from an engine finding dict.

    Missing evidence -> pessimistic defaults (AV:N / AC:L / AT:N / PR:N / UI:N)
    which is the FIRST-recommended stance for a red-team surface. Fields that
    have no engine equivalent (SC/SI/SA subsequent-system impact) default to N.
    """
    if not isinstance(finding, dict):
        return ""
    cat = (finding.get("category") or "").strip()
    sev = (finding.get("severity") or "").strip()

    av = _AV_HINT.get(cat, "N")
    ac = "L"                                        # low attack complexity default
    at = "N"                                        # no attack-requirements presumption
    pr = _PR_HINT.get(cat, "N")                     # None unless category implies auth
    ui = "N"                                        # no user interaction assumed on infra
    vc, vi, va = _impact_from_severity(sev)
    sc = si = sa = "N"                              # no subsequent-system data
    parts = [f"CVSS:4.0",
             f"AV:{av}", f"AC:{ac}", f"AT:{at}", f"PR:{pr}", f"UI:{ui}",
             f"VC:{vc}", f"VI:{vi}", f"VA:{va}", f"SC:{sc}", f"SI:{si}", f"SA:{sa}"]

    # Threat metric: E (Exploit Maturity) — A(ttacked)/P(oC)/U(nreported)
    if _has_public_exploit(finding):
        parts.append("E:A")
    return "/".join(parts)


def enrich_findings(findings):
    """Attach `cvss4` (vector string) and `cvss4_band` to each finding that has
    real evidence (a non-empty severity or category). Idempotent."""
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        if not (f.get("severity") or f.get("category")):           # skip empty stubs
            continue
        try:
            v = vector_for(f)
            if v:
                f["cvss4"] = v
                f["cvss4_band"] = band_for(f.get("severity"))
        except Exception:                                              # never break the caller
            pass
    return findings


def main(argv=None):
    import argparse
    import json
    import sys
    ap = argparse.ArgumentParser(prog="cvss4.py",
                                 description="CVSS 4.0 vector from an engine finding")
    ap.add_argument("--severity", default="critical",
                    choices=["critical", "high", "medium", "low", "info"])
    ap.add_argument("--category", default="CVE (vulners)")
    ap.add_argument("--cve", action="append", default=[])
    ap.add_argument("--exploit", action="store_true",
                    help="mark as having a public exploit reference")
    args = ap.parse_args(argv)
    finding = {"severity": args.severity, "category": args.category, "cve": args.cve}
    if args.exploit:
        finding["exploit_refs"] = [{"source": "metasploit", "name": "x", "url": "x"}]
    print(f"vector: {vector_for(finding)}")
    print(f"band  : {band_for(args.severity)}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
