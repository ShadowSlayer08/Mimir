"""cvss4.py — CVSS 4.0 vector construction from engine findings.

Locks the three properties that matter:
  1. Every vector is well-formed (starts with CVSS:4.0/ + all base metrics present).
  2. Severity -> band lookup follows the FIRST bands.
  3. Category heuristics steer AV correctly (network vs adjacent vs local).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cvss4  # noqa: E402


_VEC = re.compile(
    r"^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/"
    r"VC:[NLH]/VI:[NLH]/VA:[NLH]/SC:[NLH]/SI:[NLH]/SA:[NLH](/E:[APU])?$"
)


def test_bands_map_to_severity_labels():
    assert cvss4.band_for("critical") == "critical"
    assert cvss4.band_for("high") == "high"
    assert cvss4.band_for("medium") == "medium"
    assert cvss4.band_for("low") == "low"
    assert cvss4.band_for("info") == "info"
    assert cvss4.band_for(9.5) == "critical"
    assert cvss4.band_for(7.9) == "high"
    assert cvss4.band_for(0.0) == "info"
    assert cvss4.band_for(None) == "info"


def test_vector_shape_valid_for_every_engine_severity():
    for sev in ("critical", "high", "medium", "low", "info"):
        v = cvss4.vector_for({"severity": sev, "category": "CVE (vulners)"})
        assert _VEC.match(v), f"malformed vector for {sev}: {v!r}"


def test_public_exploit_promotes_E_to_A():
    without = cvss4.vector_for({"severity": "critical", "category": "CVE (vulners)"})
    with_ = cvss4.vector_for({"severity": "critical", "category": "CVE (vulners)",
                              "exploit_refs": [{"source": "metasploit", "name": "x",
                                                "url": "https://x"}]})
    assert "/E:A" not in without
    assert with_.endswith("/E:A")


def test_attack_vector_hints_by_category():
    n = cvss4.vector_for({"severity": "high", "category": "CVE (vulners)"})
    a = cvss4.vector_for({"severity": "high", "category": "Wireless"})
    l = cvss4.vector_for({"severity": "high", "category": "Thick"})
    assert "/AV:N/" in n
    assert "/AV:A/" in a
    assert "/AV:L/" in l


def test_enrich_findings_is_idempotent_and_shape_stable():
    findings = [{"severity": "critical", "category": "CVE (vulners)"},
                {"severity": "medium", "category": "Web"},
                {}]
    cvss4.enrich_findings(findings)
    cvss4.enrich_findings(findings)                                # second pass = no-op
    assert findings[0]["cvss4"].startswith("CVSS:4.0/")
    assert findings[0]["cvss4_band"] == "critical"
    assert findings[1]["cvss4"].startswith("CVSS:4.0/")
    assert "cvss4" not in findings[2]                              # empty finding untouched


def test_malformed_input_never_raises():
    for bad in (None, 42, "not a dict", []):
        assert cvss4.vector_for(bad) == ""
    cvss4.enrich_findings(None)                                    # tolerates None
    cvss4.enrich_findings([])                                      # tolerates empty
