"""Abuse-info (guided human-led exploitation insight) lookup + step enrichment."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from abuse import abuse_for, load_info  # noqa: E402
from nmap_analyzer import load_scan, analyze, build_report  # noqa: E402
from attack_path_engine import generate_paths  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO, "tests", "fixtures", "full_scan.xml")


def test_lookup_and_subtechnique_fallback():
    info = load_info()
    assert "T1190" in info
    direct = abuse_for("T1003.006", info)        # has its own entry (DCSync)
    assert direct and "DCSync" in direct.get("name", "")
    base = abuse_for("T1021.999", info)           # unknown sub -> base T1021
    assert base and base.get("impact")


def test_entries_have_impact_and_how():
    for tid, e in load_info().items():
        assert e.get("impact") and e.get("how"), tid


def test_paths_carry_abuse_insight():
    hosts, meta, _ = load_scan(FIXTURE)
    report = build_report(hosts, meta, analyze(hosts))
    paths = generate_paths(report)
    enriched = [s for p in paths for s in p["steps"] if s.get("abuse")]
    assert enriched, "expected at least one staged step enriched with abuse info"
    a = enriched[0]["abuse"]
    assert "impact" in a and "how" in a and "opsec" in a
