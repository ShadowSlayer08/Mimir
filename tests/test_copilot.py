"""Engagement co-pilot — ranked next-best-action recommender."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from copilot import recommend, recommend_from_engagement  # noqa: E402


def test_domain_path_outranks_lateral_and_low_finding():
    paths = [
        {"id": "AP-9", "name": "lateral hop", "kind": "lateral", "severity": "low",
         "confidence": "low", "score": 13, "hosts": ["a", "b"],
         "steps": [{"technique_id": "T1078", "command": ""}]},
        {"id": "AD-1", "name": "user -> Domain Admins", "kind": "domain", "severity": "critical",
         "confidence": "high", "score": 110, "hosts": ["u", "DA"],
         "steps": [{"technique_id": "T1098", "command": "certipy shadow auto"}]},
    ]
    findings = [{"host": "h", "port": 80, "severity": "low", "title": "cleartext", "category": "Protocol"}]
    recs = recommend(findings, paths)
    assert recs[0]["title"] == "user -> Domain Admins"        # DA objective ranked #1
    assert recs[0]["category"] == "objective"
    assert recs[0]["command"] == "certipy shadow auto"        # surfaces the next command
    assert recs[0]["score"] > recs[-1]["score"]


def test_quick_win_finding_surfaces():
    findings = [{"host": "h", "port": 2375, "severity": "critical",
                 "title": "Docker API exposed (unauth -> RCE)", "category": "Container"}]
    recs = recommend(findings, [])
    assert any(a["category"] == "quick-win" and "Docker" in a["title"] for a in recs)


def test_deterministic_ranked_and_top_n():
    paths = [{"id": f"P{i}", "name": f"p{i}", "kind": "lateral", "severity": "medium",
              "confidence": "medium", "score": 30, "hosts": ["a"], "steps": []} for i in range(20)]
    r1 = recommend([], paths, top=5)
    r2 = recommend([], paths, top=5)
    assert [a["title"] for a in r1] == [a["title"] for a in r2]   # deterministic
    assert len(r1) == 5 and [a["rank"] for a in r1] == [1, 2, 3, 4, 5]


def test_from_engagement():
    eng = {"findings": [], "attack_paths": [
        {"id": "X", "name": "n", "kind": "domain", "severity": "critical",
         "confidence": "high", "score": 100, "hosts": ["a"], "steps": []}]}
    recs = recommend_from_engagement(eng)
    assert recs and recs[0]["rank"] == 1
