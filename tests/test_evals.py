"""Eval harness (evals/bench.py) — scoring logic and CI-friendly end-to-end.

Locks the two properties that make the harness trustworthy:
  1. `_evaluate` is a pure scorer: same inputs -> same recall/miss list.
  2. End-to-end: every shipped scenario must pass at 100% recall (deterministic).
     A regression in the engine shows up as a red bench BEFORE it hits users.
"""
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evals import bench  # noqa: E402


def _scenario_files():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return sorted(glob.glob(os.path.join(root, "evals", "scenarios", "*.yml")))


def test_scorer_pure_and_counts_correctly():
    scenario = {"expected": {
        "hosts_min": 1, "findings_min": 1,
        "findings_must_include": [
            {"title_contains": "eternalblue", "severity": "critical"},
            {"title_contains": "not-there", "severity_min": "high"},
        ],
        "techniques_must_include": ["T1190", "T9999"],
        "path_kinds_must_include": ["rce"],
        "top_action_title_regex": "eternalblue",
    }}
    report = {"host_summary": [{"host": "a"}],
              "findings": [{"title": "EternalBlue (MS17-010)", "severity": "critical"}]}
    paths = [{"kind": "rce", "steps": [{"technique_id": "T1190"}]}]
    recs = [{"title": "RCE via EternalBlue"}]

    r = bench._evaluate(scenario, report, paths, recs)
    # 2 counts + 2 findings (1 hit) + 2 techniques (1 hit) + 1 kind + 1 top = 8 total, 6 hits
    assert r["total"] == 8, r
    assert r["hits"] == 6, r
    # Only the "not-there" finding and T9999 technique should miss.
    misses = " | ".join(r["misses"])
    assert "not-there" in misses and "T9999" in misses
    assert "eternalblue" not in misses.lower()             # already matched
    # Rerun identical inputs -> identical output (purity)
    r2 = bench._evaluate(scenario, report, paths, recs)
    assert r == r2


def test_severity_at_least():
    assert bench._sev_at_least("critical", "high")
    assert bench._sev_at_least("high", "high")
    assert not bench._sev_at_least("medium", "high")
    assert not bench._sev_at_least(None, "low")            # missing severity is a miss


def test_all_shipped_scenarios_pass_deterministic():
    """CI: every scenario must run and evaluate at 100% recall deterministically."""
    files = _scenario_files()
    assert files, "no scenarios found under evals/scenarios/"
    for path in files:
        r = bench._run_scenario(path, compare_llm=False)
        assert "error" not in r, r
        det = r["deterministic"]
        assert det["recall"] == 1.0, \
            f"{os.path.basename(path)} recall {det['recall']*100:.0f}% - misses: {det['misses']}"


def test_llm_branch_skipped_gracefully_when_offline():
    """With Ollama down, --compare-llm must degrade to a 'skipped' marker, not crash."""
    import llm
    saved = llm.available
    try:
        llm.available = lambda: False
        r = bench._run_scenario(_scenario_files()[0], compare_llm=True)
    finally:
        llm.available = saved
    assert r.get("llm", {}).get("skipped"), r
