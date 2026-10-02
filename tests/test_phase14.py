"""Phase 14 additions — web_recon / ai_target / opsec / ct_monitor /
roe_parse / sdk / copilot-goal / ledger-checkpoint.

One test file to lock the new contracts (one module per test group), so a
regression in any Phase-14 lift fails fast.
"""
import os
import re
import sys
import sqlite3
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import apptargets                 # noqa: E402
import ct_monitor                 # noqa: E402
import copilot                    # noqa: E402
import ledger                     # noqa: E402
import llm                        # noqa: E402
import opsec                      # noqa: E402
import roe_parse                  # noqa: E402
from modules import dispatch_apps # noqa: E402

_ATTACK = re.compile(r"^T\d{4}(\.\d{3})?$")


# ---- web_recon + ai_target --------------------------------------------- #
def test_web_recon_dispatches_valid_checks():
    t = {"kind": "web_recon", "ref": "https://acme.example", "host": "acme.example"}
    res = dispatch_apps([t], {"findings": []})
    assert res and res[0]["module"] == "web_recon"
    for c in res[0]["checks"]:
        assert _ATTACK.match(c["attack"]), c["attack"]
        assert c.get("risk") in ("safe", "intrusive")


def test_ai_target_includes_llm_top_10_coverage():
    t = {"kind": "ai_target", "ref": "openai:gpt-x", "host": "openai"}
    res = dispatch_apps([t], {"findings": []})
    assert res and res[0]["module"] == "ai_target"
    owasp = {c.get("owasp") for c in res[0]["checks"]}
    # Must cover the LLM03/LLM04/LLM07 corners at least.
    assert {"LLM01", "LLM02", "LLM04", "LLM07"}.issubset(owasp)


def test_apptargets_parsers_for_new_kinds():
    wt = apptargets.parse_web_recon(["acme.example", "https://x.example/path"])
    assert len(wt) == 2 and wt[0]["kind"] == "web_recon" and wt[1]["host"] == "x.example"
    at = apptargets.parse_ai_target(["https://api.example/v1/chat", "openai:gpt-4"])
    assert len(at) == 2 and at[0]["kind"] == "ai_target" and at[1]["host"] == "openai"


# ---- opsec ---------------------------------------------------------------- #
def test_opsec_annotates_paths_and_warns_above_ceiling():
    paths = [{"id": "P-1", "steps": [
        {"technique_id": "T1590.005"},   # 1 (passive OSINT)
        {"technique_id": "T1210"},       # 7 (RCE confirmation)
        {"technique_id": "T1499"},       # 10 (DoS)
    ]}]
    opsec.annotate_paths(paths, profile="stealth")
    scores = [s["noise"] for s in paths[0]["steps"]]
    assert scores == [1, 7, 10]
    assert paths[0]["steps"][0].get("noise_warn") is None     # 1 <= stealth ceiling (3)
    assert paths[0]["steps"][1].get("noise_warn") is True     # 7 > 3
    assert paths[0]["steps"][2].get("noise_warn") is True
    assert paths[0]["noise_max"] == 10 and paths[0]["noise_warn"] is True


def test_opsec_fallback_by_risk_tag():
    checks = [{"name": "x", "attack": "T9999",  "risk": "safe"},        # unknown tech -> risk:safe = 3
              {"name": "y", "attack": "T9999",  "risk": "intrusive"}]   # risk:intrusive = 7
    opsec.annotate_modules([{"checks": checks}], profile="normal")
    assert checks[0]["noise"] == 3 and checks[1]["noise"] == 7


# ---- ct_monitor ----------------------------------------------------------- #
def test_ct_monitor_valid_invalid_domain():
    assert ct_monitor._valid_domain("acme.example")
    assert not ct_monitor._valid_domain("not a domain")
    assert not ct_monitor._valid_domain("")


def test_ct_monitor_offline_handles_missing_cache():
    """`lookup(..., offline=True)` on a never-seen domain returns an empty-but-well-formed dict."""
    res = ct_monitor.lookup("totally-made-up-" + os.urandom(4).hex() + ".example",
                            offline=True)
    assert "subdomains" in res and "cert_count" in res
    assert res["cert_count"] == 0


# ---- roe_parse ------------------------------------------------------------ #
def test_roe_parse_regex_extractor_pulls_scope_and_rules():
    text = """\
# Engagement: Acme Q4
Jurisdiction: US-CA

## In scope
10.0.0.0/24
acme.example

## Out of scope
10.0.0.99

Allowed window: 18:00-23:59 Mon-Fri.
Rules: no denial of service. non-intrusive only.
"""
    r = roe_parse.extract_regex(text)
    assert "10.0.0.0/24" in r["in_scope"]
    assert "acme.example" in r["in_scope"]
    assert "10.0.0.99" in r["out_of_scope"]
    assert "T1499" in r["forbidden_techniques"]
    assert "intrusive" in r["forbidden_risk"]
    assert r["engagement"].lower().startswith("acme")


def test_roe_parse_llm_falls_back_offline():
    """With no local model reachable, parse() uses the regex extractor only."""
    saved = llm.available
    try:
        llm.available = lambda: False
        text = "In scope: 10.0.0.0/24\nNo denial of service."
        r = roe_parse.parse(text, prefer_llm=True)
        assert "10.0.0.0/24" in r["in_scope"]
        assert r["_sources"]["in_scope"] == "regex"
    finally:
        llm.available = saved


# ---- plugin SDK ----------------------------------------------------------- #
def test_sdk_module_params_coerce_types():
    from sdk import ModuleParams
    import dataclasses

    @dataclasses.dataclass
    class HelloParams(ModuleParams):
        name: str = ""
        depth: int = 1
        deep: bool = False
        tags: list = dataclasses.field(default_factory=list)

    p = HelloParams.from_target({"name": "acme", "depth": "3", "deep": "yes",
                                 "tags": "a,b,c"})
    assert p.name == "acme" and p.depth == 3 and p.deep is True
    assert p.tags == ["a", "b", "c"]


def test_sdk_test_harness_scope_rejects_out_of_scope():
    from sdk import TestHarness, BaseModule, module_result

    class Dummy(BaseModule):
        name = "example.dummy"; title = "dummy"
        def assess_target(self, target, findings):
            return [module_result(self, target["ref"], checks=[{
                "name": "k", "command": "echo", "attack": "T1595",
                "owasp": "", "cwe": "", "risk": "safe", "purpose": ""}])]

    with TestHarness(scope=["10.0.0.0/24"]) as h:
        r = h.run(Dummy, {"kind": "example.dummy", "ref": "10.0.0.5", "host": "10.0.0.5"})
        assert r and h.staged_count == 1
        r2 = h.run(Dummy, {"kind": "example.dummy", "ref": "10.99.99.99", "host": "10.99.99.99"})
        assert r2 == [] and h.out_of_scope == [("10.99.99.99", "not_in_scope")]


# ---- copilot goal-bonus -------------------------------------------------- #
def test_copilot_goal_bonus_up_weights_objective_actions():
    """`goal=domain_admin` should prefer domain-category / cred-access actions."""
    paths = [
        {"id": "P-1", "name": "lateral hop", "kind": "lateral", "severity": "medium",
         "confidence": "medium", "score": 50, "hosts": ["a", "b"],
         "steps": [{"technique_id": "T1078"}]},
        {"id": "AD-1", "name": "user -> DA", "kind": "domain", "severity": "critical",
         "confidence": "high", "score": 70, "hosts": ["u", "DA"],
         "steps": [{"technique_id": "T1003", "command": "x"}]},
    ]
    # Force deterministic path.
    saved = llm.available
    try:
        llm.available = lambda: False
        without = copilot.recommend([], paths, top=5)
        with_goal = copilot.recommend([], paths, top=5, goal="domain_admin")
    finally:
        llm.available = saved
    assert with_goal[0]["title"].endswith("user -> DA")
    # The DA action got a goal_bonus of +50 (objective category + T1003 technique)
    da = next(a for a in with_goal if a["title"] == "user -> DA")
    assert da["trace"]["goal_bonus"] >= 25
    assert da["trace"]["goal"] == "domain_admin"
    # The lateral action is untouched (no matching dimensions)
    lat = next(a for a in with_goal if a["title"] == "lateral hop")
    assert "goal_bonus" not in (lat.get("trace") or {})
    # DA score is higher with the goal than without.
    assert da["score"] > next(a["score"] for a in without if a["title"] == "user -> DA")


def test_copilot_unknown_goal_is_noop():
    paths = [{"id": "P-1", "name": "x", "kind": "domain", "severity": "high",
              "confidence": "high", "score": 60, "hosts": ["a"], "steps": []}]
    saved = llm.available
    try:
        llm.available = lambda: False
        a = copilot.recommend([], paths, goal="imaginary-goal")
        b = copilot.recommend([], paths)
    finally:
        llm.available = saved
    assert a[0]["score"] == b[0]["score"]


# ---- ledger checkpoint / replay ----------------------------------------- #
def _tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ckpt-test-")
    os.close(fd); os.unlink(path)
    return path


def test_ledger_checkpoint_save_list_load():
    db = _tmp_db()
    try:
        payload = {"engagement": "acme-Q3",
                   "staged_steps": [{"id": "AP-1", "status": "done"}],
                   "notes": "fin"}
        cid = ledger.checkpoint_save(db, "milestone-1", payload,
                                     engagement="acme-Q3", operator="alice")
        assert cid >= 1
        rows = ledger.checkpoint_list(db)
        assert len(rows) == 1 and rows[0]["label"] == "milestone-1"
        assert rows[0]["operator"] == "alice"
        got = ledger.checkpoint_load(db, cid)
        assert got == payload
        latest = ledger.checkpoint_latest(db)
        assert latest == cid
    finally:
        os.path.exists(db) and os.unlink(db)


def test_ledger_checkpoint_missing_id():
    db = _tmp_db()
    try:
        ledger.checkpoint_save(db, "m", {})
        raised = False
        try:
            ledger.checkpoint_load(db, 999)
        except KeyError:
            raised = True
        assert raised
    finally:
        os.path.exists(db) and os.unlink(db)
