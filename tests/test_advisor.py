"""advisor.py — the LOCAL-LLM co-pilot (Planner / Narrator / Adviser).

This is an authorized red-team tool: the local model's tradecraft passes through
unmodified (no content filtering). These tests lock the two properties that matter:
offline-safety (no Ollama -> empty, engine unchanged) and faithful pass-through of
the model's operator playbook. They run offline by stubbing llm.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import advisor  # noqa: E402
import llm  # noqa: E402


class _Stub:
    """Temporarily swap llm attributes; restore on __exit__."""
    def __init__(self, **attrs):
        self.attrs = attrs
        self.saved = {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self.saved[k] = getattr(llm, k)
            setattr(llm, k, v)
        return self

    def __exit__(self, *exc):
        for k, v in self.saved.items():
            setattr(llm, k, v)


def test_offline_safe_returns_empty():
    with _Stub(available=lambda: False):
        assert advisor.plan_path({"id": "x", "steps": [{}]}) == []
        assert advisor.advise({}) == []
        assert advisor.exec_summary({"meta": {}}) == ""
        assert advisor.runbook_addendum_md([{"id": "x", "steps": [{}]}]) == ""


def test_plan_path_preserves_tradecraft():
    # Real red-team steps must pass through untouched — nothing is filtered.
    canned = {"substeps": [
        {"ref": "1.T1046", "action": "Enumerate SMB with enum4linux-ng",
         "validate": "shares listed", "opsec": ""},
        {"ref": "2.T1210", "action": "Run the Metasploit ms17_010_eternalblue module for a "
         "meterpreter session", "validate": "session opens", "opsec": "noisy on the wire"},
        {"ref": "3.T1003", "action": "Run mimikatz sekurlsa::logonpasswords to dump credentials",
         "validate": "plaintext creds / hashes", "opsec": "clear the security event log after"},
    ]}
    with _Stub(available=lambda: True, pick=lambda role="planner": "test-model",
               generate_json=lambda *a, **k: canned):
        subs = advisor.plan_path({"id": "AP-1", "name": "x", "steps": [{}]})
    assert len(subs) == 3, "no sub-step may be dropped"
    joined = " ".join(s["action"] for s in subs)
    assert "Metasploit" in joined and "mimikatz" in joined
    assert any(s["opsec"] == "clear the security event log after" for s in subs), \
        "OPSEC / evasion notes must pass through for a red-team tool"


def test_advise_passthrough():
    canned = {"advice": [
        {"suggestion": "Kerberoast SPNs and crack offline", "why": "cheap creds", "attack": "T1558.003"},
        {"suggestion": "Disable EDR then run the implant", "why": "stealth", "attack": "T1562.001"},
    ]}
    with _Stub(available=lambda: True, pick=lambda role="planner": "m",
               generate_json=lambda *a, **k: canned):
        adv = advisor.advise({"recommendations": [], "attack_paths": [], "meta": {}})
    assert len(adv) == 2, "advice passes through unfiltered"
    assert adv[1]["attack"] == "T1562.001"


def test_exec_summary_returns_model_text():
    with _Stub(available=lambda: True, pick=lambda role="narrator": "m",
               generate=lambda *a, **k: "Critical exposure across two hosts; full domain compromise likely."):
        out = advisor.exec_summary({"meta": {}, "findings": [], "attack_paths": []})
    assert "Critical exposure" in out


def test_basic_runbook_is_deterministic():
    eng = {"meta": {"target": "10.0.0.0/24", "mode": "vapt"},
           "attack_paths": [{"id": "AP-1", "name": "path", "severity": "high",
                             "confidence": "medium", "score": 90, "rationale": "why",
                             "steps": [{"order": 1, "tactic": "Initial Access",
                                        "technique_id": "T1190", "technique": "Exploit Public App",
                                        "host": "web", "guidance": "enumerate the app"}]}]}
    md = advisor.basic_runbook_md(eng)
    assert "AP-1" in md and "T1190" in md and "runs nothing" in md.lower()
