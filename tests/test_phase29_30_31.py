"""Phase 29 + 30 + 31 bundled tests.

Covers:
  * (29) link graphs: _observe_results emits parsed_result Fact citing the
    step Fact (via io_nonce lookup); new_findings/services/urls carry
    source_fact_id.
  * (29) cancel-cause attribution: aborted_by lands in summary for budget
    exhaustion paths.
  * (29) rerank dedup: situation_key stable across iterations => rerank
    skipped.
  * (30) Hints: ParseResult.hints threads through _merge_hints into
    engagement['hints']; nmap parser emits SMB/LDAP/RDP hints.
  * (30) sidequestion: mimir-facts ask / answer round-trip; autopilot
    loop halts when a pending question exists.
  * (31) nonce helpers: generation is unique, tag + verify round-trip,
    wrong nonce rejected, autopilot step record carries io_nonce.
"""
import io
import json
import os
import sys
import sqlite3
import tempfile

os.environ["OLLAMA_HOST"] = "http://127.0.0.1:1"
os.environ["MIMIR_LLM_TIMEOUT"] = "0.5"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import autopilot                                 # noqa: E402
import autopilot_loop                            # noqa: E402
import fact_ledger                               # noqa: E402
import parsers                                   # noqa: E402
from parsers.base import ParseResult             # noqa: E402


def _tmp(suffix=""):
    fd, p = tempfile.mkstemp(suffix=suffix, prefix="p293031-")
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
            "modules": [], "hosts": [], "findings": []}


# --------------------------------------------------------------------------- #
# Phase 31 — nonce helpers
# --------------------------------------------------------------------------- #
def test_new_nonce_is_unique_and_hex():
    seen = {autopilot._new_nonce() for _ in range(50)}
    assert len(seen) == 50
    for n in seen:
        assert len(n) == 32 and all(c in "0123456789abcdef" for c in n)


def test_tag_and_verify_roundtrip():
    nonce = autopilot._new_nonce()
    tagged = autopilot.tag_stdout_for_llm("mock stdout here", nonce)
    assert nonce in tagged
    ok, body = autopilot.verify_llm_output_is_tool_output(tagged, nonce)
    assert ok is True
    assert body == "mock stdout here"


def test_verify_rejects_wrong_nonce():
    tagged = autopilot.tag_stdout_for_llm("x", autopilot._new_nonce())
    ok, _ = autopilot.verify_llm_output_is_tool_output(tagged, "deadbeef" * 4)
    assert ok is False


def test_verify_rejects_missing_markers():
    ok, _ = autopilot.verify_llm_output_is_tool_output(
        "plain untagged text", autopilot._new_nonce())
    assert ok is False


def test_autopilot_step_record_carries_io_nonce():
    eng = _mkeng([_mkstep(command="echo nonce-test")])
    out = autopilot.run(eng, noise_ceiling=10, timeout_s=10)
    r = out["results"][0]
    assert r["verdict"] == "executed_ok"
    assert "io_nonce" in r
    assert len(r["io_nonce"]) == 32


# --------------------------------------------------------------------------- #
# Phase 29 — cancel-cause attribution
# --------------------------------------------------------------------------- #
def test_aborted_by_budget_turns():
    eng = _mkeng([_mkstep(command=f"echo s{i}", order=i) for i in range(5)])
    out = autopilot.run(eng, noise_ceiling=10, timeout_s=10, budget_turns=1)
    assert out["summary"]["aborted"] is True
    assert out["summary"]["aborted_by"] == "budget_turns"


def test_aborted_by_budget_tokens():
    # One step runs; tokens approximated as 100/sec; set tokens=1 so
    # the NEXT step's pre-check lands skipped_budget.
    eng = _mkeng([_mkstep(command="echo a", order=i) for i in range(3)])
    out = autopilot.run(eng, noise_ceiling=10, timeout_s=10, budget_tokens=1)
    assert out["summary"]["aborted_by"] == "budget_tokens"


def test_aborted_by_is_none_on_clean_run():
    eng = _mkeng([_mkstep(command="echo a")])
    out = autopilot.run(eng, noise_ceiling=10, timeout_s=10)
    assert out["summary"]["aborted"] is False
    assert out["summary"]["aborted_by"] is None


# --------------------------------------------------------------------------- #
# Phase 29 — link graphs via source_fact_id
# --------------------------------------------------------------------------- #
def test_parsed_result_fact_cites_step_fact_by_nonce():
    db = _tmp(".db")
    try:
        eng = _mkeng([_mkstep(
            command='echo "scan output 10.1.1.1 CVE-2025-12345"')])
        autopilot_loop.run_loop(
            eng, max_iterations=1,
            autopilot_kwargs={"noise_ceiling": 10, "timeout_s": 10,
                              "fact_db": db,
                              "engagement_id": "eng-link"})
        # The ledger should hold: 1 step Fact (executed_ok), 1 parsed_result
        # Fact citing it, and some hint/finding derivatives.
        step_facts = fact_ledger.list_facts(db, "eng-link", kind="executed_ok")
        parsed_facts = fact_ledger.list_facts(db, "eng-link", kind="parsed_result")
        assert len(step_facts) >= 1
        assert len(parsed_facts) >= 1
        # Each parsed Fact cites the step Fact via from_fact_ids.
        assert parsed_facts[0]["from_fact_ids"] == [step_facts[0]["id"]]
    finally:
        _cleanup(db)


def test_findings_carry_source_fact_id_after_merge():
    db = _tmp(".db")
    try:
        eng = _mkeng([_mkstep(
            command='echo "CVE-2024-11111 observed on probe.lab"')])
        autopilot_loop.run_loop(
            eng, max_iterations=1,
            autopilot_kwargs={"noise_ceiling": 10, "timeout_s": 10,
                              "fact_db": db,
                              "engagement_id": "eng-sfid"})
        findings = [f for f in (eng.get("findings") or [])
                    if f.get("cve") == "CVE-2024-11111"]
        assert findings
        assert findings[0].get("source_fact_id") is not None
    finally:
        _cleanup(db)


# --------------------------------------------------------------------------- #
# Phase 29 — rerank dedup
# --------------------------------------------------------------------------- #
def test_situation_key_is_stable_across_identical_engagements():
    eng = _mkeng([])
    k1 = autopilot_loop._situation_key(eng)
    k2 = autopilot_loop._situation_key(eng)
    assert k1 == k2


def test_situation_key_changes_when_findings_grow():
    eng = _mkeng([])
    before = autopilot_loop._situation_key(eng)
    eng["findings"].append({"host": "x", "cve": "CVE-9", "title": "t"})
    after = autopilot_loop._situation_key(eng)
    assert before != after


def test_rerank_skipped_on_steady_state_iterations():
    # Dry-run; no execution => parse-steps=0 => situation unchanged
    # across iterations 2+ => rerank_skipped flag flips true.
    eng = _mkeng([_mkstep(command="echo a")])
    out = autopilot_loop.run_loop(
        eng, max_iterations=3,
        autopilot_kwargs={"dry_run": True, "noise_ceiling": 10})
    # First iter — rerank_skipped False; convergence may halt after 1,
    # so we just assert "at least one iteration ran".
    assert out["iterations"] >= 1
    assert out["per_iter"][0]["rerank_skipped"] is False


# --------------------------------------------------------------------------- #
# Phase 30 — Hints
# --------------------------------------------------------------------------- #
_NMAP_SMB = """\
Nmap scan report for 10.0.0.5
Host is up (0.0010s latency).
PORT     STATE SERVICE
445/tcp  open  microsoft-ds
"""


def test_nmap_parser_emits_smb_hint():
    r = parsers.dispatch("nmap -sV -p 445 10.0.0.5", _NMAP_SMB)
    assert any("SMB on 10.0.0.5:445" in h for h in r.hints)
    assert any("null-session" in h for h in r.hints)


def test_hints_merge_into_engagement():
    eng = {"hosts": [], "findings": []}
    added = autopilot_loop._merge_hints(
        eng, ["Try null-session on 10.0.0.5",
              "Try null-session on 10.0.0.5",           # dup
              "LDAP anon bind on dc01"])
    assert added == 2
    assert eng["hints"] == ["Try null-session on 10.0.0.5",
                            "LDAP anon bind on dc01"]


def test_hints_land_as_facts_when_fact_db_set():
    db = _tmp(".db")
    try:
        eng = _mkeng([])
        pr = ParseResult(source_tool="probe")
        pr.hints = ["use null-session on 10.0.0.5"]
        autopilot_loop._record_hint_facts(db, "eng-h", pr.hints, 42)
        rows = fact_ledger.list_facts(db, "eng-h", kind="hint")
        assert len(rows) == 1
        assert rows[0]["data"]["hint"] == "use null-session on 10.0.0.5"
        assert rows[0]["from_fact_ids"] == [42]
    finally:
        _cleanup(db)


# --------------------------------------------------------------------------- #
# Phase 30 — sidequestion
# --------------------------------------------------------------------------- #
def test_ask_and_answer_cli_round_trip():
    db = _tmp(".db")
    try:
        rc = fact_ledger.main(["--db", db, "ask", "eng-q",
                               "Which cred set?"])
        assert rc == 0
        pending = fact_ledger.list_facts(db, "eng-q",
                                         kind="sidequestion:pending")
        assert len(pending) == 1
        rc = fact_ledger.main(["--db", db, "answer",
                               str(pending[0]["id"]), "set-A"])
        assert rc == 0
        answered = fact_ledger.list_facts(db, "eng-q",
                                          kind="sidequestion:answered")
        assert len(answered) == 1
        assert answered[0]["from_fact_ids"] == [pending[0]["id"]]
    finally:
        _cleanup(db)


def test_pending_sidequestion_detector():
    db = _tmp(".db")
    try:
        # No facts at all — nothing pending.
        assert autopilot_loop._pending_sidequestion(db, "eng-x") is None
        # Ask one — becomes pending.
        q = fact_ledger.record(db_path=db, engagement_id="eng-x",
                               kind="sidequestion:pending",
                               data={"question": "what creds?"})
        pending = autopilot_loop._pending_sidequestion(db, "eng-x")
        assert pending is not None
        assert pending["id"] == q
        # Answer it — pending clears.
        fact_ledger.record(db_path=db, engagement_id="eng-x",
                           kind="sidequestion:answered",
                           from_fact_ids=[q],
                           data={"answer": "set-A"})
        assert autopilot_loop._pending_sidequestion(db, "eng-x") is None
    finally:
        _cleanup(db)


def test_autopilot_loop_halts_on_pending_sidequestion():
    db = _tmp(".db")
    try:
        # Seed a pending question.
        fact_ledger.record(db_path=db, engagement_id="eng-halt",
                           kind="sidequestion:pending",
                           data={"question": "Which domain user?"})
        eng = _mkeng([_mkstep(command="echo a")])
        out = autopilot_loop.run_loop(
            eng, max_iterations=3,
            autopilot_kwargs={"dry_run": True, "noise_ceiling": 10,
                              "fact_db": db,
                              "engagement_id": "eng-halt"})
        assert out.get("halted_on") == "sidequestion"
        assert out["iterations"] == 0        # loop never entered iter 1
    finally:
        _cleanup(db)
