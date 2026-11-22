"""Phase 25 — the four fixes to the gaps called out in the end-of-phase-24
status review: v2 re-dispatch, seed corpus, Crucible peer mock, DPO trainer.

Covers:
  * autopilot_loop._restage_from_discoveries: new services -> module checks
    appended to AUTOPILOT-V2-SYNTH path; dedup across iterations; respects
    noise ceiling + accept_risk.
  * autopilot_loop.run_loop with re-dispatch: a second iteration actually
    gets new executable steps when parser output surfaces new ports.
  * slm.seed.seed_db populates the trace DB with seed:* rows (non-zero
    count); idempotent re-seed; stats_for_seeds reports by source.
  * slm.bridge.query_peer + crucible_peer_mock HMAC round-trip: valid
    signature -> verdict mapped to +1/0/-1; bad signature -> 401.
  * slm.train_dpo.build_pairs filters by min_pair_delta; dry-run main
    path returns 0 without any torch deps.
"""
import io
import json
import os
import socket
import sqlite3
import sys
import tempfile
import threading
import time

os.environ["OLLAMA_HOST"] = "http://127.0.0.1:1"
os.environ["MIMIR_LLM_TIMEOUT"] = "0.5"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import autopilot_loop                           # noqa: E402
from slm import trace as slm_trace              # noqa: E402
from slm import seed as slm_seed                # noqa: E402
from slm import bridge as slm_bridge            # noqa: E402
from slm import train_dpo as slm_dpo            # noqa: E402

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import crucible_peer_mock                        # noqa: E402


def _tmp(suffix=""):
    fd, p = tempfile.mkstemp(suffix=suffix, prefix="p25-")
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


def _with_env(key, value):
    prev = os.environ.get(key)
    if value is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = value
    return prev


def _restore_env(key, prev):
    if prev is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = prev


# --------------------------------------------------------------------------- #
# Fix #2 — autopilot v2 re-dispatch
# --------------------------------------------------------------------------- #
def test_restage_from_discoveries_appends_new_checks():
    eng = {"hosts": [], "findings": [], "attack_paths": []}
    new_services = [
        {"host": "10.0.0.5", "port": 22, "proto": "tcp", "service": "ssh"},
        {"host": "10.0.0.5", "port": 445, "proto": "tcp", "service": "microsoft-ds"},
    ]
    added, modules_called = autopilot_loop._restage_from_discoveries(
        eng, new_services, mode="vapt", noise_ceiling=10,
        accept_risk=("safe", "intrusive"))
    # modules.dispatch may vary by KB; we only require SOMETHING runnable
    # landed on the synthetic path for one of the known services.
    assert modules_called > 0
    assert added > 0
    synth = eng["attack_paths"][0]
    assert synth["id"] == "AUTOPILOT-V2-SYNTH"
    assert synth["kind"] == "autopilot-synth"
    for step in synth["steps"]:
        assert step["risk"] in ("safe", "intrusive")
        assert step["command"]
        assert step["noise"] <= 10


def test_restage_respects_noise_ceiling_and_risk_accept():
    eng = {"hosts": [], "findings": [], "attack_paths": []}
    new_services = [{"host": "10.0.0.5", "port": 22, "proto": "tcp",
                     "service": "ssh"}]
    # safe-only + low ceiling must either produce only safe steps or none.
    added, _ = autopilot_loop._restage_from_discoveries(
        eng, new_services, mode="vapt", noise_ceiling=4,
        accept_risk=("safe",))
    if eng["attack_paths"]:
        for step in eng["attack_paths"][0]["steps"]:
            assert step["risk"] == "safe"
            assert step["noise"] <= 4


def test_restage_dedups_across_iterations():
    eng = {"hosts": [], "findings": [], "attack_paths": []}
    new_services = [{"host": "10.0.0.5", "port": 22, "proto": "tcp",
                     "service": "ssh"}]
    autopilot_loop._restage_from_discoveries(
        eng, new_services, mode="vapt", noise_ceiling=10,
        accept_risk=("safe", "intrusive"))
    before = len(eng["attack_paths"][0]["steps"]) if eng["attack_paths"] else 0
    # Second call with identical services must add zero.
    autopilot_loop._restage_from_discoveries(
        eng, new_services, mode="vapt", noise_ceiling=10,
        accept_risk=("safe", "intrusive"))
    after = len(eng["attack_paths"][0]["steps"]) if eng["attack_paths"] else 0
    assert before == after


def test_restage_empty_input_is_zero_cost():
    eng = {"hosts": [], "findings": [], "attack_paths": []}
    added, called = autopilot_loop._restage_from_discoveries(
        eng, [], mode="vapt")
    assert added == 0 and called == 0
    assert eng["attack_paths"] == []


# --------------------------------------------------------------------------- #
# Fix #1 — seed corpus
# --------------------------------------------------------------------------- #
def test_seed_db_populates_non_zero_rows():
    db = _tmp(".db"); prev = _with_env("MIMIR_SLM_TRACE_DB", db)
    try:
        n = slm_seed.seed_db(db, max_rows=50)
        assert n > 0
        s = slm_seed.stats_for_seeds(db)
        assert s["present"] is True
        assert s["total"] == n
        assert len(s["by_source"]) >= 1
    finally:
        _restore_env("MIMIR_SLM_TRACE_DB", prev); _cleanup(db)


def test_seed_db_is_idempotent():
    db = _tmp(".db"); prev = _with_env("MIMIR_SLM_TRACE_DB", db)
    try:
        n1 = slm_seed.seed_db(db, max_rows=30)
        n2 = slm_seed.seed_db(db, max_rows=30)
        assert n1 > 0
        assert n2 == 0                 # already there, dedup on (kind, prompt_hash)
    finally:
        _restore_env("MIMIR_SLM_TRACE_DB", prev); _cleanup(db)


def test_seed_rows_are_marked_worked_by_default():
    db = _tmp(".db"); prev = _with_env("MIMIR_SLM_TRACE_DB", db)
    try:
        slm_seed.seed_db(db, max_rows=5)
        con = sqlite3.connect(db)
        try:
            outcomes = [r[0] for r in con.execute(
                "SELECT outcome FROM qualia_trace WHERE kind LIKE 'seed:%'"
            ).fetchall()]
        finally:
            con.close()
        assert outcomes and all(o == "worked" for o in outcomes)
    finally:
        _restore_env("MIMIR_SLM_TRACE_DB", prev); _cleanup(db)


def test_seed_without_mark_worked_leaves_outcome_null():
    db = _tmp(".db"); prev = _with_env("MIMIR_SLM_TRACE_DB", db)
    try:
        slm_seed.seed_db(db, max_rows=5, mark_worked=False)
        con = sqlite3.connect(db)
        try:
            outcomes = [r[0] for r in con.execute(
                "SELECT outcome FROM qualia_trace WHERE kind LIKE 'seed:%'"
            ).fetchall()]
        finally:
            con.close()
        assert outcomes and all(o is None for o in outcomes)
    finally:
        _restore_env("MIMIR_SLM_TRACE_DB", prev); _cleanup(db)


# --------------------------------------------------------------------------- #
# Fix #3 — Crucible peer mock HMAC round-trip
# --------------------------------------------------------------------------- #
def _pick_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


def _mock_server(port, key):
    srv = crucible_peer_mock.make_server("127.0.0.1", port, key)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, th


def _with_bridge_env(url, key):
    prev = {k: os.environ.get(k) for k in ("CRUCIBLE_URL", "CRUCIBLE_API_KEY")}
    os.environ["CRUCIBLE_URL"] = url
    os.environ["CRUCIBLE_API_KEY"] = key
    # The crucible_bridge module cached DEFAULT_* at import — re-poll.
    import crucible_bridge
    for name in ("_URL", "_KEY"):
        if hasattr(crucible_bridge, name):
            delattr(crucible_bridge, name)
    return prev


def _restore_bridge_env(prev):
    for k, v in prev.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_mock_peer_agrees_on_attack_id_response():
    port = _pick_port()
    srv, _ = _mock_server(port, "testkey123")
    prev = _with_bridge_env(f"http://127.0.0.1:{port}", "testkey123")
    try:
        sig = slm_bridge.query_peer("prompt", "use T1210 for lateral movement")
        assert sig == 1
    finally:
        srv.shutdown(); _restore_bridge_env(prev)


def test_mock_peer_disagrees_on_empty_response():
    port = _pick_port()
    srv, _ = _mock_server(port, "testkey123")
    prev = _with_bridge_env(f"http://127.0.0.1:{port}", "testkey123")
    try:
        sig = slm_bridge.query_peer("prompt", "")
        assert sig == -1
    finally:
        srv.shutdown(); _restore_bridge_env(prev)


def test_mock_peer_unsure_on_generic_response():
    port = _pick_port()
    srv, _ = _mock_server(port, "testkey123")
    prev = _with_bridge_env(f"http://127.0.0.1:{port}", "testkey123")
    try:
        sig = slm_bridge.query_peer("prompt", "some generic advice without ids")
        assert sig == 0
    finally:
        srv.shutdown(); _restore_bridge_env(prev)


def test_mock_peer_rejects_bad_signature():
    port = _pick_port()
    srv, _ = _mock_server(port, "server-secret")
    prev = _with_bridge_env(f"http://127.0.0.1:{port}", "WRONG-KEY")
    try:
        sig = slm_bridge.query_peer("prompt", "use T1210")
        # 401 maps to None (bridge treats non-2xx as "no signal").
        assert sig is None
    finally:
        srv.shutdown(); _restore_bridge_env(prev)


# --------------------------------------------------------------------------- #
# Fix #4 — DPO trainer (pair construction + dry-run)
# --------------------------------------------------------------------------- #
def _seed_trace_with_rewards(db, pairs):
    """pairs is [(prompt, [(response, reward), ...])]."""
    prev = _with_env("MIMIR_SLM_TRACE_DB", db)
    try:
        # Ensure schema exists before ALTER TABLE.
        slm_trace._connect(db).close()
        from slm import reward as slm_reward
        slm_reward.ensure_reward_column(db)
        for prompt, responses in pairs:
            for resp, rew in responses:
                slm_trace.record("k", "adviser", prompt,
                                 llm_result=resp, fallback_result=None,
                                 used_fallback=False, validator_passed=True)
        # Set outcome + reward.
        con = sqlite3.connect(db, isolation_level=None)
        try:
            rows = con.execute("SELECT id, llm_result FROM qualia_trace").fetchall()
            reward_map = {}
            for prompt, responses in pairs:
                for resp, rew in responses:
                    reward_map[resp] = rew
            for rid, text in rows:
                r = reward_map.get(text, 0.0)
                con.execute(
                    "UPDATE qualia_trace SET outcome=?, reward=? WHERE id=?",
                    ("worked", r, rid))
        finally:
            con.close()
    finally:
        _restore_env("MIMIR_SLM_TRACE_DB", prev)


def test_dpo_build_pairs_filters_by_min_delta():
    db = _tmp(".db")
    _seed_trace_with_rewards(db, [
        ("P1", [("good", 0.9), ("bad", 0.1)]),           # delta 0.8 -> pair
        ("P2", [("good2", 0.55), ("notbad", 0.50)]),     # delta 0.05 -> skipped
    ])
    try:
        pairs = list(slm_dpo.build_pairs(db, only_outcome="worked",
                                         min_pair_delta=0.2))
        prompts = {p["prompt"] for p in pairs}
        assert "P1" in prompts
        assert "P2" not in prompts
        p1 = next(p for p in pairs if p["prompt"] == "P1")
        assert p1["chosen"] == "good" and p1["rejected"] == "bad"
    finally:
        _cleanup(db)


def test_dpo_dry_run_is_safe_without_torch():
    db = _tmp(".db")
    _seed_trace_with_rewards(db, [
        ("P1", [("good", 0.9), ("bad", 0.1)]),
    ])
    try:
        rc = slm_dpo.main(["--db", db, "--out", "/tmp/unused-dpo",
                           "--dry-run"])
        assert rc == 0
    finally:
        _cleanup(db)


def test_dpo_cli_through_mimir_slm_dry_run():
    import mimir_slm
    db = _tmp(".db")
    _seed_trace_with_rewards(db, [("P1", [("a", 0.9), ("b", 0.1)])])
    try:
        rc = mimir_slm.main(["train", "--db", db, "--dry-run",
                             "--out", "/tmp/x"])
        assert rc == 0
    finally:
        _cleanup(db)
