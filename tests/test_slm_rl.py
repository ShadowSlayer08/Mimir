"""Phase 24 — slm.reward / slm.distill / slm.rl / slm.bridge + CLI.

Covers:
  * reward.ensure_reward_column + score_all math (weighted, clipped to [-1,1])
  * reward.compute_reward branches: curator / lesson / autopilot / validator / peer
  * bridge.export_dump/import_dump roundtrip; peer rows always outcome=NULL
  * bridge.query_peer returns None when the HMAC bridge is unavailable
  * distill.build_distillation_rows emits student rows w/o teacher calls
  * rl._normalise_group_rewards computes z-scores; degenerate group -> zeros
  * rl.recipe() prints the full GRPO script (sanity check)
  * mimir-slm reward / distill / rl recipe / peer-sync status CLI paths
"""
import io
import json
import os
import sqlite3
import sys
import tempfile

# Force LLM offline so teacher re-asks short-circuit cleanly in tests.
os.environ["OLLAMA_HOST"] = "http://127.0.0.1:1"
os.environ["MIMIR_LLM_TIMEOUT"] = "0.5"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from slm import trace as slm_trace     # noqa: E402
from slm import reward as slm_reward   # noqa: E402
from slm import bridge as slm_bridge   # noqa: E402
from slm import distill as slm_distill # noqa: E402
from slm import rl as slm_rl           # noqa: E402
import mimir_slm                        # noqa: E402


def _tmp(suffix=""):
    fd, p = tempfile.mkstemp(suffix=suffix, prefix="slm-rl-test-")
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


def _with_env(db):
    prev = os.environ.get("MIMIR_SLM_TRACE_DB")
    os.environ["MIMIR_SLM_TRACE_DB"] = db or ""
    return prev


def _restore_env(prev):
    if prev is None:
        os.environ.pop("MIMIR_SLM_TRACE_DB", None)
    else:
        os.environ["MIMIR_SLM_TRACE_DB"] = prev


def _seed(db, rows):
    """Insert hand-crafted qualia_trace rows. Each row is a kwargs dict."""
    slm_trace._connect(db).close()      # ensure schema
    for r in rows:
        slm_trace.record(
            r.get("kind", "k"), r.get("role", "adviser"),
            r.get("prompt", "p"),
            llm_result=r.get("llm_result"),
            fallback_result=r.get("fallback_result"),
            used_fallback=r.get("used_fallback", False),
            system=r.get("system"),
            validator_passed=r.get("validator_passed"),
            model=r.get("model"),
            engagement_id=r.get("engagement_id"))


# --------------------------------------------------------------------------- #
# reward.ensure_reward_column — idempotent ALTER
# --------------------------------------------------------------------------- #
def test_reward_column_is_added_idempotently():
    db = _tmp(".db"); prev = _with_env(db)
    try:
        _seed(db, [{"prompt": "p"}])
        slm_reward.ensure_reward_column(db)
        slm_reward.ensure_reward_column(db)       # second call must not error
        con = sqlite3.connect(db)
        try:
            cols = {r[1] for r in con.execute(
                "PRAGMA table_info(qualia_trace)").fetchall()}
        finally:
            con.close()
        assert "reward" in cols and "reward_breakdown" in cols
    finally:
        _restore_env(prev); _cleanup(db)


# --------------------------------------------------------------------------- #
# reward.compute_reward — each branch contributes correctly + clipped
# --------------------------------------------------------------------------- #
def test_reward_curator_worked_boosts_signal():
    tr = {"prompt": "p", "llm_result": "r", "outcome": "worked",
          "validator_passed": None, "engagement_id": None}
    r, br = slm_reward.compute_reward(tr)
    assert r > 0
    assert "curator_worked" in br


def test_reward_curator_muted_penalises():
    tr = {"prompt": "p", "outcome": "muted", "validator_passed": None}
    r, br = slm_reward.compute_reward(tr)
    assert r < 0
    assert "curator_muted" in br


def test_reward_validator_adds_signal():
    tr_pass = {"prompt": "p", "outcome": None, "validator_passed": True}
    tr_fail = {"prompt": "p", "outcome": None, "validator_passed": False}
    assert slm_reward.compute_reward(tr_pass)[0] > 0
    assert slm_reward.compute_reward(tr_fail)[0] < 0


def test_reward_peer_signal_folds_in():
    tr = {"prompt": "p", "outcome": None, "validator_passed": None}
    base_r, _ = slm_reward.compute_reward(tr, peer_signal=0)
    ag_r,   _ = slm_reward.compute_reward(tr, peer_signal=+1)
    dis_r,  _ = slm_reward.compute_reward(tr, peer_signal=-1)
    assert ag_r > base_r
    assert dis_r < base_r


def test_reward_is_clipped_to_unit_interval():
    # Stack every positive signal we can.
    tr = {"prompt": "exploit T1210 on 10.0.0.5",
          "outcome": "worked",
          "validator_passed": True}
    # Also seed a lessons DB.
    lessons_db = _tmp(".db")
    con = sqlite3.connect(lessons_db); con.execute(
        "CREATE TABLE lessons(id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "ts TEXT, technique TEXT, outcome TEXT, context TEXT, "
        "engagement TEXT, note TEXT)"); con.execute(
        "INSERT INTO lessons(technique,outcome,context) VALUES(?,?,?)",
        ("T1210", "worked", "")); con.commit(); con.close()
    try:
        r, _ = slm_reward.compute_reward(tr, lessons_db=lessons_db,
                                         peer_signal=1,
                                         weights={"curator_worked": 5.0})
        assert -1.0 <= r <= 1.0
    finally:
        _cleanup(lessons_db)


def test_reward_weights_override_from_env_and_arg():
    prev = os.environ.pop("MIMIR_SLM_REWARD_WEIGHTS", None)
    try:
        os.environ["MIMIR_SLM_REWARD_WEIGHTS"] = "curator_worked=0.1"
        w = slm_reward.load_weights()
        assert abs(w["curator_worked"] - 0.1) < 1e-9
        w = slm_reward.load_weights({"curator_worked": 0.3})
        assert abs(w["curator_worked"] - 0.3) < 1e-9
    finally:
        os.environ.pop("MIMIR_SLM_REWARD_WEIGHTS", None)
        if prev is not None:
            os.environ["MIMIR_SLM_REWARD_WEIGHTS"] = prev


# --------------------------------------------------------------------------- #
# reward.score_all — persists reward column for every row
# --------------------------------------------------------------------------- #
def test_score_all_persists_reward_column():
    db = _tmp(".db"); prev = _with_env(db)
    try:
        _seed(db, [{"prompt": "p1", "llm_result": "a"},
                   {"prompt": "p2", "llm_result": "b", "validator_passed": True}])
        slm_trace.set_outcome(db, 1, "worked")
        n, stats = slm_reward.score_all(db)
        assert n == 2
        assert stats["positive"] >= 1
        con = sqlite3.connect(db)
        try:
            rewards = [r[0] for r in con.execute(
                "SELECT reward FROM qualia_trace ORDER BY id").fetchall()]
        finally:
            con.close()
        assert all(r is not None for r in rewards)
    finally:
        _restore_env(prev); _cleanup(db)


# --------------------------------------------------------------------------- #
# bridge — export / import roundtrip; peer rows outcome=NULL
# --------------------------------------------------------------------------- #
def test_bridge_export_roundtrip_through_import():
    src_db = _tmp(".db"); dst_db = _tmp(".db")
    prev = _with_env(src_db)
    try:
        _seed(src_db, [{"prompt": "p-worked", "llm_result": "r1"},
                       {"prompt": "p-muted",  "llm_result": "r2"}])
        slm_trace.set_outcome(src_db, 1, "worked")
        slm_trace.set_outcome(src_db, 2, "muted")

        buf = io.StringIO()
        n_out = slm_bridge.export_dump(src_db, buf, only_outcome="worked")
        assert n_out == 1
        buf.seek(0)

        n_in = slm_bridge.import_dump(dst_db, buf)
        assert n_in == 1
        rows = slm_trace.recent(dst_db, limit=5)
        assert len(rows) == 1
        # Imported as peer:* with outcome unset.
        assert rows[0]["kind"].startswith("peer:")
        assert rows[0]["outcome"] is None
    finally:
        _restore_env(prev); _cleanup(src_db, dst_db)


def test_bridge_query_peer_returns_none_when_offline():
    # No CRUCIBLE_* env set → bridge is unavailable.
    for k in ("CRUCIBLE_URL", "CRUCIBLE_API_KEY"):
        os.environ.pop(k, None)
    assert slm_bridge.available() is False
    assert slm_bridge.query_peer("prompt", "response") is None


def test_bridge_status_reports_offline():
    for k in ("CRUCIBLE_URL", "CRUCIBLE_API_KEY"):
        os.environ.pop(k, None)
    s = slm_bridge.peer_status()
    assert s["available"] is False


# --------------------------------------------------------------------------- #
# distill — build rows without touching the teacher
# --------------------------------------------------------------------------- #
def test_distill_rows_emit_without_teacher_when_disabled():
    db = _tmp(".db"); prev = _with_env(db)
    try:
        _seed(db, [{"prompt": "p1", "llm_result": "r1"},
                   {"prompt": "p2", "fallback_result": "r2", "used_fallback": True}])
        slm_trace.set_outcome(db, 1, "worked")
        slm_trace.set_outcome(db, 2, "worked")
        rows = list(slm_distill.build_distillation_rows(
            db, only_outcome="worked", include_teacher=False))
        assert len(rows) == 2
        for r in rows:
            assert r["teacher"] == ""
            assert r["student"] in ("r1", "r2")
            assert r["source"] == "self-distill"
    finally:
        _restore_env(prev); _cleanup(db)


# --------------------------------------------------------------------------- #
# rl — z-score normalisation; recipe printer
# --------------------------------------------------------------------------- #
def test_rl_normalise_group_rewards_zscores_samples():
    samples = [{"reward": 0.0}, {"reward": 0.5}, {"reward": 1.0}]
    slm_rl._normalise_group_rewards(samples)
    advs = [s["advantage"] for s in samples]
    assert sum(advs) < 1e-6         # z-scored -> mean 0
    assert advs[0] < advs[1] < advs[2]


def test_rl_normalise_group_rewards_degenerate_group():
    samples = [{"reward": None}, {"reward": None}]
    slm_rl._normalise_group_rewards(samples)
    assert all(s["advantage"] == 0.0 for s in samples)


def test_rl_recipe_mentions_grpo_and_qwen():
    text = slm_rl.recipe()
    assert "GRPO" in text
    assert "Qwen" in text or "qwen" in text
    assert "mimir-slm" in text


# --------------------------------------------------------------------------- #
# CLI — happy paths
# --------------------------------------------------------------------------- #
def test_cli_reward_scores_rows():
    db = _tmp(".db"); prev = _with_env(db)
    try:
        _seed(db, [{"prompt": "p", "llm_result": "r"}])
        slm_trace.set_outcome(db, 1, "worked")
        rc = mimir_slm.main(["reward", "--db", db])
        assert rc == 0
    finally:
        _restore_env(prev); _cleanup(db)


def test_cli_distill_no_teacher_writes_file():
    db = _tmp(".db"); prev = _with_env(db); out = _tmp(".jsonl")
    try:
        _seed(db, [{"prompt": "p", "llm_result": "r"}])
        slm_trace.set_outcome(db, 1, "worked")
        rc = mimir_slm.main(["distill", "--db", db, out, "--no-teacher"])
        assert rc == 0
        with open(out, encoding="utf-8") as fh:
            rows = [json.loads(ln) for ln in fh if ln.strip()]
        assert len(rows) == 1 and rows[0]["source"] == "self-distill"
    finally:
        _restore_env(prev); _cleanup(db, out)


def test_cli_rl_recipe_runs():
    rc = mimir_slm.main(["rl", "recipe"])
    assert rc == 0


def test_cli_peer_sync_status_reports_offline():
    for k in ("CRUCIBLE_URL", "CRUCIBLE_API_KEY"):
        os.environ.pop(k, None)
    rc = mimir_slm.main(["peer-sync", "status"])
    assert rc == 0


def test_cli_peer_sync_export_import_roundtrip():
    src_db = _tmp(".db"); dst_db = _tmp(".db")
    prev = _with_env(src_db); dump = _tmp(".jsonl")
    try:
        _seed(src_db, [{"prompt": "p", "llm_result": "r"}])
        slm_trace.set_outcome(src_db, 1, "worked")
        rc = mimir_slm.main(["peer-sync", "export", "--db", src_db, dump,
                             "--only-outcome", "worked"])
        assert rc == 0
        rc = mimir_slm.main(["peer-sync", "import", "--db", dst_db, dump])
        assert rc == 0
        assert len(slm_trace.recent(dst_db, limit=5)) == 1
    finally:
        _restore_env(prev); _cleanup(src_db, dst_db, dump)
