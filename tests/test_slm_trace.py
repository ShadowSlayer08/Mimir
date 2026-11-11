"""Phase 23 — slm.trace sink, qualia instrumentation, mimir_slm CLI.

Covers:
  * Sink is opt-in: no env var -> record() returns False and no DB appears.
  * record() round-trips every field; redacts secret-shaped tokens.
  * stats() counts rows, computes fallback_rate + readiness score.
  * recent() returns rows newest-first with filter by kind.
  * set_outcome() enforces the allowed label set.
  * export_jsonl() emits only curator-OK rows; drops fallback-only
    uncurated rows; honors --only-outcome.
  * qualia.decide + qualia.prose write exactly one trace per call.
  * mimir_slm status + trace + export + curate CLI happy paths.
  * train / eval / promote placeholders exit 0 without failing.
"""
import io
import json
import os
import sys
import tempfile

# Keep the LLM offline in-case something probes it during import.
os.environ["OLLAMA_HOST"] = "http://127.0.0.1:1"
os.environ["MIMIR_LLM_TIMEOUT"] = "0.5"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from slm import trace as slm_trace    # noqa: E402
import mimir_slm                       # noqa: E402
import qualia                          # noqa: E402


def _tmp(suffix=""):
    fd, p = tempfile.mkstemp(suffix=suffix, prefix="slm-trace-test-")
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


def _with_env(db, extra=None):
    """Context-manager-ish — set env, return a prior snapshot, caller restores."""
    prev = {
        "MIMIR_SLM_TRACE_DB": os.environ.get("MIMIR_SLM_TRACE_DB"),
        "MIMIR_SLM_TRACE_ENGAGEMENT": os.environ.get("MIMIR_SLM_TRACE_ENGAGEMENT"),
    }
    os.environ["MIMIR_SLM_TRACE_DB"] = db or ""
    if extra:
        os.environ.update(extra)
    return prev


def _restore_env(prev):
    for k, v in prev.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# --------------------------------------------------------------------------- #
# Opt-in
# --------------------------------------------------------------------------- #
def test_sink_is_optin_when_env_unset():
    prev = _with_env("")
    try:
        assert slm_trace.enabled() is False
        ok = slm_trace.record("rank-actions", "adviser", "prompt",
                              {"rank": 1}, None, False)
        assert ok is False
    finally:
        _restore_env(prev)


def test_sink_records_and_round_trips():
    db = _tmp(".db"); prev = _with_env(db)
    try:
        ok = slm_trace.record(
            "rank-actions", "adviser", "rank these: A,B,C",
            llm_result={"ranking": [2, 0, 1]}, fallback_result=None,
            used_fallback=False, system="syz", validator_passed=True,
            model="qwen2.5:7b", engagement_id="acme-q3")
        assert ok is True
        rows = slm_trace.recent(db, limit=5)
        assert len(rows) == 1
        r = rows[0]
        assert r["kind"] == "rank-actions"
        assert r["role"] == "adviser"
        assert r["used_fallback"] is False
        assert r["outcome"] is None
    finally:
        _restore_env(prev); _cleanup(db)


# --------------------------------------------------------------------------- #
# Redaction — vault.redact runs over every text field
# --------------------------------------------------------------------------- #
def test_sink_redacts_secret_shapes():
    db = _tmp(".db"); prev = _with_env(db)
    try:
        slm_trace.record(
            "x", "adviser",
            "api_key=sk-ab1cdefghijklmnopqrstuvwx1234567890 password=hunter2",
            llm_result={"found": "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABC"},
            fallback_result=None, used_fallback=False,
            validator_passed=None)
        row = slm_trace.recent(db, limit=1)[0]
        assert "sk-ab1c" not in row["prompt"]
        assert "hunter2" not in row["prompt"]
        # The result column is a stringified JSON blob but still redacted.
        assert "ghp_abcdefghij" not in row["result"]
    finally:
        _restore_env(prev); _cleanup(db)


# --------------------------------------------------------------------------- #
# Stats + readiness
# --------------------------------------------------------------------------- #
def test_stats_counts_rows_and_curated_outcomes():
    db = _tmp(".db"); prev = _with_env(db)
    try:
        for i in range(3):
            slm_trace.record(f"k{i}", "adviser", f"p{i}",
                             llm_result={"ok": True}, fallback_result=None,
                             used_fallback=False, validator_passed=True)
        slm_trace.record("fb", "adviser", "pf", None,
                         fallback_result={"n": 1}, used_fallback=True,
                         validator_passed=False)
        slm_trace.set_outcome(db, 1, "worked")
        slm_trace.set_outcome(db, 2, "no_signal")
        s = slm_trace.stats(db)
        assert s["total"] == 4
        assert s["curated"]["worked"] == 1
        assert s["curated"]["no_signal"] == 1
        assert 0.0 <= s["readiness"] <= 1.0
        # fallback_rate = 1 fallback / 4 rows = 0.25
        assert abs(s["fallback_rate"] - 0.25) < 1e-6
    finally:
        _restore_env(prev); _cleanup(db)


def test_recent_filters_by_kind_and_returns_newest_first():
    db = _tmp(".db"); prev = _with_env(db)
    try:
        slm_trace.record("rank", "adviser", "p1", {"r": 1}, None, False)
        slm_trace.record("rank", "adviser", "p2", {"r": 2}, None, False)
        slm_trace.record("narrate", "narrator", "p3", "ok", None, False)
        rank_rows = slm_trace.recent(db, limit=5, kind="rank")
        assert [r["kind"] for r in rank_rows] == ["rank", "rank"]
        assert rank_rows[0]["id"] > rank_rows[1]["id"]
    finally:
        _restore_env(prev); _cleanup(db)


def test_set_outcome_rejects_bad_labels():
    db = _tmp(".db"); prev = _with_env(db)
    try:
        slm_trace.record("k", "adviser", "p", {"ok": True}, None, False)
        try:
            slm_trace.set_outcome(db, 1, "LOOKS_GREAT")
            raise AssertionError("expected ValueError")
        except ValueError:
            pass
    finally:
        _restore_env(prev); _cleanup(db)


# --------------------------------------------------------------------------- #
# Export JSONL
# --------------------------------------------------------------------------- #
def test_export_jsonl_prefers_llm_rows_drops_uncurated_fallback():
    db = _tmp(".db"); prev = _with_env(db)
    try:
        slm_trace.record("k", "adviser", "p-llm",
                         llm_result={"r": 1}, fallback_result=None,
                         used_fallback=False)
        slm_trace.record("k", "adviser", "p-fb",
                         llm_result=None, fallback_result={"r": 2},
                         used_fallback=True)
        slm_trace.record("k", "adviser", "p-fb-worked",
                         llm_result=None, fallback_result={"r": 3},
                         used_fallback=True)
        slm_trace.set_outcome(db, 3, "worked")

        buf = io.StringIO()
        n = slm_trace.export_jsonl(db, buf)
        # llm row + worked fallback row = 2; raw fallback row dropped
        assert n == 2
        rows = [json.loads(ln) for ln in buf.getvalue().splitlines()]
        prompts = {r["prompt"] for r in rows}
        assert "p-llm" in prompts and "p-fb-worked" in prompts and "p-fb" not in prompts
    finally:
        _restore_env(prev); _cleanup(db)


def test_export_jsonl_only_outcome_filter():
    db = _tmp(".db"); prev = _with_env(db)
    try:
        slm_trace.record("k", "adviser", "p1", {"r": 1}, None, False)
        slm_trace.record("k", "adviser", "p2", {"r": 2}, None, False)
        slm_trace.set_outcome(db, 1, "worked")
        buf = io.StringIO()
        n = slm_trace.export_jsonl(db, buf, only_outcome="worked")
        assert n == 1
    finally:
        _restore_env(prev); _cleanup(db)


# --------------------------------------------------------------------------- #
# qualia instrumentation — one trace per call, correct fallback flag
# --------------------------------------------------------------------------- #
def _force_llm_offline():
    """Monkey-patch qualia's bound llm module so llm.available() is False.

    The module-load ordering in run_tests.py means the real Ollama host was
    already cached in llm.DEFAULT_HOST by the time this module sets the
    OLLAMA_HOST env — so just setting the env is not enough to force the
    fallback branch when a real local daemon is running. Patching available()
    on the exact module instance qualia.py imported closes that gap.

    Returns a zero-arg undo callable.
    """
    import llm as _real_llm
    original = _real_llm.available
    _real_llm.available = lambda: False
    return lambda: setattr(_real_llm, "available", original)


def test_qualia_decide_writes_one_trace_fallback_branch():
    db = _tmp(".db"); prev = _with_env(db); undo = _force_llm_offline()
    try:
        out = qualia.decide("rank-actions", "prompt",
                            lambda: {"ok": True, "src": "det"})
        assert out == {"ok": True, "src": "det"}
        rows = slm_trace.recent(db, limit=5)
        assert len(rows) == 1
        assert rows[0]["used_fallback"] is True
    finally:
        undo(); _restore_env(prev); _cleanup(db)


def test_qualia_prose_writes_one_trace_fallback_branch():
    db = _tmp(".db"); prev = _with_env(db); undo = _force_llm_offline()
    try:
        out = qualia.prose("narrate-stage", "prompt",
                           lambda: "deterministic summary")
        assert out == "deterministic summary"
        rows = slm_trace.recent(db, limit=5)
        assert len(rows) == 1
        assert rows[0]["used_fallback"] is True
    finally:
        undo(); _restore_env(prev); _cleanup(db)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_cli_status_handles_absent_db(capsys=None):
    prev = _with_env("")
    try:
        rc = mimir_slm.main(["status"])
        assert rc == 1
    finally:
        _restore_env(prev)


def test_cli_status_and_trace_and_export_roundtrip(tmp_path=None):
    db = _tmp(".db"); prev = _with_env(db)
    out_path = _tmp(".jsonl")
    try:
        slm_trace.record("rank", "adviser", "p", {"r": 1}, None, False)
        rc = mimir_slm.main(["status", "--db", db])
        assert rc == 0
        rc = mimir_slm.main(["trace", "--db", db, "--limit", "5"])
        assert rc == 0
        rc = mimir_slm.main(["export", "--db", db, out_path])
        assert rc == 0
        with open(out_path, encoding="utf-8") as fh:
            lines = [ln for ln in fh if ln.strip()]
        assert len(lines) == 1
    finally:
        _restore_env(prev); _cleanup(db, out_path)


def test_cli_curate_updates_outcome():
    db = _tmp(".db"); prev = _with_env(db)
    try:
        slm_trace.record("k", "adviser", "p", {"r": 1}, None, False)
        rc = mimir_slm.main(["curate", "--db", db, "1", "worked"])
        assert rc == 0
        rows = slm_trace.recent(db, limit=1)
        assert rows[0]["outcome"] == "worked"
    finally:
        _restore_env(prev); _cleanup(db)


def test_cli_placeholders_do_not_fail():
    for sub in ("train", "eval", "promote"):
        assert mimir_slm.main([sub]) == 0
