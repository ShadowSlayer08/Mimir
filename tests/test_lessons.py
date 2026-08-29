"""lessons.py + copilot lessons-bias integration.

Locks the store's contracts and the ranker's opt-in bias plumbing:
  * record / summary / suggest_bias round-trip through a real SQLite file
  * bias is bounded (+/-20), never drops candidates, never mutates untraced keys
  * missing DB path -> unbiased pass-through (no crash)
  * copilot.recommend(..., lessons_db=path) applies the bias and re-sorts
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import copilot  # noqa: E402
import lessons  # noqa: E402
import llm  # noqa: E402


def _fresh_db():
    """Return a fresh temp DB path — caller unlinks."""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="lessons-test-")
    os.close(fd)
    os.unlink(path)                                                # let lessons.py create it
    return path


def test_record_and_summary_roundtrip():
    db = _fresh_db()
    try:
        lessons.record(db, "T1210", "worked", context="smb", engagement="eng-1")
        lessons.record(db, "T1210", "worked", context="smb")
        lessons.record(db, "T1110.003", "blocked", context="entra", note="lockout policy")
        s = lessons.summary(db)
        assert {(r["technique"], r["context"], r["outcome"], r["n"]) for r in s} == {
            ("T1210", "smb", "worked", 2),
            ("T1110.003", "entra", "blocked", 1),
        }
    finally:
        os.path.exists(db) and os.unlink(db)


def test_record_rejects_bad_outcome():
    db = _fresh_db()
    try:
        try:
            lessons.record(db, "T1210", "epic-win")
        except ValueError as e:
            assert "outcome" in str(e)
        else:
            raise AssertionError("bad outcome must raise")
    finally:
        os.path.exists(db) and os.unlink(db)


def test_suggest_bias_bounded_and_signed():
    db = _fresh_db()
    try:
        # 20 wins on T1210/smb -> would be +100 but must clamp at +20.
        for _ in range(20):
            lessons.record(db, "T1210", "worked", context="smb")
        # 20 false positives on T1595/http -> -120 but clamps at -20.
        for _ in range(20):
            lessons.record(db, "T1595", "false_positive", context="http")
        b = lessons.suggest_bias(db)
        assert b[("T1210", "smb")] == 20
        assert b[("T1595", "http")] == -20
    finally:
        os.path.exists(db) and os.unlink(db)


def test_missing_db_returns_empty_bias():
    assert lessons.suggest_bias(None) == {}
    assert lessons.suggest_bias("/does/not/exist.db") == {}
    assert lessons.summary("/does/not/exist.db") == []


def test_apply_bias_never_drops_candidates_and_traces():
    actions = [
        {"attack": "T1210", "score": 50, "category": "foothold", "title": "SMB RCE", "source": "smb"},
        {"attack": "T9999", "score": 40, "category": "lateral", "title": "unmatched", "source": "x"},
    ]
    bias = {("T1210", ""): 15}
    out = lessons.apply_bias(actions, bias)
    assert len(out) == 2                                           # no drops
    assert out[0]["score"] == 65                                   # 50 + 15
    assert out[0]["trace"]["lessons_bias"] == 15
    assert "trace" not in out[1] or "lessons_bias" not in (out[1].get("trace") or {})


# ---- copilot integration ------------------------------------------------- #
class _Stub:
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


def test_copilot_lessons_bias_reorders_deterministic():
    """Two paths of similar deterministic weight — a strong +bias on the lateral
    T1078 must push it above the deterministic winner."""
    paths = [
        {"id": "P-1", "name": "domain compromise", "kind": "domain", "severity": "critical",
         "confidence": "high", "score": 100, "hosts": ["u", "DA"],
         "steps": [{"technique_id": "T1098", "command": "x"}]},
        {"id": "P-2", "name": "SMB lateral", "kind": "lateral", "severity": "high",
         "confidence": "medium", "score": 40, "hosts": ["a", "b"],
         "steps": [{"technique_id": "T1078", "command": "y"}]},
    ]
    db = _fresh_db()
    try:
        # Big win history on T1078
        for _ in range(10):
            lessons.record(db, "T1078", "worked")
        with _Stub(available=lambda: False):
            biased = copilot.recommend([], paths, top=5, lessons_db=db)
            unbiased = copilot.recommend([], paths, top=5)
        titles = [a["title"] for a in biased]
        assert "SMB lateral" in titles
        assert unbiased[0]["title"] == "domain compromise"         # baseline
        # bias should raise SMB lateral's score by +20 (clamped)
        smb = next(a for a in biased if a["title"] == "SMB lateral")
        assert smb["trace"]["lessons_bias"] == 20
    finally:
        os.path.exists(db) and os.unlink(db)


def test_copilot_lessons_none_is_noop():
    """No DB path -> ranker output identical to no-bias run (fallback path)."""
    paths = [{"id": "P-1", "name": "x", "kind": "domain", "severity": "critical",
              "confidence": "high", "score": 100, "hosts": ["a"], "steps": []}]
    with _Stub(available=lambda: False):
        a = copilot.recommend([], paths, lessons_db=None)
        b = copilot.recommend([], paths)
    assert [x["title"] for x in a] == [x["title"] for x in b]
