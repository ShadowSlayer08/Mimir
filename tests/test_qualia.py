"""qualia.py + LLM-first copilot: the offline-safety and validation contracts.

Locks the invariants that make the whole engine LLM-first safely:
  * offline (llm.available() == False)                     -> deterministic fallback
  * LLM present but returns None / invalid shape / raises  -> deterministic fallback
  * LLM present and returns a valid shape                  -> LLM output applied
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import copilot  # noqa: E402
import llm  # noqa: E402
import qualia  # noqa: E402


class _Stub:
    """Swap llm module attributes; restore on __exit__."""
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


_PATHS = [
    {"id": "AD-1", "name": "user -> DA", "kind": "domain", "severity": "critical",
     "confidence": "high", "score": 110, "hosts": ["u", "DA"],
     "steps": [{"technique_id": "T1098", "command": "certipy"}]},
    {"id": "L-1", "name": "lateral", "kind": "lateral", "severity": "medium",
     "confidence": "medium", "score": 40, "hosts": ["a", "b"],
     "steps": [{"technique_id": "T1078", "command": "x"}]},
]


# ---- qualia.decide contract --------------------------------------------- #
def test_decide_offline_uses_fallback():
    with _Stub(available=lambda: False):
        out = qualia.decide("x", "prompt", lambda: {"note": "fallback"})
    assert out == {"note": "fallback"}


def test_decide_llm_none_falls_back():
    with _Stub(available=lambda: True, pick=lambda role="adviser": "m",
               generate_json=lambda *a, **k: None):
        out = qualia.decide("x", "p", lambda: {"note": "fb"})
    assert out == {"note": "fb"}


def test_decide_validator_rejects_bad_shape():
    with _Stub(available=lambda: True, pick=lambda role="adviser": "m",
               generate_json=lambda *a, **k: {"wrong": 1}):
        out = qualia.decide("x", "p", lambda: {"note": "fb"},
                            validator=lambda o: "right" in o)
    assert out == {"note": "fb"}, "validator failure MUST fall back"


def test_decide_swallows_exceptions():
    def _boom(*a, **k):
        raise RuntimeError("nope")
    with _Stub(available=lambda: True, pick=lambda role="adviser": "m",
               generate_json=_boom):
        out = qualia.decide("x", "p", lambda: "fb")
    assert out == "fb", "decide() must never raise"


def test_decide_returns_llm_when_valid():
    good = {"ranked": [{"i": 0, "score": 88, "why": "ok"}]}
    with _Stub(available=lambda: True, pick=lambda role="adviser": "m",
               generate_json=lambda *a, **k: good):
        out = qualia.decide("x", "p", lambda: "fb",
                            validator=lambda o: isinstance(o, dict) and "ranked" in o)
    assert out is good


# ---- copilot LLM-first -> deterministic fallback ------------------------ #
def test_copilot_offline_matches_deterministic():
    with _Stub(available=lambda: False):
        out = copilot.recommend([], _PATHS)
    det = copilot._deterministic_recommend([], _PATHS)
    assert [(a["title"], a["rank"]) for a in out] == [(a["title"], a["rank"]) for a in det]


def test_copilot_llm_reorders_pool():
    # Model puts the lateral path FIRST (contra the deterministic weighting) — the
    # LLM branch must honour that ordering.
    canned = {"ranked": [{"i": 1, "score": 95, "why": "cheap lateral leverage"},
                         {"i": 0, "score": 90, "why": "objective but noisy"}]}
    with _Stub(available=lambda: True, pick=lambda role="adviser": "m",
               generate_json=lambda *a, **k: canned):
        out = copilot.recommend([], _PATHS)
    assert out[0]["title"] == "lateral" and out[0]["rank"] == 1
    assert out[1]["title"] == "user -> DA"
    assert out[0]["trace"]["source"] == "llm"
    assert out[0]["why"] == "cheap lateral leverage"           # LLM narration wins
    assert out[0]["score"] == 95


def test_copilot_llm_bad_index_falls_back():
    canned = {"ranked": [{"i": 999, "score": 90, "why": "invalid"}]}
    with _Stub(available=lambda: True, pick=lambda role="adviser": "m",
               generate_json=lambda *a, **k: canned):
        out = copilot.recommend([], _PATHS)
    det = copilot._deterministic_recommend([], _PATHS)
    assert [a["title"] for a in out] == [a["title"] for a in det]


def test_copilot_llm_duplicate_indices_fall_back():
    canned = {"ranked": [{"i": 0, "score": 90, "why": "a"},
                         {"i": 0, "score": 80, "why": "duplicate!"}]}
    with _Stub(available=lambda: True, pick=lambda role="adviser": "m",
               generate_json=lambda *a, **k: canned):
        out = copilot.recommend([], _PATHS)
    assert out == copilot._deterministic_recommend([], _PATHS)


def test_killchain_narrative_offline_uses_fallback():
    import killchain
    st = {"id": 3, "name": "Delivery & Exploitation",
          "staged_steps": [{"tactic": "Initial Access", "technique_id": "T1190",
                            "host": "web", "path": "AP-1"}],
          "findings": [], "objective": "Stage initial-access steps."}
    with _Stub(available=lambda: False):
        assert killchain._stage_narrative(st, st["objective"]) == "Stage initial-access steps."


def test_killchain_narrative_empty_stage_short_circuits():
    """A stage with no staged steps and no findings shouldn't waste an LLM call."""
    import killchain
    # If the LLM branch were hit here we'd raise from generate; the fact that it
    # returns the fallback proves the short-circuit worked (no LLM call at all).
    def _boom(*a, **k):
        raise AssertionError("must not call LLM for empty stage")
    with _Stub(available=lambda: True, pick=lambda role="narrator": "m", generate=_boom):
        out = killchain._stage_narrative({"id": 5, "name": "x", "staged_steps": [],
                                          "findings": []}, "fallback prose")
    assert out == "fallback prose"


def test_copilot_empty_pool_stays_empty():
    with _Stub(available=lambda: True, pick=lambda role="adviser": "m",
               generate_json=lambda *a, **k: {"ranked": [{"i": 0, "score": 1, "why": "x"}]}):
        assert copilot.recommend([], []) == []                 # empty pool short-circuits
