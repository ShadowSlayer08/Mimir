"""Phase 27 — slm.promote pin manager + llm.pick hook.

Covers:
  * load_pins / save_pins round-trip with role filter
  * promote(tag, roles=...) defaults to planner+adviser; --role 'all'
    expands; unknown roles raise ValueError
  * rollback(role) removes one; rollback(role=None) wipes the file
  * pin_for(role) honors the configured path
  * llm.pick(role) uses the pin between env override and preference table
  * CLI: mimir-slm promote <tag>; --show; --rollback; --role all
"""
import json
import os
import sys
import tempfile

os.environ["OLLAMA_HOST"] = "http://127.0.0.1:1"
os.environ["MIMIR_LLM_TIMEOUT"] = "0.5"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from slm import promote as slm_promote          # noqa: E402
import mimir_slm                                 # noqa: E402


def _tmp(suffix=".json"):
    fd, p = tempfile.mkstemp(suffix=suffix, prefix="pins-")
    os.close(fd)
    os.unlink(p)      # we want the path NOT to exist initially
    return p


def _cleanup(path):
    if path and os.path.exists(path):
        try:
            os.unlink(path)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# File I/O round-trip
# --------------------------------------------------------------------------- #
def test_load_pins_missing_file_returns_empty_dict():
    p = _tmp()
    assert slm_promote.load_pins(p) == {}


def test_save_and_load_pins_roundtrip():
    p = _tmp()
    try:
        slm_promote.save_pins({"planner": "mimir-slm:x",
                               "adviser": "mimir-slm:x"}, path=p)
        loaded = slm_promote.load_pins(p)
        assert loaded == {"planner": "mimir-slm:x", "adviser": "mimir-slm:x"}
    finally:
        _cleanup(p)


def test_save_pins_drops_unknown_roles_silently():
    p = _tmp()
    try:
        slm_promote.save_pins({"planner": "m", "nonsense": "ignore"}, path=p)
        loaded = slm_promote.load_pins(p)
        assert loaded == {"planner": "m"}
    finally:
        _cleanup(p)


def test_load_pins_malformed_file_is_empty_dict():
    p = _tmp()
    try:
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("this is not json")
        assert slm_promote.load_pins(p) == {}
    finally:
        _cleanup(p)


# --------------------------------------------------------------------------- #
# promote / rollback / show
# --------------------------------------------------------------------------- #
def test_promote_defaults_to_planner_and_adviser():
    p = _tmp()
    try:
        after = slm_promote.promote("mimir-slm:1", path=p)
        assert after == {"planner": "mimir-slm:1", "adviser": "mimir-slm:1"}
    finally:
        _cleanup(p)


def test_promote_with_role_all_fills_every_role():
    p = _tmp()
    try:
        after = slm_promote.promote("mimir-slm:1",
                                    roles=slm_promote._ROLES, path=p)
        assert set(after.keys()) == set(slm_promote._ROLES)
    finally:
        _cleanup(p)


def test_promote_rejects_empty_tag():
    try:
        slm_promote.promote("", path=_tmp())
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_promote_rejects_unknown_role():
    try:
        slm_promote.promote("x", roles=("bogus",), path=_tmp())
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_rollback_single_role_leaves_others():
    p = _tmp()
    try:
        slm_promote.promote("m", roles=("planner", "adviser"), path=p)
        after = slm_promote.rollback(role="planner", path=p)
        assert after == {"adviser": "m"}
    finally:
        _cleanup(p)


def test_rollback_all_removes_file():
    p = _tmp()
    try:
        slm_promote.promote("m", path=p)
        assert os.path.exists(p)
        slm_promote.rollback(path=p)
        assert not os.path.exists(p)
    finally:
        _cleanup(p)


def test_pin_for_returns_configured_tag():
    p = _tmp()
    try:
        slm_promote.promote("mimir-slm:42", roles=("planner",), path=p)
        assert slm_promote.pin_for("planner", path=p) == "mimir-slm:42"
        assert slm_promote.pin_for("narrator", path=p) is None
    finally:
        _cleanup(p)


def test_show_reports_presence_and_pins():
    p = _tmp()
    try:
        slm_promote.promote("m", path=p)
        s = slm_promote.show(path=p)
        assert s["present"] is True
        assert "planner" in s["pins"]
    finally:
        _cleanup(p)


# --------------------------------------------------------------------------- #
# llm.pick hook — pin is used between env and preferences
# --------------------------------------------------------------------------- #
def test_llm_pick_reads_pin_file_when_env_unset():
    p = _tmp()
    prev_env = {k: os.environ.pop(k, None)
                for k in ("MIMIR_LLM_MODEL", "VANTAGE_LLM_MODEL",
                          "MIMIR_LLM_PLANNER", "MIMIR_LLM_PINS")}
    try:
        os.environ["MIMIR_LLM_PINS"] = p
        slm_promote.promote("mimir-slm:pinned", roles=("planner",), path=p)
        import llm
        # No env override + no Ollama reachable -> pin wins over empty
        # local_models() (which returns [] on our dead-host test env).
        assert llm.pick("planner") == "mimir-slm:pinned"
    finally:
        for k, v in prev_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        _cleanup(p)


def test_llm_pick_env_override_still_wins_over_pin():
    p = _tmp()
    prev_env = {k: os.environ.pop(k, None)
                for k in ("MIMIR_LLM_MODEL", "VANTAGE_LLM_MODEL",
                          "MIMIR_LLM_PLANNER", "MIMIR_LLM_PINS")}
    try:
        os.environ["MIMIR_LLM_PINS"] = p
        slm_promote.promote("pinned-tag", roles=("planner",), path=p)
        os.environ["MIMIR_LLM_PLANNER"] = "env-override-tag"
        import llm
        # Env override is temporary but stronger than the pin.
        assert llm.pick("planner") == "env-override-tag"
    finally:
        for k, v in prev_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        _cleanup(p)


# --------------------------------------------------------------------------- #
# CLI — mimir-slm promote / --show / --rollback
# --------------------------------------------------------------------------- #
def test_cli_promote_writes_pin_and_show_prints_it():
    p = _tmp()
    prev = os.environ.pop("MIMIR_LLM_PINS", None)
    try:
        os.environ["MIMIR_LLM_PINS"] = p
        rc = mimir_slm.main(["promote", "mimir-slm:cli-test"])
        assert rc == 0
        loaded = slm_promote.load_pins(p)
        assert loaded["planner"] == "mimir-slm:cli-test"
        assert loaded["adviser"] == "mimir-slm:cli-test"
        rc2 = mimir_slm.main(["promote", "--show"])
        assert rc2 == 0
    finally:
        if prev is None:
            os.environ.pop("MIMIR_LLM_PINS", None)
        else:
            os.environ["MIMIR_LLM_PINS"] = prev
        _cleanup(p)


def test_cli_promote_role_all_fills_everything():
    p = _tmp()
    prev = os.environ.pop("MIMIR_LLM_PINS", None)
    try:
        os.environ["MIMIR_LLM_PINS"] = p
        rc = mimir_slm.main(["promote", "mimir-slm:everywhere", "--role", "all"])
        assert rc == 0
        loaded = slm_promote.load_pins(p)
        assert set(loaded.keys()) == set(slm_promote._ROLES)
    finally:
        if prev is None:
            os.environ.pop("MIMIR_LLM_PINS", None)
        else:
            os.environ["MIMIR_LLM_PINS"] = prev
        _cleanup(p)


def test_cli_rollback_clears_pin_file():
    p = _tmp()
    prev = os.environ.pop("MIMIR_LLM_PINS", None)
    try:
        os.environ["MIMIR_LLM_PINS"] = p
        mimir_slm.main(["promote", "tag"])
        rc = mimir_slm.main(["promote", "--rollback"])
        assert rc == 0
        assert not os.path.exists(p)
    finally:
        if prev is None:
            os.environ.pop("MIMIR_LLM_PINS", None)
        else:
            os.environ["MIMIR_LLM_PINS"] = prev
        _cleanup(p)


def test_cli_promote_no_args_returns_usage_error():
    rc = mimir_slm.main(["promote"])
    assert rc == 2
