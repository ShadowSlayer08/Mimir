"""autopilot.py — gate chain, verdict shape, dry-run, resume, command-safety,
   ledger write, authorization flag, and CLI refusal paths.

Every test uses a synthetic engagement (no subprocess fires unless we want it
to), builds the gate chain by calling run() directly, and asserts on the
returned structured verdicts.
"""
import json
import os
import sys
import sqlite3
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import autopilot  # noqa: E402


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _mkstep(**over):
    """Build one path-shape step with safe defaults."""
    base = {"technique_id": "T1046", "host": "10.0.0.5",
            "command": "echo probe", "risk": "safe", "noise": 1, "order": 1}
    base.update(over)
    return base


def _mkeng(steps, kind="recon"):
    return {
        "attack_paths": [{"id": "P-1", "kind": kind, "steps": steps}],
        "modules": [],
    }


def _verdicts(result):
    return [r["verdict"] for r in result["results"]]


def _tmp(suffix=""):
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="autopilot-test-")
    os.close(fd)
    return path


# --------------------------------------------------------------------------- #
# Dry-run: never fires a real subprocess
# --------------------------------------------------------------------------- #
def test_dry_run_never_executes_and_tags_every_step():
    eng = _mkeng([_mkstep(command="echo one"),
                  _mkstep(command="echo two", order=2)])
    out = autopilot.run(eng, dry_run=True)
    vs = _verdicts(out)
    assert vs == ["dry_run", "dry_run"], vs
    assert out["summary"]["started"] == 0
    for r in out["results"]:
        assert "exit_code" not in r


def test_dry_run_log_jsonl_is_tailable_and_resumable():
    log = _tmp(".jsonl")
    try:
        eng = _mkeng([_mkstep(command="echo a")])
        autopilot.run(eng, dry_run=True, log_path=log)
        with open(log, encoding="utf-8") as fh:
            lines = [json.loads(ln) for ln in fh if ln.strip()]
        assert any(r.get("verdict") == "dry_run" for r in lines)
        assert any("summary" in r for r in lines)
        # Resume on the same log must skip every executed_ok/dry_run.
        out2 = autopilot.run(eng, dry_run=True, resume_path=log)
        assert _verdicts(out2) == ["skipped_resume"]
    finally:
        os.unlink(log)


# --------------------------------------------------------------------------- #
# Gate 1 — institutional-TLD hard-block
# --------------------------------------------------------------------------- #
def test_gate_institutional_blocks_gov():
    eng = _mkeng([_mkstep(host="target.gov", command="echo x")])
    out = autopilot.run(eng, dry_run=True)
    assert _verdicts(out) == ["skipped_institutional"]


def test_gate_institutional_blocks_mil_edu_int():
    for h in ("example.mil", "example.edu", "example.int"):
        out = autopilot.run(_mkeng([_mkstep(host=h, command="echo x")]),
                            dry_run=True)
        assert _verdicts(out) == ["skipped_institutional"], h


# --------------------------------------------------------------------------- #
# Gate 2 — ROE scope
# --------------------------------------------------------------------------- #
def test_gate_scope_out_of_scope_rejects():
    rules = {"in_scope": ["10.0.0.0/24"], "out_of_scope": ["10.0.0.99"],
             "forbidden_techniques": [], "forbidden_risk": [],
             "forbidden_kinds": [], "allowed_windows": []}
    eng = _mkeng([_mkstep(host="10.0.0.99")])
    out = autopilot.run(eng, roe_rules=rules, dry_run=True)
    assert _verdicts(out) == ["skipped_scope"]


def test_gate_scope_in_scope_allows():
    rules = {"in_scope": ["10.0.0.0/24"], "out_of_scope": [],
             "forbidden_techniques": [], "forbidden_risk": [],
             "forbidden_kinds": [], "allowed_windows": []}
    eng = _mkeng([_mkstep(host="10.0.0.42")])
    out = autopilot.run(eng, roe_rules=rules, dry_run=True)
    assert _verdicts(out) == ["dry_run"]


# --------------------------------------------------------------------------- #
# Gate 4 — forbidden-technique list
# --------------------------------------------------------------------------- #
def test_gate_forbidden_technique_blocks():
    rules = {"in_scope": [], "out_of_scope": [],
             "forbidden_techniques": ["T1499"], "forbidden_risk": [],
             "forbidden_kinds": [], "allowed_windows": []}
    eng = _mkeng([_mkstep(technique_id="T1499", host="10.0.0.5")])
    out = autopilot.run(eng, roe_rules=rules, dry_run=True)
    assert _verdicts(out) == ["skipped_forbidden_technique"]


# --------------------------------------------------------------------------- #
# Gate 5 — noise ceiling
# --------------------------------------------------------------------------- #
def test_gate_noise_above_ceiling_skips():
    # T1499 (DoS) is noise 10 per opsec._TECH_NOISE; annotate_paths overwrites
    # any hand-set noise with that lookup. Ceiling 5 must skip it.
    eng = _mkeng([_mkstep(technique_id="T1499")])
    out = autopilot.run(eng, dry_run=True, noise_ceiling=5)
    assert _verdicts(out) == ["skipped_noise"]


def test_gate_noise_at_ceiling_allows():
    # T1046 (network service scanning) has noise score 5 — equals the ceiling,
    # not above it, so it must pass through.
    eng = _mkeng([_mkstep(technique_id="T1046")])
    out = autopilot.run(eng, dry_run=True, noise_ceiling=5)
    assert _verdicts(out) == ["dry_run"]


# --------------------------------------------------------------------------- #
# Gate 6 — risk-tag accept list
# --------------------------------------------------------------------------- #
def test_gate_risk_intrusive_without_opt_in_skips():
    eng = _mkeng([_mkstep(risk="intrusive", noise=2)])
    out = autopilot.run(eng, dry_run=True)
    assert _verdicts(out) == ["skipped_risk"]


def test_gate_risk_intrusive_with_opt_in_allows():
    eng = _mkeng([_mkstep(risk="intrusive", noise=2)])
    out = autopilot.run(eng, dry_run=True, accept_risk=["safe", "intrusive"])
    assert _verdicts(out) == ["dry_run"]


# --------------------------------------------------------------------------- #
# Gate 7 — command-safety deny list
# --------------------------------------------------------------------------- #
def test_gate_command_safety_blocks_rm_rf_root():
    eng = _mkeng([_mkstep(command="rm -rf /")])
    out = autopilot.run(eng, dry_run=True,
                        accept_risk=["safe", "intrusive"], noise_ceiling=10)
    assert _verdicts(out) == ["skipped_command"]


def test_gate_command_safety_blocks_anti_forensics_and_shutdown():
    for c in ("shutdown -h now", "wevtutil cl Security"):
        out = autopilot.run(
            _mkeng([_mkstep(command=c)]),
            dry_run=True, accept_risk=["safe", "intrusive"], noise_ceiling=10)
        assert _verdicts(out) == ["skipped_command"], c


# --------------------------------------------------------------------------- #
# Max-steps cap
# --------------------------------------------------------------------------- #
def test_max_steps_cap_halts_after_n():
    eng = _mkeng([_mkstep(command=f"echo {i}", order=i) for i in range(5)])
    out = autopilot.run(eng, dry_run=True, max_steps=3)
    vs = _verdicts(out)
    # Dry-run is not "started" (started counts real spawns), so max-steps cap
    # fires only when real steps accumulate. Validate by using real execution:
    assert len(vs) == 5          # dry-run walks every step
    assert out["summary"]["started"] == 0


def test_max_steps_cap_halts_real_execution_after_n():
    eng = _mkeng([_mkstep(command=f"echo s{i}", order=i) for i in range(5)])
    out = autopilot.run(eng, max_steps=2, timeout_s=10, noise_ceiling=10,
                        accept_risk=["safe", "intrusive"])
    started = sum(1 for r in out["results"]
                  if r["verdict"] in ("executed_ok", "executed_nonzero", "timeout"))
    assert started == 2, (started, _verdicts(out))
    assert "skipped_max_steps" in _verdicts(out)


# --------------------------------------------------------------------------- #
# Real execution + ledger write
# --------------------------------------------------------------------------- #
def test_real_execution_marks_executed_ok_and_writes_ledger():
    db = _tmp(".db")
    try:
        eng = _mkeng([_mkstep(command="echo autopilot-ok")])
        out = autopilot.run(eng, ledger_db=db, noise_ceiling=5)
        assert _verdicts(out) == ["executed_ok"], _verdicts(out)
        assert out["results"][0]["exit_code"] == 0
        # Ledger tables exist + have rows.
        con = sqlite3.connect(db)
        try:
            runs = con.execute("select count(*) from autopilot_runs").fetchone()[0]
            logs = con.execute("select count(*) from autopilot_log").fetchone()[0]
        finally:
            con.close()
        assert runs == 1
        assert logs == 1
    finally:
        for suffix in ("", "-wal", "-shm", "-journal"):
            p = db + suffix
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except OSError:
                    pass


def test_real_execution_timeout_verdict():
    # sys.executable sleeps 5s, autopilot hard-kills at 1s.
    cmd = f'"{sys.executable}" -c "import time; time.sleep(5)"'
    eng = _mkeng([_mkstep(command=cmd)])
    out = autopilot.run(eng, timeout_s=1, noise_ceiling=5)
    assert _verdicts(out) == ["timeout"], _verdicts(out)
    assert out["results"][0]["exit_code"] == -9


# --------------------------------------------------------------------------- #
# CLI: --yes-i-am-authorized is mandatory
# --------------------------------------------------------------------------- #
def test_cli_refuses_without_authorization_flag():
    eng_path = _tmp(".json")
    with open(eng_path, "w", encoding="utf-8") as fh:
        json.dump({"attack_paths": [], "modules": []}, fh)
    try:
        rc = autopilot.main([eng_path])     # no --yes-i-am-authorized
        assert rc == 2
    finally:
        os.unlink(eng_path)


def test_cli_dry_run_e2e_shape():
    eng_path = _tmp(".json")
    with open(eng_path, "w", encoding="utf-8") as fh:
        json.dump(_mkeng([_mkstep(command="echo cli")]), fh)
    log = _tmp(".jsonl")
    try:
        rc = autopilot.main([eng_path, "--yes-i-am-authorized",
                             "--dry-run", "--log", log])
        assert rc == 0
        with open(log, encoding="utf-8") as fh:
            entries = [json.loads(ln) for ln in fh if ln.strip()]
        kinds = {e.get("verdict") for e in entries}
        assert "dry_run" in kinds, kinds
    finally:
        for p in (eng_path, log):
            try:
                os.unlink(p)
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# Step walker — covers modules + attack paths, dedupes empties
# --------------------------------------------------------------------------- #
def test_step_walker_emits_both_paths_and_module_checks():
    eng = {
        "attack_paths": [{"id": "P-1", "kind": "recon",
                          "steps": [_mkstep(command="echo path")]}],
        "modules": [{"module": "smb", "target": "10.0.0.5",
                     "checks": [{"name": "enum", "command": "echo mod",
                                 "risk": "safe", "attack": "T1046"}]}],
    }
    steps = autopilot._walk_step_commands(eng)
    sources = sorted({s["source"] for s in steps})
    assert sources == ["module", "path"], sources
    assert len(steps) == 2


def test_step_walker_drops_empty_and_commented_commands():
    eng = {
        "attack_paths": [{"id": "P-1", "kind": "recon",
                          "steps": [{"command": "", "host": "x"},
                                    {"command": "# a note", "host": "x"},
                                    _mkstep(command="echo real")]}],
        "modules": [],
    }
    steps = autopilot._walk_step_commands(eng)
    assert [s["command"] for s in steps] == ["echo real"]


# --------------------------------------------------------------------------- #
# --only-phase filter
# --------------------------------------------------------------------------- #
def test_only_phase_filter_restricts_execution():
    eng = {
        "attack_paths": [
            {"id": "P-1", "kind": "recon",
             "steps": [_mkstep(command="echo r1")]},
            {"id": "P-2", "kind": "domain",
             "steps": [_mkstep(command="echo d1")]},
        ],
        "modules": [],
    }
    out = autopilot.run(eng, dry_run=True, only_phases=["recon"])
    assert _verdicts(out) == ["dry_run"]
    assert "r1" in out["results"][0]["command"]
