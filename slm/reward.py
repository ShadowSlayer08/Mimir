"""slm.reward — compute a scalar reward for each qualia trace.

Phase 24. The reward signal is the heart of RL/DPO/GRPO — it tells the
trainer which of several candidate SLM responses to prefer. We derive it
from signals the engine already captures:

  * Curator outcome       (slm_trace.outcome: worked / no_signal / muted)
  * Lessons ledger        (lessons.py: did an operator mark the technique
                           referenced by this decision as "worked" in this
                           engagement's context?)
  * Autopilot verdicts    (ledger.autopilot_log: did the step derived from
                           this decision land executed_ok / timeout / skipped?)
  * Validator-pass flag   (did the LLM's shape pass the call-site validator?)
  * Peer agreement        (slm.bridge.query_peer: optional second opinion
                           from Crucible's SLM; only used when configured)

The reward is a weighted sum normalised to [-1, 1]. Weights are
operator-tunable via `MIMIR_SLM_REWARD_WEIGHTS=k1=.., k2=..` env or the
CLI `--weight k=v` flag; sensible defaults ship.
"""
from __future__ import annotations

import json
import os
import sqlite3
from typing import Any

from . import trace as _trace


# Default reward weights. All signals in [-1, 1]; weighted sum is clipped.
DEFAULT_WEIGHTS = {
    "curator_worked":        1.0,
    "curator_no_signal":    -0.25,
    "curator_muted":        -0.75,
    "lesson_worked":         0.5,
    "lesson_burned":        -0.5,
    "autopilot_ok":          0.4,
    "autopilot_nonzero":    -0.1,
    "autopilot_timeout":    -0.2,
    "autopilot_skipped":    -0.3,
    "validator_pass":        0.15,
    "validator_fail":       -0.15,
    "peer_agree":            0.25,
    "peer_disagree":        -0.25,
}


# --------------------------------------------------------------------------- #
# Schema extension — one additive column, idempotent.
# --------------------------------------------------------------------------- #
def ensure_reward_column(db_path):
    """Add the `reward` and `reward_breakdown` columns if missing."""
    con = sqlite3.connect(db_path, isolation_level=None)
    try:
        existing = {r[1] for r in con.execute(
            "PRAGMA table_info(qualia_trace)").fetchall()}
        if "reward" not in existing:
            con.execute("ALTER TABLE qualia_trace ADD COLUMN reward REAL")
        if "reward_breakdown" not in existing:
            con.execute("ALTER TABLE qualia_trace ADD COLUMN reward_breakdown TEXT")
    finally:
        con.close()


def load_weights(overrides=None):
    """Merge: defaults ← MIMIR_SLM_REWARD_WEIGHTS env ← explicit overrides."""
    w = dict(DEFAULT_WEIGHTS)
    env = (os.environ.get("MIMIR_SLM_REWARD_WEIGHTS") or "").strip()
    if env:
        for kv in env.split(","):
            if "=" not in kv:
                continue
            k, v = kv.split("=", 1)
            try:
                w[k.strip()] = float(v.strip())
            except ValueError:
                pass
    for k, v in (overrides or {}).items():
        try:
            w[k] = float(v)
        except (TypeError, ValueError):
            pass
    return w


# --------------------------------------------------------------------------- #
# Signal extraction
# --------------------------------------------------------------------------- #
def _lesson_signal(lessons_db, technique, engagement_id):
    """Return +1 / -1 / 0 from the lessons ledger for (technique, engagement).

    "worked" -> +1, "burned" -> -1, otherwise 0. Context match is best-effort:
    engagement is used as `context` when present, else any context counts.
    """
    if not (lessons_db and technique and os.path.exists(lessons_db)):
        return 0
    try:
        con = sqlite3.connect(lessons_db, isolation_level=None)
        try:
            row = None
            if engagement_id:
                row = con.execute(
                    "SELECT outcome FROM lessons WHERE technique=? AND context=? "
                    "ORDER BY id DESC LIMIT 1",
                    (technique, engagement_id)).fetchone()
            if row is None:
                row = con.execute(
                    "SELECT outcome FROM lessons WHERE technique=? "
                    "ORDER BY id DESC LIMIT 1", (technique,)).fetchone()
        finally:
            con.close()
    except sqlite3.DatabaseError:
        return 0
    if not row:
        return 0
    return {"worked": 1, "burned": -1}.get(row[0], 0)


def _autopilot_signal(ledger_db, technique, host):
    """Scan ledger.autopilot_log for the latest verdict matching this
    (technique, host). Returns one of:
      ok        — executed_ok
      nonzero   — executed_nonzero
      timeout
      skipped   — any skipped_*
      unknown
    """
    if not (ledger_db and os.path.exists(ledger_db)):
        return "unknown"
    try:
        con = sqlite3.connect(ledger_db, isolation_level=None)
        try:
            rows = con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='autopilot_log'").fetchone()
            if not rows:
                return "unknown"
            q = "SELECT verdict FROM autopilot_log WHERE 1=1"
            params = []
            if technique:
                q += " AND attack=?"
                params.append(technique)
            if host:
                q += " AND host=?"
                params.append(host)
            q += " ORDER BY run_id DESC LIMIT 1"
            row = con.execute(q, params).fetchone()
        finally:
            con.close()
    except sqlite3.DatabaseError:
        return "unknown"
    if not row:
        return "unknown"
    v = (row[0] or "").lower()
    if v == "executed_ok":
        return "ok"
    if v == "executed_nonzero":
        return "nonzero"
    if v == "timeout":
        return "timeout"
    if v.startswith("skipped_"):
        return "skipped"
    return "unknown"


def _extract_technique(prompt):
    """Best-effort grep for an ATT&CK id in a prompt (e.g. "T1210")."""
    import re
    m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", (prompt or ""))
    return m.group(0) if m else ""


def _extract_host(prompt):
    """Best-effort grep for the first IPv4 / FQDN in a prompt."""
    import re
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", (prompt or ""))
    if m:
        return m.group(0)
    m = re.search(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+){1,}\b", (prompt or "").lower())
    if m and not m.group(0).endswith((".py", ".json", ".yml")):
        return m.group(0)
    return ""


# --------------------------------------------------------------------------- #
# Reward composition
# --------------------------------------------------------------------------- #
def compute_reward(trace_row, *, lessons_db=None, ledger_db=None,
                   peer_signal=None, weights=None):
    """Return (reward in [-1, 1], breakdown dict) for one trace row.

    trace_row: dict with keys ts, kind, role, prompt, llm_result, fallback_result,
               used_fallback, validator_passed, engagement_id, outcome.
    peer_signal: optional {+1, 0, -1} — the peer SLM's agreement with this row's
                 response (fetch via slm.bridge.query_peer separately).
    """
    w = load_weights(weights)
    br = {}
    total = 0.0

    # Curator outcome.
    outcome = (trace_row.get("outcome") or "").lower()
    if outcome == "worked":
        br["curator_worked"] = w["curator_worked"]; total += br["curator_worked"]
    elif outcome == "no_signal":
        br["curator_no_signal"] = w["curator_no_signal"]; total += br["curator_no_signal"]
    elif outcome == "muted":
        br["curator_muted"] = w["curator_muted"]; total += br["curator_muted"]

    technique = _extract_technique(trace_row.get("prompt", ""))
    host = _extract_host(trace_row.get("prompt", ""))
    eid = trace_row.get("engagement_id") or None

    # Lessons ledger.
    lsig = _lesson_signal(lessons_db, technique, eid) if lessons_db else 0
    if lsig > 0:
        br["lesson_worked"] = w["lesson_worked"]; total += br["lesson_worked"]
    elif lsig < 0:
        br["lesson_burned"] = w["lesson_burned"]; total += br["lesson_burned"]

    # Autopilot verdict.
    av = _autopilot_signal(ledger_db, technique, host) if ledger_db else "unknown"
    if av == "ok":
        br["autopilot_ok"] = w["autopilot_ok"]; total += br["autopilot_ok"]
    elif av == "nonzero":
        br["autopilot_nonzero"] = w["autopilot_nonzero"]; total += br["autopilot_nonzero"]
    elif av == "timeout":
        br["autopilot_timeout"] = w["autopilot_timeout"]; total += br["autopilot_timeout"]
    elif av == "skipped":
        br["autopilot_skipped"] = w["autopilot_skipped"]; total += br["autopilot_skipped"]

    # Validator.
    vp = trace_row.get("validator_passed")
    if vp is True:
        br["validator_pass"] = w["validator_pass"]; total += br["validator_pass"]
    elif vp is False:
        br["validator_fail"] = w["validator_fail"]; total += br["validator_fail"]

    # Peer agreement.
    if peer_signal is not None:
        if peer_signal > 0:
            br["peer_agree"] = w["peer_agree"]; total += br["peer_agree"]
        elif peer_signal < 0:
            br["peer_disagree"] = w["peer_disagree"]; total += br["peer_disagree"]

    # Clip to [-1, 1].
    total = max(-1.0, min(1.0, total))
    return round(total, 4), br


def score_all(db_path, *, lessons_db=None, ledger_db=None,
              peer_signals=None, weights=None, only_curated=False):
    """Compute and persist reward for every row in the trace DB. Returns
    (updated_count, stats_dict). `peer_signals` is an optional {id: int} map
    built by slm.bridge.query_peer_batch.
    """
    ensure_reward_column(db_path)
    peer_signals = peer_signals or {}
    con = sqlite3.connect(db_path, isolation_level=None)
    try:
        q = ("SELECT id, kind, role, prompt, llm_result, fallback_result, "
             "used_fallback, validator_passed, engagement_id, outcome "
             "FROM qualia_trace")
        if only_curated:
            q += " WHERE outcome IS NOT NULL"
        rows = con.execute(q).fetchall()
        n = 0
        rewards = []
        for row in rows:
            tr = {
                "id": row[0], "kind": row[1], "role": row[2],
                "prompt": row[3], "llm_result": row[4],
                "fallback_result": row[5],
                "used_fallback": bool(row[6]),
                "validator_passed": (None if row[7] is None else bool(row[7])),
                "engagement_id": row[8], "outcome": row[9],
            }
            peer = peer_signals.get(row[0])
            r, br = compute_reward(tr, lessons_db=lessons_db,
                                   ledger_db=ledger_db, peer_signal=peer,
                                   weights=weights)
            con.execute(
                "UPDATE qualia_trace SET reward=?, reward_breakdown=? WHERE id=?",
                (r, json.dumps(br, ensure_ascii=False), row[0]))
            rewards.append(r); n += 1
    finally:
        con.close()
    stats = {
        "scored": n,
        "mean": round(sum(rewards) / len(rewards), 4) if rewards else 0.0,
        "max": max(rewards) if rewards else 0.0,
        "min": min(rewards) if rewards else 0.0,
        "positive": sum(1 for r in rewards if r > 0),
        "negative": sum(1 for r in rewards if r < 0),
    }
    return n, stats
