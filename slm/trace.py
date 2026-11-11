"""slm.trace — append-only SQLite trace sink for qualia decisions.

Opt-in via environment variable `MIMIR_SLM_TRACE_DB=/path/to/trace.db`. When
unset, every function here no-ops (zero overhead for operators who have not
turned on the SLM data pipeline).

Schema:
  qualia_trace(
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT,               -- UTC ISO-8601 seconds precision
    kind            TEXT,               -- qualia label ("rank-actions", ...)
    role            TEXT,               -- llm role ("planner" | "narrator" | ...)
    prompt_hash     TEXT,               -- sha256 of prompt (dedup / join key)
    prompt          TEXT,               -- redacted prompt
    system          TEXT,               -- redacted system prompt (NULL if default)
    llm_result      TEXT,               -- redacted JSON or prose (NULL if used_fallback)
    fallback_result TEXT,               -- redacted JSON or prose (NULL if LLM won)
    used_fallback   INTEGER,            -- 0 = LLM output used, 1 = fallback used
    validator_passed INTEGER,           -- 0/1 if a validator was provided, NULL otherwise
    model           TEXT,               -- model name recorded for the run (if any)
    engagement_id   TEXT,               -- optional engagement id for joining
    outcome         TEXT                -- curation label: "worked" / "no_signal" / "muted" / NULL
  )

Call shape (from qualia.decide / qualia.prose):
    slm.trace.record(kind=..., role=..., prompt=..., system=...,
                     llm_result=..., fallback_result=..., used_fallback=...,
                     validator_passed=..., model=...)

Never raises; swallows every error so a misconfigured sink cannot break an
engagement.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone


_ENV_DB = "MIMIR_SLM_TRACE_DB"
_ENV_ENGAGEMENT = "MIMIR_SLM_TRACE_ENGAGEMENT"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS qualia_trace (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT,
    kind            TEXT,
    role            TEXT,
    prompt_hash     TEXT,
    prompt          TEXT,
    system          TEXT,
    llm_result      TEXT,
    fallback_result TEXT,
    used_fallback   INTEGER,
    validator_passed INTEGER,
    model           TEXT,
    engagement_id   TEXT,
    outcome         TEXT
);
CREATE INDEX IF NOT EXISTS ix_qt_kind ON qualia_trace(kind);
CREATE INDEX IF NOT EXISTS ix_qt_outcome ON qualia_trace(outcome);
CREATE INDEX IF NOT EXISTS ix_qt_hash ON qualia_trace(prompt_hash);
"""


def enabled():
    """True when the operator has opted in by setting the env var AND the
    path is writable (or does not yet exist)."""
    return bool(_db_path())


def _db_path():
    p = (os.environ.get(_ENV_DB) or "").strip()
    return p or None


def _engagement_id():
    return (os.environ.get(_ENV_ENGAGEMENT) or "").strip() or None


def _redact(s):
    if s is None:
        return None
    if not isinstance(s, str):
        try:
            s = json.dumps(s, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            s = str(s)
    try:
        import vault
        return vault.redact(s)
    except Exception:
        return s


def _hash(prompt):
    try:
        return hashlib.sha256((prompt or "").encode("utf-8")).hexdigest()
    except Exception:
        return ""


def _connect(path):
    con = sqlite3.connect(path, isolation_level=None, timeout=5.0)
    try:
        con.executescript(_SCHEMA)
    except sqlite3.DatabaseError:                                   # pragma: no cover
        pass
    return con


def record(kind, role, prompt, llm_result, fallback_result,
           used_fallback, *, system=None, validator_passed=None,
           model=None, engagement_id=None):
    """Append one trace row. No-op when `MIMIR_SLM_TRACE_DB` is unset.

    All text fields are redacted via `vault.redact` before write. Never
    raises — a broken sink must not break the engagement.
    """
    path = _db_path()
    if not path:
        return False
    try:
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "kind": (kind or "")[:64],
            "role": (role or "")[:32],
            "prompt_hash": _hash(prompt),
            "prompt": _redact(prompt),
            "system": _redact(system) if system else None,
            "llm_result": _redact(llm_result) if llm_result is not None else None,
            "fallback_result": _redact(fallback_result) if fallback_result is not None else None,
            "used_fallback": 1 if used_fallback else 0,
            "validator_passed": (None if validator_passed is None
                                 else (1 if validator_passed else 0)),
            "model": (model or "")[:128] if model else None,
            "engagement_id": (engagement_id or _engagement_id() or None),
            "outcome": None,
        }
        con = _connect(path)
        try:
            con.execute(
                "INSERT INTO qualia_trace(ts,kind,role,prompt_hash,prompt,"
                "system,llm_result,fallback_result,used_fallback,"
                "validator_passed,model,engagement_id,outcome) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rec["ts"], rec["kind"], rec["role"], rec["prompt_hash"],
                 rec["prompt"], rec["system"], rec["llm_result"],
                 rec["fallback_result"], rec["used_fallback"],
                 rec["validator_passed"], rec["model"],
                 rec["engagement_id"], rec["outcome"]))
        finally:
            con.close()
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Query helpers — used by mimir_slm.py and the test suite.
# --------------------------------------------------------------------------- #
def stats(path=None):
    """Return a corpus-readiness snapshot."""
    path = path or _db_path()
    if not path or not os.path.exists(path):
        return {"path": path, "present": False, "total": 0}
    con = _connect(path)
    try:
        total = con.execute("SELECT COUNT(*) FROM qualia_trace").fetchone()[0]
        by_kind = dict(con.execute(
            "SELECT kind, COUNT(*) FROM qualia_trace GROUP BY kind "
            "ORDER BY COUNT(*) DESC").fetchall())
        by_role = dict(con.execute(
            "SELECT role, COUNT(*) FROM qualia_trace GROUP BY role").fetchall())
        used_fb = con.execute(
            "SELECT SUM(used_fallback), COUNT(*) FROM qualia_trace").fetchone()
        curated = con.execute(
            "SELECT outcome, COUNT(*) FROM qualia_trace WHERE outcome IS NOT NULL "
            "GROUP BY outcome").fetchall()
        validator_pass = con.execute(
            "SELECT SUM(validator_passed), SUM(CASE WHEN validator_passed IS NOT NULL "
            "THEN 1 ELSE 0 END) FROM qualia_trace").fetchone()
    finally:
        con.close()
    fb_rate = (used_fb[0] or 0) / used_fb[1] if used_fb[1] else 0.0
    v_total = validator_pass[1] or 0
    v_pass = validator_pass[0] or 0
    v_rate = v_pass / v_total if v_total else None
    return {
        "path": path, "present": True, "total": total,
        "by_kind": by_kind, "by_role": by_role,
        "fallback_rate": round(fb_rate, 4),
        "validator_pass_rate": round(v_rate, 4) if v_rate is not None else None,
        "curated": dict(curated),
        "readiness": _readiness(total, curated),
    }


def _readiness(total, curated_rows):
    """Score (0..1) describing how close the corpus is to fine-tuneable."""
    worked = sum(c for lbl, c in curated_rows if lbl == "worked")
    # 500 curated "worked" traces is the SLM phase target.
    return round(min(1.0, worked / 500.0), 4)


def recent(path=None, limit=20, kind=None):
    path = path or _db_path()
    if not path or not os.path.exists(path):
        return []
    con = _connect(path)
    try:
        if kind:
            rows = con.execute(
                "SELECT id,ts,kind,role,used_fallback,outcome,"
                "substr(prompt,1,160),substr(COALESCE(llm_result,fallback_result),1,160) "
                "FROM qualia_trace WHERE kind=? ORDER BY id DESC LIMIT ?",
                (kind, int(limit))).fetchall()
        else:
            rows = con.execute(
                "SELECT id,ts,kind,role,used_fallback,outcome,"
                "substr(prompt,1,160),substr(COALESCE(llm_result,fallback_result),1,160) "
                "FROM qualia_trace ORDER BY id DESC LIMIT ?",
                (int(limit),)).fetchall()
    finally:
        con.close()
    return [
        {"id": r[0], "ts": r[1], "kind": r[2], "role": r[3],
         "used_fallback": bool(r[4]), "outcome": r[5],
         "prompt": r[6], "result": r[7]} for r in rows]


def set_outcome(path, trace_id, outcome):
    """Operator curation — mark a trace as `worked` / `no_signal` / `muted`."""
    if outcome not in ("worked", "no_signal", "muted", None):
        raise ValueError(f"outcome must be one of worked/no_signal/muted/None, got {outcome!r}")
    con = _connect(path)
    try:
        con.execute("UPDATE qualia_trace SET outcome=? WHERE id=?",
                    (outcome, int(trace_id)))
    finally:
        con.close()


def export_jsonl(path, out_stream, *, only_outcome=None, min_role=None):
    """Emit curated training JSONL to `out_stream`. Each row is:
         {"prompt": "...", "response": "...", "kind": "...", "role": "..."}

    Rows where the LLM produced the output are preferred as training
    targets; fallback-only rows are dropped unless the operator explicitly
    labelled them `worked` (and will be included with the fallback result).
    """
    if not os.path.exists(path):
        return 0
    con = _connect(path)
    try:
        q = ("SELECT kind,role,prompt,llm_result,fallback_result,used_fallback,outcome "
             "FROM qualia_trace WHERE prompt IS NOT NULL")
        params = []
        if only_outcome:
            q += " AND outcome=?"
            params.append(only_outcome)
        rows = con.execute(q, params).fetchall()
    finally:
        con.close()
    n = 0
    for kind, role, prompt, llm_r, fb_r, used_fb, outcome in rows:
        response = fb_r if used_fb else llm_r
        if not response:
            continue
        if used_fb and outcome != "worked":
            continue       # don't train on failed LLM shapes unless curator OK'd
        out_stream.write(json.dumps({
            "prompt": prompt, "response": response,
            "kind": kind, "role": role,
            "outcome": outcome or "unlabeled",
        }, ensure_ascii=False) + "\n")
        n += 1
    return n
