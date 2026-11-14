"""slm.bridge — Mimir ↔ Crucible mutual-teacher bridge.

Phase 24. Crucible is the paired AI-red-team tool (see crucible_bridge.py).
Both engines now have an SLM groundwork (Phase 23 on this side, equivalent
on Crucible's); this module cross-connects them for:

  * Corpus exchange — export Mimir's curated traces as a JSONL dump
    Crucible can ingest, and import Crucible's dumps into our trace DB
    as `peer:*` kind rows (never auto-curated; operator labels them).
  * Peer-opinion signal — during training, ask Crucible's SLM to score
    Mimir's candidate response (and vice versa). The signal feeds
    `slm.reward.compute_reward(..., peer_signal=±1)`.

Transport reuses `crucible_bridge._request` — HMAC-SHA256 over
`method\\npath\\nbody`, the operator's `CRUCIBLE_API_KEY`.  If the
bridge is offline (no URL / no key), `available()` returns False and
the module is a safe no-op; `query_peer` returns `None`, which the
reward composer interprets as "no peer signal".

The imported rows are DATA, never instructions. The bridge NEVER lets a
peer directly curate our rows (change `outcome`) — curation stays an
operator action via `mimir-slm curate`.
"""
from __future__ import annotations

import io
import json
import os
import sqlite3
from typing import Iterable

try:
    import crucible_bridge
except Exception:                                                  # pragma: no cover
    crucible_bridge = None


# --------------------------------------------------------------------------- #
# Availability + simple health check
# --------------------------------------------------------------------------- #
def available():
    """True when a Crucible URL + API key are configured."""
    if crucible_bridge is None:
        return False
    try:
        return bool(crucible_bridge.available())
    except Exception:                                              # pragma: no cover
        return False


def peer_status():
    out = {"available": available(), "transport": "crucible_bridge"}
    if crucible_bridge is not None:
        try:
            out["url_configured"] = bool(crucible_bridge._url())
            out["key_configured"] = bool(crucible_bridge._key())
        except Exception:                                          # pragma: no cover
            pass
    return out


# --------------------------------------------------------------------------- #
# Export — emit JSONL dump Crucible can ingest.
# --------------------------------------------------------------------------- #
def export_dump(trace_db, out_stream, *, only_outcome=None,
                only_role=None, limit=None):
    """Emit a Crucible-ingestible JSONL dump of Mimir's traces.

    One row per line: {"origin": "mimir", "kind": ..., "role": ...,
                       "prompt": ..., "response": ..., "reward": ...,
                       "outcome": ..., "ts": ...}.
    `response` is `llm_result` when present, else `fallback_result`.
    """
    if not os.path.exists(trace_db):
        return 0
    con = sqlite3.connect(trace_db, isolation_level=None)
    try:
        cols = {r[1] for r in con.execute(
            "PRAGMA table_info(qualia_trace)").fetchall()}
        has_reward = "reward" in cols
        q = ("SELECT id, ts, kind, role, prompt, llm_result, "
             "fallback_result, outcome" +
             (", reward" if has_reward else "") +
             " FROM qualia_trace WHERE prompt IS NOT NULL")
        params = []
        if only_outcome:
            q += " AND outcome=?"; params.append(only_outcome)
        if only_role:
            q += " AND role=?"; params.append(only_role)
        q += " ORDER BY id DESC"
        if limit:
            q += " LIMIT ?"; params.append(int(limit))
        rows = con.execute(q, params).fetchall()
    finally:
        con.close()

    n = 0
    for row in rows:
        reward = row[8] if has_reward and len(row) > 8 else None
        out_stream.write(json.dumps({
            "origin": "mimir",
            "mimir_id": row[0],
            "ts": row[1], "kind": row[2], "role": row[3],
            "prompt": row[4],
            "response": row[5] if row[5] is not None else row[6],
            "outcome": row[7],
            "reward": reward,
        }, ensure_ascii=False) + "\n")
        n += 1
    return n


# --------------------------------------------------------------------------- #
# Import — ingest Crucible's dump as peer:* trace rows.
# --------------------------------------------------------------------------- #
def import_dump(trace_db, in_stream):
    """Append Crucible's dump rows to the trace DB as origin='peer'. Never
    curates (leaves outcome NULL) — operator decides via `mimir-slm curate`.

    Returns the count of rows actually inserted. Invalid lines are skipped.
    """
    con = sqlite3.connect(trace_db, isolation_level=None)
    try:
        # Make sure the base schema exists.
        from . import trace as _trace
        con.executescript(_trace._SCHEMA)
        n = 0
        for raw in in_stream:
            raw = raw.strip()
            if not raw or not raw.startswith("{"):
                continue
            try:
                row = json.loads(raw)
            except Exception:
                continue
            prompt = row.get("prompt") or ""
            resp = row.get("response") or ""
            if not prompt:
                continue
            kind = (row.get("kind") or "peer")
            kind = kind if kind.startswith("peer:") else f"peer:{kind}"
            # Secondary-scrub via vault.redact for defence in depth.
            try:
                import vault
                prompt = vault.redact(prompt)
                resp = vault.redact(resp)
            except Exception:                                      # pragma: no cover
                pass
            con.execute(
                "INSERT INTO qualia_trace(ts,kind,role,prompt_hash,prompt,"
                "system,llm_result,fallback_result,used_fallback,"
                "validator_passed,model,engagement_id,outcome) VALUES("
                "?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (row.get("ts", ""), kind[:64], (row.get("role") or "")[:32],
                 _trace._hash(prompt), prompt, None,
                 resp, None, 0, None,
                 (row.get("model") or "")[:128] if row.get("model") else None,
                 (row.get("engagement_id") or None),
                 None))     # NEVER auto-curate from a peer — operator decides.
            n += 1
    finally:
        con.close()
    return n


# --------------------------------------------------------------------------- #
# Peer-opinion signal — ask Crucible's SLM to score our candidate response.
# --------------------------------------------------------------------------- #
def query_peer(prompt, response, *, role="adviser", timeout=None):
    """Ask Crucible's peer SLM whether `response` is a reasonable answer
    to `prompt`. Returns one of:

      +1  — peer agrees (useful teacher signal)
       0  — peer is unsure / indifferent / unreachable
      -1  — peer disagrees (penalty signal)
      None — bridge offline (no signal available)

    The peer endpoint is POST /slm/peer-opinion over the same HMAC bridge
    as crucible_bridge._request. If Crucible has no such endpoint
    configured, any non-2xx response maps to `None`.
    """
    if not available():
        return None
    try:
        body = {"prompt": prompt, "response": response, "role": role}
        data = crucible_bridge._request(
            "POST", "/slm/peer-opinion", body=body,
            timeout=timeout)
        if not isinstance(data, dict):
            return 0
        verdict = (data.get("verdict") or "").lower()
        if verdict in ("agree", "yes", "ok", "+1"):
            return 1
        if verdict in ("disagree", "no", "wrong", "-1"):
            return -1
        return 0
    except Exception:
        return None


def query_peer_batch(trace_db, *, only_outcome="worked", limit=100,
                     timeout=None):
    """Score up to `limit` rows via query_peer. Returns {trace_id: signal}.

    Offline-safe: empty dict when the bridge is unavailable.
    """
    if not available() or not os.path.exists(trace_db):
        return {}
    con = sqlite3.connect(trace_db, isolation_level=None)
    try:
        q = ("SELECT id, role, prompt, llm_result, fallback_result "
             "FROM qualia_trace WHERE prompt IS NOT NULL")
        params = []
        if only_outcome:
            q += " AND outcome=?"
            params.append(only_outcome)
        q += " ORDER BY id DESC LIMIT ?"
        params.append(int(limit))
        rows = con.execute(q, params).fetchall()
    finally:
        con.close()
    out = {}
    for tid, role, prompt, llm_r, fb_r in rows:
        resp = llm_r if llm_r is not None else fb_r
        sig = query_peer(prompt, resp, role=role, timeout=timeout)
        if sig is not None:
            out[tid] = sig
    return out
