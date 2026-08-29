#!/usr/bin/env python3
"""
lessons.py — persistent "what worked / what didn't" store, feeding co-pilot bias.

Authorized / lab / CTF use only.

A tiny SQLite table (co-located with the engagement ledger DB) that records
operator outcomes on staged steps: the technique + service_context + verdict
(`worked`, `blocked`, `false_positive`, `noisy`) with an optional note. Over
engagements the tally forms a prior: for each `(technique, service_ctx)` pair we
learn how often that step actually paid off.

`copilot.recommend()` reads `suggest_bias()` and shifts scores up for
frequently-successful (technique, ctx) combos and down for the ones that keep
failing. Small, bounded (±20 pts), auditable — never overrides validator gates
or drops candidates; it only re-orders. The engine stays useful with no lessons
DB at all (unbiased ranking is the default).

    python lessons.py eng.db record --technique T1210 --context smb --outcome worked
    python lessons.py eng.db summary
"""
from __future__ import annotations

import os
import sqlite3
import sys
from datetime import datetime, timezone

_SCHEMA = """
CREATE TABLE IF NOT EXISTS lessons(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT,
  engagement TEXT,
  technique TEXT,
  context TEXT,
  outcome TEXT,
  note TEXT
);
CREATE INDEX IF NOT EXISTS lessons_key ON lessons(technique, context, outcome);
"""

_OUTCOMES = ("worked", "blocked", "false_positive", "noisy")
# Weighted contribution of each outcome to the (technique, ctx) score delta.
_OUTCOME_W = {"worked": 5, "blocked": -3, "false_positive": -6, "noisy": -2}
# Hard cap on the total bias applied to a single action.
_MAX_BIAS = 20


def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                          # pragma: no cover
            pass


_force_utf8_stdio()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect(db_path):
    con = sqlite3.connect(db_path)
    con.executescript(_SCHEMA)
    return con


def _norm_ctx(ctx):
    return (ctx or "").strip().lower()[:40]


# --------------------------------------------------------------------------- #
def record(db_path, technique, outcome, *, context="", engagement="", note=""):
    """Record one operator outcome. Silently no-ops on unknown outcome."""
    outcome = (outcome or "").strip().lower()
    if outcome not in _OUTCOMES:
        raise ValueError(f"outcome must be one of {_OUTCOMES}, got {outcome!r}")
    if not technique:
        raise ValueError("technique required (e.g. T1210)")
    con = _connect(db_path)
    try:
        con.execute("INSERT INTO lessons(ts,engagement,technique,context,outcome,note)"
                    " VALUES(?,?,?,?,?,?)",
                    (_now(), engagement, technique, _norm_ctx(context), outcome, note or ""))
        con.commit()
    finally:
        con.close()


def summary(db_path):
    """Aggregate: [{"technique":T, "context":c, "outcome":o, "n": count}, ...]."""
    if not db_path or not os.path.exists(db_path):
        return []
    con = _connect(db_path)
    try:
        rows = con.execute(
            "SELECT technique, context, outcome, COUNT(*) FROM lessons "
            "GROUP BY technique, context, outcome ORDER BY technique, context, outcome"
        ).fetchall()
    finally:
        con.close()
    return [{"technique": t, "context": c, "outcome": o, "n": n} for t, c, o, n in rows]


def suggest_bias(db_path):
    """Return `{(technique, context): bias_int}` — the score delta the ranker
    should apply. Only combos with net evidence get an entry."""
    if not db_path or not os.path.exists(db_path):
        return {}
    con = _connect(db_path)
    try:
        rows = con.execute(
            "SELECT technique, context, outcome, COUNT(*) FROM lessons "
            "GROUP BY technique, context, outcome"
        ).fetchall()
    finally:
        con.close()
    tally = {}
    for tech, ctx, outcome, n in rows:
        key = (tech, ctx)
        tally[key] = tally.get(key, 0) + _OUTCOME_W.get(outcome, 0) * int(n)
    # Clamp to +/- _MAX_BIAS, drop zero entries.
    return {k: max(-_MAX_BIAS, min(_MAX_BIAS, v)) for k, v in tally.items() if v}


def apply_bias(actions, bias):
    """Non-destructive: return a new list with `score` adjusted and `bias`/`bias_from`
    recorded in trace. Same input order — the CALLER re-sorts if it wants to."""
    if not bias:
        return actions
    out = []
    for a in actions or []:
        tech = (a.get("attack") or "").strip()
        # source hint: for path actions the first-step host suggests the service ctx;
        # here we key on (technique) alone plus optional (technique, "") fallback.
        candidates = [(tech, ""), (tech, _norm_ctx(a.get("source", "")))]
        delta = 0
        used = None
        for k in candidates:
            if k in bias:
                delta = bias[k]
                used = k
                break
        b = dict(a)
        if delta:
            b["score"] = int(b.get("score", 0)) + delta
            trace = dict(b.get("trace") or {})
            trace["lessons_bias"] = delta
            trace["lessons_key"] = f"{used[0]}|{used[1]}" if used else ""
            b["trace"] = trace
        out.append(b)
    return out


def rerank_with_lessons(actions, db_path):
    """Convenience: apply the DB's bias to `actions` and re-sort by new score."""
    biased = apply_bias(actions, suggest_bias(db_path))
    biased.sort(key=lambda a: (-int(a.get("score", 0)), a.get("category", ""),
                               a.get("title", "")))
    for i, a in enumerate(biased, 1):
        a["rank"] = i
    return biased


# --------------------------------------------------------------------------- #
def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="lessons.py",
                                 description="what-worked ledger for co-pilot ranking")
    ap.add_argument("db", help="engagement ledger SQLite path (shares the ledger.py DB)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    rec = sub.add_parser("record", help="record one operator outcome")
    rec.add_argument("--technique", required=True, help="ATT&CK id, e.g. T1210")
    rec.add_argument("--outcome", required=True, choices=list(_OUTCOMES))
    rec.add_argument("--context", default="", help="service / host-class hint (smb / rdp / linux ...)")
    rec.add_argument("--engagement", default="", help="engagement id tag (optional)")
    rec.add_argument("--note", default="", help="free-form operator note")

    sub.add_parser("summary", help="print aggregate tallies")
    sub.add_parser("bias", help="print the score-delta table copilot would apply")

    args = ap.parse_args(argv)
    if args.cmd == "record":
        record(args.db, args.technique, args.outcome,
               context=args.context, engagement=args.engagement, note=args.note)
        print(f"[+] recorded {args.technique} @ {args.context or '-'} = {args.outcome}")
        return 0
    if args.cmd == "summary":
        rows = summary(args.db)
        if not rows:
            print("(no lessons yet)")
            return 0
        for r in rows:
            print(f"  {r['technique']:<10} {r['context']:<12} {r['outcome']:<15} n={r['n']}")
        return 0
    if args.cmd == "bias":
        b = suggest_bias(args.db)
        if not b:
            print("(no net bias yet)")
            return 0
        for (t, c), d in sorted(b.items(), key=lambda kv: -kv[1]):
            print(f"  {t:<10} {c or '-':<12} bias={d:+d}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
