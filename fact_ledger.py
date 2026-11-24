#!/usr/bin/env python3
"""fact_ledger.py — append-only Fact graph for autonomous testing.

Phase 28, borrowed from Cairn's `Fact-only, append-only graph` pattern.

Mimir has two kinds of state:

  * The **engagement JSON** is the mutable summary — hosts, findings,
    attack paths, recommendations. Operators read it; the engine mutates
    it. Good for review.
  * The **Fact ledger** is the immutable event log — every autopilot step
    verdict, every corrective fact, every operator decision, in append
    order with causal links. Good for replay, training, audit.

A Fact row carries:
    id             INTEGER PRIMARY KEY                # monotonic
    ts             TEXT (UTC ISO-8601 seconds)
    engagement_id  TEXT
    kind           TEXT          # verdict kind (executed_ok / dry_run / ...)
                                 # OR a free kind (reopen / hint / ...)
    source         TEXT          # "autopilot" / "operator" / "lessons"
    from_fact_ids  TEXT (JSON)   # Cairn-style hyperedge — this Fact
                                 # "follows from" these prior Facts
    data           TEXT (JSON)   # the verdict record or custom payload

Facts never UPDATE or DELETE. State changes are new Facts. A `reopen`
Fact cites the original Fact it corrects via `from_fact_ids=[orig_id]`
and `kind="reopen"`; downstream consumers merge the two.

CLI (`mimir-facts`):
  record <kind> <engagement> [--data JSON] [--from ID,ID,...]  — explicit append
  list   <engagement>         [--kind K] [--limit N]           — tail
  reopen <id> <reason>                                         — corrective fact
  replay <engagement>                                          — walk in order
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone


def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                          # pragma: no cover
            pass


_force_utf8_stdio()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS facts(
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    engagement_id  TEXT NOT NULL,
    kind           TEXT NOT NULL,
    source         TEXT NOT NULL,
    from_fact_ids  TEXT,       -- JSON array of int ids
    data           TEXT        -- JSON object
);
CREATE INDEX IF NOT EXISTS ix_facts_eng    ON facts(engagement_id);
CREATE INDEX IF NOT EXISTS ix_facts_kind   ON facts(kind);
CREATE INDEX IF NOT EXISTS ix_facts_eng_ts ON facts(engagement_id, ts);
"""


def _connect(db_path):
    con = sqlite3.connect(db_path, isolation_level=None, timeout=5.0)
    try:
        con.executescript(_SCHEMA)
    except sqlite3.DatabaseError:                                  # pragma: no cover
        pass
    return con


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# API — append-only. Never update, never delete.
# --------------------------------------------------------------------------- #
def record(*, db_path, engagement_id, kind, source="operator",
           data=None, from_fact_ids=None, ts=None):
    """Append one immutable Fact. Returns the new id."""
    if not db_path:
        raise ValueError("db_path is required")
    con = _connect(db_path)
    try:
        cur = con.execute(
            "INSERT INTO facts(ts, engagement_id, kind, source, "
            "from_fact_ids, data) VALUES(?,?,?,?,?,?)",
            (ts or _now(), (engagement_id or "")[:200],
             (kind or "note")[:80], (source or "operator")[:40],
             json.dumps(list(from_fact_ids or [])),
             json.dumps(data or {}, ensure_ascii=False)))
        return cur.lastrowid
    finally:
        con.close()


def reopen(*, db_path, fact_id, reason, source="operator"):
    """Append a corrective fact that cites `fact_id` as its origin. The old
    Fact is NOT modified. Readers see both in order and should treat the
    `reopen` as authoritative for the claim it corrects.
    """
    orig = get(db_path, int(fact_id))
    if not orig:
        raise ValueError(f"no fact with id={fact_id}")
    return record(db_path=db_path,
                  engagement_id=orig["engagement_id"],
                  kind="reopen", source=source,
                  from_fact_ids=[int(fact_id)],
                  data={"reason": reason, "corrects_id": int(fact_id),
                        "corrects_kind": orig["kind"]})


def get(db_path, fact_id):
    con = _connect(db_path)
    try:
        row = con.execute(
            "SELECT id, ts, engagement_id, kind, source, from_fact_ids, "
            "data FROM facts WHERE id=?", (int(fact_id),)).fetchone()
    finally:
        con.close()
    if not row:
        return None
    return _row_to_dict(row)


def list_facts(db_path, engagement_id, *, kind=None, limit=100, since_id=0):
    con = _connect(db_path)
    try:
        q = ("SELECT id, ts, engagement_id, kind, source, from_fact_ids, "
             "data FROM facts WHERE engagement_id=? AND id>?")
        params = [engagement_id, int(since_id)]
        if kind:
            q += " AND kind=?"; params.append(kind)
        q += " ORDER BY id ASC LIMIT ?"
        params.append(int(limit))
        rows = con.execute(q, params).fetchall()
    finally:
        con.close()
    return [_row_to_dict(r) for r in rows]


def replay(db_path, engagement_id):
    """Yield every Fact for an engagement in append order. Useful for
    rebuilding state from the event log."""
    con = _connect(db_path)
    try:
        rows = con.execute(
            "SELECT id, ts, engagement_id, kind, source, from_fact_ids, "
            "data FROM facts WHERE engagement_id=? ORDER BY id ASC",
            (engagement_id,)).fetchall()
    finally:
        con.close()
    for r in rows:
        yield _row_to_dict(r)


def latest_state(db_path, engagement_id):
    """Fold every Fact into a snapshot dict. `reopen` facts override the
    kind they cite via from_fact_ids[0]. Returns:
      {"facts_total": N, "by_kind": {...}, "reopened": [ids], "last_ts": "..."}
    """
    reopened = set()
    kinds = {}
    total = 0
    last_ts = ""
    for f in replay(db_path, engagement_id):
        total += 1
        last_ts = f["ts"]
        if f["kind"] == "reopen":
            corrects = (f["data"] or {}).get("corrects_id")
            if corrects is not None:
                reopened.add(int(corrects))
        kinds[f["kind"]] = kinds.get(f["kind"], 0) + 1
    return {"facts_total": total, "by_kind": kinds,
            "reopened": sorted(reopened), "last_ts": last_ts}


def _row_to_dict(row):
    try:
        from_ids = json.loads(row[5] or "[]")
    except Exception:
        from_ids = []
    try:
        data = json.loads(row[6] or "{}")
    except Exception:
        data = {}
    return {"id": row[0], "ts": row[1], "engagement_id": row[2],
            "kind": row[3], "source": row[4],
            "from_fact_ids": from_ids, "data": data}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _cmd_record(args):
    data = {}
    if args.data:
        try:
            data = json.loads(args.data)
        except Exception as exc:
            print(f"[mimir-facts] --data must be JSON: {exc}",
                  file=sys.stderr); return 2
    frm = []
    if args.from_ids:
        for part in args.from_ids.split(","):
            part = part.strip()
            if part:
                try:
                    frm.append(int(part))
                except ValueError:
                    pass
    fid = record(db_path=args.db, engagement_id=args.engagement,
                 kind=args.kind, source=args.source,
                 data=data, from_fact_ids=frm)
    print(f"[mimir-facts] recorded #{fid}  kind={args.kind}  "
          f"engagement={args.engagement}", file=sys.stderr)
    return 0


def _cmd_list(args):
    rows = list_facts(args.db, args.engagement,
                      kind=args.kind, limit=args.limit)
    for r in rows:
        data_preview = json.dumps(r["data"])[:80]
        print(f"#{r['id']:>5} {r['ts'][:19]} [{r['source']:<10}] "
              f"{r['kind']:<22} from={r['from_fact_ids']}  {data_preview}")
    return 0


def _cmd_reopen(args):
    fid = reopen(db_path=args.db, fact_id=args.id, reason=args.reason,
                 source=args.source)
    print(f"[mimir-facts] reopen #{fid}  corrects=#{args.id}",
          file=sys.stderr)
    return 0


def _cmd_replay(args):
    for r in replay(args.db, args.engagement):
        print(json.dumps(r, ensure_ascii=False))
    return 0


def _cmd_state(args):
    s = latest_state(args.db, args.engagement)
    print(json.dumps(s, indent=2, sort_keys=True))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="mimir-facts",
        description="Append-only Fact ledger for Mimir engagements. "
                    "Facts never update or delete; state changes are new "
                    "Facts. `reopen` cites a prior Fact as the one it "
                    "corrects (Cairn-style hyperedge).")
    ap.add_argument("--db", default=os.environ.get("MIMIR_FACT_DB", ""),
                    help="SQLite path (default: $MIMIR_FACT_DB)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("record", help="append one Fact")
    p.add_argument("kind")
    p.add_argument("engagement")
    p.add_argument("--data", help="JSON object payload")
    p.add_argument("--from-ids", dest="from_ids",
                   help="comma-separated prior Fact ids")
    p.add_argument("--source", default="operator")
    p.set_defaults(fn=_cmd_record)

    p = sub.add_parser("list", help="tail Facts for an engagement")
    p.add_argument("engagement")
    p.add_argument("--kind")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(fn=_cmd_list)

    p = sub.add_parser("reopen", help="append a corrective Fact")
    p.add_argument("id", type=int)
    p.add_argument("reason")
    p.add_argument("--source", default="operator")
    p.set_defaults(fn=_cmd_reopen)

    p = sub.add_parser("replay", help="emit every Fact as JSONL")
    p.add_argument("engagement")
    p.set_defaults(fn=_cmd_replay)

    p = sub.add_parser("state", help="summary snapshot (by-kind + reopened)")
    p.add_argument("engagement")
    p.set_defaults(fn=_cmd_state)

    args = ap.parse_args(argv)
    if not args.db:
        print("[mimir-facts] --db or $MIMIR_FACT_DB required",
              file=sys.stderr); return 2
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
