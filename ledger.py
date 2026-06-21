#!/usr/bin/env python3
"""
ledger.py — persistent engagement ledger (SQLite).

Authorized / lab / CTF use only.

Records each assess.py run so re-assessing a target ACCRETES rather than resets:
hosts and findings are upserted (first_seen / last_seen / times-seen tracked),
attack paths are stored per run. Lets an operator see what changed between rounds.

    python assess.py <target> --ledger engagement.db ...
    python ledger.py engagement.db            # show history + recurring findings
"""
from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, mode TEXT, source TEXT, target TEXT,
  hosts INT, findings INT, paths INT);
CREATE TABLE IF NOT EXISTS hosts(
  key TEXT PRIMARY KEY, ip TEXT, label TEXT, os TEXT, grade TEXT,
  first_seen TEXT, last_seen TEXT, seen INT);
CREATE TABLE IF NOT EXISTS findings(
  key TEXT PRIMARY KEY, host TEXT, port INT, category TEXT, severity TEXT, title TEXT,
  cve TEXT, first_seen TEXT, last_seen TEXT, seen INT);
CREATE TABLE IF NOT EXISTS attack_paths(
  run_id INT, pid TEXT, name TEXT, kind TEXT, severity TEXT, confidence TEXT, score INT);
CREATE TABLE IF NOT EXISTS run_findings(
  run_id INT, fkey TEXT, host TEXT, port INT, severity TEXT, title TEXT);
CREATE TABLE IF NOT EXISTS run_hosts(
  run_id INT, hkey TEXT, label TEXT, grade TEXT);
CREATE TABLE IF NOT EXISTS triage(
  key TEXT PRIMARY KEY, status TEXT, owner TEXT, notes TEXT, severity_override TEXT, updated TEXT);
"""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fkey(f):
    raw = f"{f.get('host')}|{f.get('port')}|{f.get('title')}"
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:16]


def _connect(db_path):
    con = sqlite3.connect(db_path)
    con.executescript(_SCHEMA)
    return con


def record_run(db_path, report, modules, paths, scan_meta):
    """Insert a run and upsert its hosts/findings/paths. Returns the run id."""
    ts = _now()
    con = _connect(db_path)
    try:
        cur = con.execute(
            "INSERT INTO runs(ts,mode,source,target,hosts,findings,paths) VALUES(?,?,?,?,?,?,?)",
            (ts, scan_meta.get("mode", ""),
             ("evidence" if scan_meta.get("from_dir") else "xml" if scan_meta.get("from_xml") else "scan"),
             str(scan_meta.get("target", "")),
             report["totals"]["hosts"], report["totals"]["findings"], len(paths)))
        run_id = cur.lastrowid

        for h in report.get("host_summary", []):
            key = h.get("ip") or h.get("host")
            con.execute(
                "INSERT INTO hosts(key,ip,label,os,grade,first_seen,last_seen,seen) "
                "VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(key) DO UPDATE SET "
                "last_seen=excluded.last_seen, grade=excluded.grade, os=excluded.os, seen=seen+1",
                (key, h.get("ip", ""), h.get("host", ""), h.get("os", ""), h.get("grade", ""), ts, ts))
            con.execute("INSERT INTO run_hosts(run_id,hkey,label,grade) VALUES(?,?,?,?)",
                        (run_id, key, h.get("host", ""), h.get("grade", "")))

        for f in report.get("findings", []):
            fk = _fkey(f)
            con.execute(
                "INSERT INTO findings(key,host,port,category,severity,title,cve,first_seen,last_seen,seen) "
                "VALUES(?,?,?,?,?,?,?,?,?,1) ON CONFLICT(key) DO UPDATE SET "
                "last_seen=excluded.last_seen, severity=excluded.severity, seen=seen+1",
                (fk, f.get("host", ""), f.get("port", 0) or 0, f.get("category", ""),
                 f.get("severity", ""), f.get("title", ""), ";".join(f.get("cve", [])), ts, ts))
            con.execute("INSERT INTO run_findings(run_id,fkey,host,port,severity,title) VALUES(?,?,?,?,?,?)",
                        (run_id, fk, f.get("host", ""), f.get("port", 0) or 0,
                         f.get("severity", ""), f.get("title", "")))

        for p in paths:
            con.execute(
                "INSERT INTO attack_paths(run_id,pid,name,kind,severity,confidence,score) VALUES(?,?,?,?,?,?,?)",
                (run_id, p.get("id", ""), p.get("name", ""), p.get("kind", ""),
                 p.get("severity", ""), p.get("confidence", ""), p.get("score", 0)))
        con.commit()
        return run_id
    finally:
        con.close()


def _run_findings(con, run_id):
    rows = con.execute("SELECT fkey,host,port,severity,title FROM run_findings WHERE run_id=?",
                       (run_id,)).fetchall()
    return {r[0]: {"host": r[1], "port": r[2], "severity": r[3], "title": r[4]} for r in rows}


def diff(db_path, run_a=None, run_b=None):
    """Compare two runs (default: the last two). Returns new / fixed / still-open
    finding lists (+ a muted bucket for triaged-out findings) + host grade
    changes; None if there aren't two comparable runs."""
    con = _connect(db_path)
    try:
        ids = [r[0] for r in con.execute("SELECT id FROM runs ORDER BY id").fetchall()]
        if run_a is None or run_b is None:
            if len(ids) < 2:
                return None
            run_a, run_b = ids[-2], ids[-1]
        if not con.execute("SELECT 1 FROM run_findings WHERE run_id IN (?,?) LIMIT 1",
                           (run_a, run_b)).fetchone():
            return None                        # pre-snapshot DB: no comparable per-run data
        fa, fb = _run_findings(con, run_a), _run_findings(con, run_b)
        triage = {r[0]: (r[1], r[2]) for r in con.execute(
            "SELECT key,status,severity_override FROM triage").fetchall()}
        muted_status = {"false_positive", "accepted", "remediated"}

        def _ann(d, k):
            st, ov = triage.get(k, (None, None))
            d = dict(d, triage=st)
            if ov:
                d["severity"] = ov             # apply operator severity override
            return d, (st in muted_status)

        new, still, muted = [], [], []
        for k in fb:
            d, m = _ann(fb[k], k)
            (muted if m else (still if k in fa else new)).append(d)
        fixed = []
        for k in fa:
            if k not in fb:
                d, m = _ann(fa[k], k)
                (muted if m else fixed).append(d)
        ga = {r[0]: r[1] for r in con.execute(
            "SELECT hkey,grade FROM run_hosts WHERE run_id=?", (run_a,)).fetchall()}
        grade_changes = [{"label": lbl, "old": ga[hk], "new": g}
                         for hk, lbl, g in con.execute(
                             "SELECT hkey,label,grade FROM run_hosts WHERE run_id=?", (run_b,)).fetchall()
                         if hk in ga and ga[hk] != g]
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for lst in (new, fixed, still, muted):
            lst.sort(key=lambda x: rank.get(x["severity"], 9))
        return {"run_a": run_a, "run_b": run_b, "new": new, "fixed": fixed,
                "still_open": still, "muted": muted, "grade_changes": grade_changes}
    finally:
        con.close()


def finding_key(f):
    """Public stable key for a finding dict (host|port|title) — for triage."""
    return _fkey(f)


def set_triage(db_path, key, status=None, owner=None, notes=None, severity_override=None):
    """Upsert operator triage for a finding (open/confirmed/false_positive/
    remediated/accepted, owner, notes, severity override). Partial updates keep
    existing values (pass only what changes)."""
    con = _connect(db_path)
    try:
        con.execute(
            "INSERT INTO triage(key,status,owner,notes,severity_override,updated) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET "
            "status=COALESCE(excluded.status,status), owner=COALESCE(excluded.owner,owner), "
            "notes=COALESCE(excluded.notes,notes), "
            "severity_override=COALESCE(excluded.severity_override,severity_override), "
            "updated=excluded.updated",
            (key, status, owner, notes, severity_override, _now()))
        con.commit()
    finally:
        con.close()


def get_triage(db_path, key):
    con = _connect(db_path)
    try:
        row = con.execute("SELECT key,status,owner,notes,severity_override,updated "
                          "FROM triage WHERE key=?", (key,)).fetchone()
        cols = ["key", "status", "owner", "notes", "severity_override", "updated"]
        return dict(zip(cols, row)) if row else None
    finally:
        con.close()


def list_triage(db_path):
    con = _connect(db_path)
    try:
        rows = con.execute("SELECT key,status,owner,notes,severity_override,updated "
                           "FROM triage ORDER BY updated DESC").fetchall()
        cols = ["key", "status", "owner", "notes", "severity_override", "updated"]
        return [dict(zip(cols, r)) for r in rows]
    finally:
        con.close()


def history(db_path):
    con = _connect(db_path)
    try:
        runs = con.execute("SELECT id,ts,mode,source,target,hosts,findings,paths "
                           "FROM runs ORDER BY id").fetchall()
        n_hosts = con.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        n_find = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        recurring = con.execute(
            "SELECT f.severity,f.host,f.port,f.title,f.seen,f.key,t.status,t.severity_override "
            "FROM findings f LEFT JOIN triage t ON t.key=f.key "
            "WHERE f.seen>1 ORDER BY f.seen DESC, f.severity LIMIT 20").fetchall()
        return runs, n_hosts, n_find, recurring
    finally:
        con.close()


def main():
    import argparse
    ap = argparse.ArgumentParser(prog="ledger.py",
                                 description="engagement ledger: history, run diff, triage")
    ap.add_argument("db")
    sub = ap.add_subparsers(dest="cmd")
    t = sub.add_parser("triage", help="set triage on a finding by its key")
    t.add_argument("fkey")
    t.add_argument("--status",
                   choices=["open", "confirmed", "false_positive", "remediated", "accepted"])
    t.add_argument("--owner")
    t.add_argument("--notes")
    t.add_argument("--severity-override", dest="sev",
                   choices=["critical", "high", "medium", "low", "info"])
    sub.add_parser("triage-list", help="list all triaged findings")
    args = ap.parse_args()

    if args.cmd == "triage":
        set_triage(args.db, args.fkey, status=args.status, owner=args.owner,
                   notes=args.notes, severity_override=args.sev)
        print(f"[+] triaged {args.fkey}: status={args.status} owner={args.owner} "
              f"override={args.sev}")
        return 0
    if args.cmd == "triage-list":
        rows = list_triage(args.db)
        if not rows:
            print("(no triage records)"); return 0
        for r in rows:
            print(f"  {r['key']:14} [{(r['status'] or '-'):14}] "
                  f"owner={r['owner'] or '-':10} override={r['severity_override'] or '-':8} "
                  f"{r['notes'] or ''}")
        return 0

    runs, n_hosts, n_find, recurring = history(args.db)
    print(f"[+] {len(runs)} run(s) | {n_hosts} unique host(s) | {n_find} unique finding(s)\n")
    for r in runs:
        print(f"  run #{r[0]:<3} {r[1]}  mode={r[2]:<8} src={r[3]:<8} target={r[4]:<22} "
              f"hosts={r[5]} findings={r[6]} paths={r[7]}")
    if recurring:
        print("\n  recurring findings (seen in >1 run):  [key -> `ledger.py <db> triage <key>`]")
        for sev, host, port, title, seen, key, status, ov in recurring:
            tgt = f"{host}:{port}" if port else host
            tag = f"  ({status}{'/' + ov if ov else ''})" if status else ""
            print(f"    {key:14} [{(ov or sev).upper():8}] x{seen}  {tgt}  {title}{tag}")
    if len(runs) >= 2:
        d = diff(args.db)
        if d:
            muted = f", {len(d.get('muted', []))} muted" if d.get("muted") else ""
            print(f"\n  changes (run #{d['run_a']} -> #{d['run_b']}): "
                  f"{len(d['new'])} new, {len(d['fixed'])} fixed, "
                  f"{len(d['still_open'])} still-open{muted}")
            for f in d["new"][:10]:
                tgt = f"{f['host']}:{f['port']}" if f['port'] else f['host']
                print(f"    + [{f['severity'].upper():8}] {tgt}  {f['title']}")
            for f in d["fixed"][:10]:
                tgt = f"{f['host']}:{f['port']}" if f['port'] else f['host']
                print(f"    - (fixed)             {tgt}  {f['title']}")
            for g in d["grade_changes"]:
                print(f"    ~ grade {g['label']}: {g['old']} -> {g['new']}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
