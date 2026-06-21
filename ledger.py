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

        for f in report.get("findings", []):
            con.execute(
                "INSERT INTO findings(key,host,port,category,severity,title,cve,first_seen,last_seen,seen) "
                "VALUES(?,?,?,?,?,?,?,?,?,1) ON CONFLICT(key) DO UPDATE SET "
                "last_seen=excluded.last_seen, severity=excluded.severity, seen=seen+1",
                (_fkey(f), f.get("host", ""), f.get("port", 0) or 0, f.get("category", ""),
                 f.get("severity", ""), f.get("title", ""), ";".join(f.get("cve", [])), ts, ts))

        for p in paths:
            con.execute(
                "INSERT INTO attack_paths(run_id,pid,name,kind,severity,confidence,score) VALUES(?,?,?,?,?,?,?)",
                (run_id, p.get("id", ""), p.get("name", ""), p.get("kind", ""),
                 p.get("severity", ""), p.get("confidence", ""), p.get("score", 0)))
        con.commit()
        return run_id
    finally:
        con.close()


def history(db_path):
    con = _connect(db_path)
    try:
        runs = con.execute("SELECT id,ts,mode,source,target,hosts,findings,paths "
                           "FROM runs ORDER BY id").fetchall()
        n_hosts = con.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        n_find = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        recurring = con.execute("SELECT severity,host,port,title,seen FROM findings "
                                "WHERE seen>1 ORDER BY seen DESC, severity LIMIT 20").fetchall()
        return runs, n_hosts, n_find, recurring
    finally:
        con.close()


def main():
    import sys
    if len(sys.argv) < 2:
        print("usage: python ledger.py <engagement.db>"); return 1
    runs, n_hosts, n_find, recurring = history(sys.argv[1])
    print(f"[+] {len(runs)} run(s) · {n_hosts} unique host(s) · {n_find} unique finding(s)\n")
    for r in runs:
        print(f"  run #{r[0]:<3} {r[1]}  mode={r[2]:<8} src={r[3]:<8} target={r[4]:<22} "
              f"hosts={r[5]} findings={r[6]} paths={r[7]}")
    if recurring:
        print("\n  recurring findings (seen in >1 run):")
        for sev, host, port, title, seen in recurring:
            tgt = f"{host}:{port}" if port else host
            print(f"    [{sev.upper():8}] x{seen}  {tgt}  {title}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
