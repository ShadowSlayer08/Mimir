"""timeline.py — engagement timeline from the ledger.

Locks the three properties: load handles a real DB shape, markdown output
covers span + runs + findings, and SVG output is well-formed with per-run ticks.
"""
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import timeline  # noqa: E402


def _seed_db():
    """Create a tiny ledger DB with 2 runs, 3 findings, 1 host."""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="tl-test-")
    os.close(fd)
    con = sqlite3.connect(path)
    con.executescript("""
CREATE TABLE runs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, mode TEXT,
                  source TEXT, target TEXT, hosts INT, findings INT, paths INT);
CREATE TABLE hosts(key TEXT PRIMARY KEY, ip TEXT, label TEXT, os TEXT, grade TEXT,
                   first_seen TEXT, last_seen TEXT, seen INT);
CREATE TABLE findings(key TEXT PRIMARY KEY, host TEXT, port INT, category TEXT,
                      severity TEXT, title TEXT, cve TEXT, first_seen TEXT,
                      last_seen TEXT, seen INT);
""")
    con.executemany("INSERT INTO runs(ts,mode,source,target,hosts,findings,paths) "
                    "VALUES(?,?,?,?,?,?,?)", [
        ("2026-07-01T09:00:00+00:00", "vapt", "xml", "10.0.0.0/24", 2, 4, 1),
        ("2026-07-05T14:30:00+00:00", "redteam", "xml", "10.0.0.0/24", 2, 6, 2),
    ])
    con.executemany("INSERT INTO hosts VALUES(?,?,?,?,?,?,?,?)", [
        ("h1", "10.0.0.5", "dc01.corp.lab", "Windows", "F",
         "2026-07-01T09:00:00+00:00", "2026-07-05T14:30:00+00:00", 2),
    ])
    con.executemany("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?)", [
        ("f1", "dc01.corp.lab", 445, "CVE (vulners)", "critical", "EternalBlue",
         "CVE-2017-0144", "2026-07-01T09:00:00+00:00", "2026-07-05T14:30:00+00:00", 2),
        ("f2", "dc01.corp.lab", 22, "CVE (vulners)", "high", "OpenSSH",
         "", "2026-07-01T09:00:00+00:00", "2026-07-01T09:00:00+00:00", 1),
        ("f3", "web.corp.lab", 80, "Protocol", "medium", "Plain HTTP",
         "", "2026-07-05T14:30:00+00:00", "2026-07-05T14:30:00+00:00", 1),
    ])
    con.commit()
    con.close()
    return path


def test_load_missing_db_is_safe():
    tl = timeline.load("/does/not/exist.db")
    assert tl == {"runs": [], "findings": [], "hosts": [], "span": None}


def test_load_shape_and_span():
    p = _seed_db()
    try:
        tl = timeline.load(p)
    finally:
        os.unlink(p)
    assert len(tl["runs"]) == 2
    assert len(tl["findings"]) == 3
    assert len(tl["hosts"]) == 1
    assert tl["span"]["days"] >= 4                                # 2026-07-01 -> 2026-07-05


def test_markdown_covers_span_runs_findings():
    p = _seed_db()
    try:
        md = timeline.to_markdown(timeline.load(p))
    finally:
        os.unlink(p)
    assert "# Engagement timeline" in md
    assert "Span:" in md and "day(s)" in md
    assert "run #1" in md and "run #2" in md
    assert "EternalBlue" in md
    assert "CRITICAL" in md


def test_svg_wellformed_with_per_run_ticks():
    p = _seed_db()
    try:
        svg = timeline.to_svg(timeline.load(p))
    finally:
        os.unlink(p)
    assert svg.startswith('<svg') and svg.endswith('</svg>')
    assert svg.count("<line") >= 3                                # axis + 2 run ticks
    assert svg.count("<circle") == 3                              # one per finding
    assert 'role="img"' in svg


def test_svg_empty_ledger_renders_placeholder():
    svg = timeline.to_svg({"runs": [], "findings": [], "hosts": [], "span": None})
    assert svg.startswith("<svg") and "No timeline data" in svg
