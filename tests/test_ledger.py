"""Engagement ledger accretes hosts/findings across runs."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ledger import (record_run, history, diff,  # noqa: E402
                    set_triage, get_triage, finding_key)


def _report(grade="C"):
    return {
        "totals": {"hosts": 1, "open_ports": 2, "findings": 1},
        "host_summary": [{"host": "h1", "ip": "10.0.0.1", "os": "Linux", "grade": grade}],
        "findings": [{"host": "10.0.0.1", "port": 445, "category": "File Sharing",
                      "severity": "medium", "title": "SMB exposed", "cve": []}],
        "unique_cves": [],
    }


def test_ledger_accretes():
    fd, db = tempfile.mkstemp(suffix=".db"); os.close(fd); os.unlink(db)
    try:
        scan = {"mode": "vapt", "target": "10.0.0.1"}
        r1 = record_run(db, _report("C"), [], [], scan)
        r2 = record_run(db, _report("F"), [], [], scan)
        assert r1 == 1 and r2 == 2
        runs, n_hosts, n_find, recurring = history(db)
        assert len(runs) == 2                 # two runs recorded
        assert n_hosts == 1                   # same host upserted, not duplicated
        assert n_find == 1                    # same finding upserted
        assert recurring and recurring[0][4] == 2   # finding seen in both runs
    finally:
        if os.path.exists(db):
            os.unlink(db)


def _report2():
    """A different finding set + grade than _report() — one fixed, one new."""
    return {
        "totals": {"hosts": 1, "open_ports": 2, "findings": 1},
        "host_summary": [{"host": "h1", "ip": "10.0.0.1", "os": "Linux", "grade": "F"}],
        "findings": [{"host": "10.0.0.1", "port": 22, "category": "Auth",
                      "severity": "high", "title": "SSH weak", "cve": []}],
        "unique_cves": [],
    }


def test_ledger_diff_new_fixed_grade():
    fd, db = tempfile.mkstemp(suffix=".db"); os.close(fd); os.unlink(db)
    try:
        scan = {"mode": "vapt", "target": "10.0.0.1"}
        record_run(db, _report("C"), [], [], scan)      # SMB exposed @445, grade C
        record_run(db, _report2(), [], [], scan)         # SSH weak @22, grade F
        d = diff(db)
        assert d is not None
        assert "SSH weak" in {f["title"] for f in d["new"]}
        assert "SMB exposed" in {f["title"] for f in d["fixed"]}
        assert d["still_open"] == []
        assert any(g["old"] == "C" and g["new"] == "F" for g in d["grade_changes"])
    finally:
        if os.path.exists(db):
            os.unlink(db)


def test_triage_persists_and_partial_update():
    fd, db = tempfile.mkstemp(suffix=".db"); os.close(fd); os.unlink(db)
    try:
        record_run(db, _report("C"), [], [], {"mode": "vapt", "target": "x"})
        k = finding_key({"host": "10.0.0.1", "port": 445, "title": "SMB exposed"})
        set_triage(db, k, status="false_positive", owner="alice")
        set_triage(db, k, notes="benign on this host")   # partial update keeps status/owner
        t = get_triage(db, k)
        assert t["status"] == "false_positive" and t["owner"] == "alice"
        assert t["notes"] == "benign on this host"
    finally:
        if os.path.exists(db):
            os.unlink(db)


def test_triage_mutes_finding_in_diff():
    fd, db = tempfile.mkstemp(suffix=".db"); os.close(fd); os.unlink(db)
    try:
        scan = {"mode": "vapt", "target": "10.0.0.1"}
        record_run(db, _report("C"), [], [], scan)       # SMB exposed @445
        set_triage(db, finding_key({"host": "10.0.0.1", "port": 445, "title": "SMB exposed"}),
                   status="false_positive")                # operator dispositions it
        record_run(db, _report("C"), [], [], scan)         # same finding recurs
        d = diff(db)
        assert all(f["title"] != "SMB exposed" for f in d["still_open"])   # not nagged
        assert any(f["title"] == "SMB exposed" for f in d["muted"])        # muted instead
    finally:
        if os.path.exists(db):
            os.unlink(db)


def test_triage_severity_override_applied_in_diff():
    fd, db = tempfile.mkstemp(suffix=".db"); os.close(fd); os.unlink(db)
    try:
        scan = {"mode": "vapt", "target": "10.0.0.1"}
        record_run(db, _report("C"), [], [], scan)
        k = finding_key({"host": "10.0.0.1", "port": 445, "title": "SMB exposed"})
        set_triage(db, k, status="confirmed", severity_override="critical")
        record_run(db, _report("C"), [], [], scan)
        d = diff(db)
        smb = [f for f in d["still_open"] if f["title"] == "SMB exposed"]
        assert smb and smb[0]["severity"] == "critical"   # override applied (status not muted)
    finally:
        if os.path.exists(db):
            os.unlink(db)
