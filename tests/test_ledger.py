"""Engagement ledger accretes hosts/findings across runs."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ledger import record_run, history  # noqa: E402


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
