"""Shared finding schema (findings.py) + portable config (config.py)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config  # noqa: E402
from findings import finding, validate, FIELDS  # noqa: E402
from nmap_analyzer import _finding as nm_finding  # noqa: E402
from evidence import _finding as ev_finding  # noqa: E402


def test_finding_conforms():
    f = finding("h", 80, "Web", "low", "t", cve=["CVE-2020-1", "CVE-2020-1"])
    assert set(FIELDS).issubset(f)
    assert f["cve"] == ["CVE-2020-1"]          # deduped + sorted
    assert validate(f) == []


def test_validate_catches_drift():
    assert validate({"host": "h"})             # missing fields
    assert validate({**finding("h", 1, "c", "low", "t"), "severity": "nope"})


def test_producers_share_one_schema():
    # both nmap_analyzer and evidence build findings through the canonical factory
    assert nm_finding is finding
    assert ev_finding is finding


def test_config_paths_and_missing_tools():
    for k in ("seclists", "wordlists", "users", "passwords"):
        assert k in config.PATHS
    miss = config.missing_tools(["definitely-not-a-real-tool-xyz", "definitely-not-a-real-tool-xyz"])
    assert miss == ["definitely-not-a-real-tool-xyz"]   # reported once (deduped)
