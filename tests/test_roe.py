"""roe.py — Rules of Engagement hard-gates.

Locks the "professional-grade governance" contract: ROE filters the staged
queue with EXPLANATIONS attached to every rejection, never silently, never
crash-permissive, never dropping the original data.
"""
import os
import sys
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import roe  # noqa: E402


_PATHS = [
    {"id": "P-1", "kind": "rce", "hosts": ["10.0.0.5"],
     "steps": [{"technique_id": "T1190", "host": "10.0.0.5"}]},
    {"id": "P-2", "kind": "domain", "hosts": ["dc01.corp.lab"],
     "steps": [{"technique_id": "T1003", "host": "dc01.corp.lab"}]},
    {"id": "P-3", "kind": "lateral", "hosts": ["10.99.99.99"],
     "steps": [{"technique_id": "T1078", "host": "10.99.99.99"}]},
    {"id": "P-4", "kind": "rce", "hosts": ["prod-db.acme.example"],
     "steps": [{"technique_id": "T1499", "host": "prod-db.acme.example"}]},   # DoS
]
_MODULES = [
    {"module": "smb", "target": "10.0.0.5", "checks": [
        {"name": "SMB enum", "attack": "T1046", "risk": "safe"},
        {"name": "PetitPotam coercion", "attack": "T1187", "risk": "intrusive"},
    ]},
    {"module": "web_app", "target": "http://prod-db.acme.example/", "checks": [
        {"name": "Fingerprint", "attack": "T1592.002", "risk": "safe"},
    ]},
]


def _write_yaml(text):
    fd, path = tempfile.mkstemp(suffix=".yml", prefix="roe-test-")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


# ---- rule parsing -------------------------------------------------------- #
def test_load_missing_file_is_permissive():
    assert roe.load("/does/not/exist.yml") == {}


def test_load_and_normalise_shape():
    p = _write_yaml("""
engagement: acme-2026Q3
jurisdiction: US-CA
in_scope: [10.0.0.0/24]
out_of_scope: [10.0.0.99]
allowed_windows:
  - {days: [mon,tue,wed,thu,fri], hours: ['18:00', '23:59']}
forbidden_techniques: [T1499, T1499.001]
forbidden_risk: [intrusive]
forbidden_kinds: [webapp]
""")
    try:
        rules = roe.load(p)
    finally:
        os.unlink(p)
    assert rules["engagement"] == "acme-2026Q3"
    assert rules["jurisdiction"] == "US-CA"
    assert "T1499" in rules["forbidden_techniques"]
    assert rules["forbidden_risk"] == {"intrusive"}
    assert rules["forbidden_kinds"] == {"webapp"}
    assert rules["in_scope"] == ["10.0.0.0/24"]
    assert len(rules["allowed_windows"]) == 1


# ---- filtering ----------------------------------------------------------- #
def test_scope_out_of_scope_wins():
    rules = roe._normalise({
        "in_scope": ["10.0.0.0/24"], "out_of_scope": ["10.0.0.5"],
    })
    kept, rejected = roe.filter_engagement(rules, _PATHS, [])
    ids = [p["id"] for p in kept["paths"]]
    assert "P-1" not in ids                        # 10.0.0.5 explicitly out
    assert any(r["id"] == "P-1" and r["reason"] == "out_of_scope" for r in rejected)


def test_scope_cidr_and_suffix_match():
    rules = roe._normalise({"in_scope": ["10.0.0.0/24", ".corp.lab"]})
    kept, _ = roe.filter_engagement(rules, _PATHS, [])
    ids = {p["id"] for p in kept["paths"]}
    assert "P-1" in ids and "P-2" in ids           # matched
    assert "P-3" not in ids and "P-4" not in ids   # rejected


def test_forbidden_technique_filters_step():
    rules = roe._normalise({"forbidden_techniques": ["T1499"]})
    kept, rejected = roe.filter_engagement(rules, _PATHS, [])
    ids = {p["id"] for p in kept["paths"]}
    assert "P-4" not in ids
    assert any(r["reason"] == "forbidden_technique:T1499" for r in rejected)


def test_forbidden_kind_filters_path():
    rules = roe._normalise({"forbidden_kinds": ["domain"]})
    kept, rejected = roe.filter_engagement(rules, _PATHS, [])
    assert not any(p["kind"] == "domain" for p in kept["paths"])
    assert any(r["reason"] == "forbidden_kind:domain" for r in rejected)


def test_forbidden_risk_hides_intrusive_checks():
    rules = roe._normalise({"forbidden_risk": ["intrusive"]})
    kept, rejected = roe.filter_engagement(rules, [], _MODULES)
    smb = next(m for m in kept["modules"] if m["module"] == "smb")
    names = [c["name"] for c in smb["checks"]]
    assert "SMB enum" in names and "PetitPotam coercion" not in names
    assert any(r["kind"] == "check" and "intrusive" in r["reason"] for r in rejected)


def test_time_window_gate():
    # Only Tue 18:00-20:00 is allowed. Use explicit-UTC timestamps so the test
    # is timezone-stable — the engine reads .weekday() / .hour from the given ts.
    rules = roe._normalise({
        "allowed_windows": [{"days": ["tue"], "hours": ["18:00", "20:00"]}],
    })
    # 2026-07-07 is a Tuesday.
    ok_ts = datetime(2026, 7, 7, 18, 30, tzinfo=timezone.utc)
    kept_ok, _ = roe.filter_engagement(rules, _PATHS, [], at_ts=ok_ts)
    assert len(kept_ok["paths"]) > 0
    bad_ts = datetime(2026, 7, 7, 10, 30, tzinfo=timezone.utc)          # Tue 10:30 UTC — before window
    kept_bad, rejected_bad = roe.filter_engagement(rules, _PATHS, [], at_ts=bad_ts)
    assert kept_bad["paths"] == []
    assert all(r["reason"] == "outside_allowed_window" for r in rejected_bad
               if r["kind"] == "path")


def test_rejection_carries_jurisdiction_tag():
    rules = roe._normalise({"jurisdiction": "EU-DE",
                            "forbidden_kinds": ["domain"]})
    _, rejected = roe.filter_engagement(rules, _PATHS, [])
    dom = next(r for r in rejected if r["reason"].startswith("forbidden_kind"))
    assert dom["jurisdiction"] == "EU-DE"


def test_empty_rules_is_permissive():
    kept, rejected = roe.filter_engagement({}, _PATHS, _MODULES)
    assert len(kept["paths"]) == len(_PATHS)
    assert rejected == []
