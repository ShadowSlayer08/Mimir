"""VAPT hides intrusive (credential-testing/brute) checks; Red Team shows them."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nmap_analyzer import load_scan, analyze, build_report  # noqa: E402
from modules import dispatch, _is_intrusive  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO, "tests", "fixtures", "full_scan.xml")


def test_is_intrusive_detection():
    assert _is_intrusive({"attack": "T1110.003", "command": "x"})
    assert _is_intrusive({"attack": "T1046", "command": "hydra -L u -P p ssh://x"})
    assert _is_intrusive({"attack": "T1135", "command": "x", "risk": "intrusive"})
    assert not _is_intrusive({"attack": "T1046", "command": "nmap -sV x"})


def _checks(results):
    return [c for r in results for c in r["checks"]]


def test_vapt_hides_redteam_shows():
    hosts, meta, _ = load_scan(FIXTURE)
    report = build_report(hosts, meta, analyze(hosts))
    vapt = dispatch(report, mode="vapt")
    red = dispatch(report, mode="redteam")
    v_checks, r_checks = _checks(vapt), _checks(red)
    assert len(v_checks) < len(r_checks), "VAPT should expose fewer checks than Red Team"
    assert not any(_is_intrusive(c) for c in v_checks), "VAPT must not expose intrusive checks"
    assert any(_is_intrusive(c) for c in r_checks), "Red Team should expose intrusive checks"
    # VAPT annotates what it hid
    assert any("hidden in VAPT mode" in s for r in vapt for s in r["attack_surface"])


def test_default_mode_shows_all():
    hosts, meta, _ = load_scan(FIXTURE)
    report = build_report(hosts, meta, analyze(hosts))
    assert len(_checks(dispatch(report))) == len(_checks(dispatch(report, mode="redteam")))
