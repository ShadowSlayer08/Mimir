"""Composite risk model (docs/risk_scoring.md) wired into nmap_analyzer."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nmap_analyzer import composite_risk, get_risk_config  # noqa: E402


def test_weights_sum_to_one():
    cfg = get_risk_config()
    assert abs(sum(cfg["weights"].values()) - 1.0) < 1e-9


def test_kev_overrides_to_critical():
    score, band = composite_risk(2.0, kev=True)
    assert band == "critical" and score == 100


def test_public_exploit_floors_at_high():
    # low CVSS, isolated, low business — would be 'low', but a public exploit floors it
    score, band = composite_risk(3.0, exposure=0.2, business=0.2, public_exploit=True)
    assert band in ("high", "critical") and score >= 60


def test_internet_facing_high_business_is_critical():
    score, band = composite_risk(9.8, exposure=1.0, business=1.0)
    assert band == "critical" and score >= 80


def test_defaults_downweight_unexploited_cvss():
    # 9.8 with no EPSS/KEV/exploit and default exposure+business -> not auto-critical
    score, band = composite_risk(9.8)
    assert band == "high" and 60 <= score < 80


def test_low_isolated_stays_low():
    score, band = composite_risk(2.0, exposure=0.2, business=0.2)
    assert band in ("info", "low")


def test_epss_raises_score():
    # same CVSS/exposure/business; a high EPSS must push the composite up
    base, _ = composite_risk(7.0, exposure=0.5, business=0.5)
    hot, _ = composite_risk(7.0, epss=0.97, exposure=0.5, business=0.5)
    assert hot > base


def test_out_of_range_exposure_business_clamped():
    # bad per-asset input (e.g. exposure: 5, business: -2) must not blow the score
    score, band = composite_risk(9.8, exposure=5.0, business=-2.0)
    assert 0 <= score <= 100 and band in ("critical", "high", "medium", "low", "info")
