"""service_risk false-positive fix (TLS variants) + severity banding."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nmap_analyzer import service_risk, cvss_severity  # noqa: E402


def test_tls_variants_not_flagged_cleartext():
    # https/imaps/ftps/pop3s reported by name (no tunnel attr) must NOT be cleartext.
    for n in ("https", "imaps", "ftps", "pop3s"):
        assert service_risk(n, 0, "", "") is None, n


def test_tunneled_cleartext_suppressed():
    assert service_risk("http", 443, "", "ssl") is None        # tunnel=ssl
    assert service_risk("imap", 993, "", "ssl") is None


def test_genuine_cleartext_still_flagged():
    assert service_risk("http", 0, "", "") is not None
    assert "cleartext" in service_risk("ftp", 0, "", "")[2].lower()
    assert service_risk("telnet", 0, "", "") is not None


def test_cvss_bands():
    assert cvss_severity(9.8) == "critical"
    assert cvss_severity(7.0) == "high"
    assert cvss_severity(4.0) == "medium"
    assert cvss_severity(0.5) == "low"
    assert cvss_severity(0) == "info"
    assert cvss_severity("not-a-number") == "info"
