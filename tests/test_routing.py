"""Best-match service routing: exact > prefix > substring (the ftp/tftp fix)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from knowledge_loader import load_knowledge  # noqa: E402


def test_tftp_not_routed_to_ftp():
    kb = load_knowledge()
    assert kb.modules_for("tftp") == ["tftp"]      # 'ftp' is a substring — must NOT win
    assert kb.modules_for("ftp") == ["ftp"]
    assert kb.modules_for("ftps") == ["ftp"]


def test_vnc_http_not_routed_to_web():
    kb = load_knowledge()
    assert kb.modules_for("vnc-http") == ["vnc"]   # 'http' is a substring — must NOT win
    assert kb.modules_for("https") == ["web"]
    assert kb.modules_for("http") == ["web"]


def test_specific_services_route():
    kb = load_knowledge()
    assert kb.modules_for("ms-wbt-server") == ["rdp"]
    assert kb.modules_for("winrm") == ["winrm"]    # overrides the developer_guide example
    assert kb.modules_for("snmp") == ["snmp"]
    assert "active_directory" in kb.modules_for("kerberos")


def test_unknown_service_routes_nowhere():
    kb = load_knowledge()
    assert kb.modules_for("totally-unknown-svc-xyz") == []
