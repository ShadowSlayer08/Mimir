"""mcp_server.py — read-only MCP surface over an engagement.

Locks two things: the JSON-RPC dispatch works, and the surface stays READ-ONLY —
there is no tool that runs, exploits, executes or writes.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mcp_server as m  # noqa: E402

ENG = {
    "meta": {"target": "10.0.0.0/24", "mode": "vapt",
             "severity_counts": {"critical": 1, "high": 2}, "unique_cves": ["CVE-2017-0144"]},
    "hosts": [{"label": "dc01", "ip": "10.0.0.5", "os": "Windows", "grade": "F",
               "score": 20, "open_ports": 3,
               "ports": [{"port": 445, "service": "microsoft-ds"}]}],
    "findings": [
        {"severity": "critical", "host": "dc01", "port": 445, "title": "EternalBlue",
         "category": "CVE", "cve": ["CVE-2017-0144"]},
        {"severity": "high", "host": "web", "port": 80, "title": "Heartbleed",
         "category": "CVE", "cve": []},
    ],
    "attack_paths": [{"id": "AP-001", "name": "Domain compromise", "kind": "domain",
                      "severity": "critical", "confidence": "high", "score": 120,
                      "steps": [{"order": 1, "tactic": "Initial Access",
                                 "technique_id": "T1190", "technique": "Exploit Public App",
                                 "host": "dc01", "guidance": "validate MS17-010"}]}],
    "recommendations": [],
}


def test_initialize_and_serverinfo():
    resp = m.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, ENG)
    assert resp["result"]["protocolVersion"] == m.PROTOCOL_VERSION
    assert resp["result"]["serverInfo"]["name"] == "mimir-engagement"
    assert "STAGING ONLY" in resp["result"]["instructions"]


def test_initialized_notification_has_no_reply():
    assert m.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, ENG) is None


def test_tools_list_shape():
    resp = m.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, ENG)
    tools = resp["result"]["tools"]
    assert len(tools) >= 6
    for t in tools:
        assert t["name"] and t["description"] and "inputSchema" in t


def test_surface_is_read_only():
    # Every tool is a read verb (get_/list_); none exploits/executes/writes.
    names = [t["name"] for t in m.tool_defs()]
    assert all(n.startswith(("get_", "list_")) for n in names), \
        "read-only surface must expose only get_/list_ tools; got " + repr(names)
    joined = " ".join(names)
    for banned in ("exploit", "exec", "launch", "stage_step", "write_", "delete"):
        assert banned not in joined, "read-only surface must not expose: " + banned


def test_call_summary_and_filters():
    r = m.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                  "params": {"name": "get_engagement_summary", "arguments": {}}}, ENG)
    assert r["result"]["isError"] is False
    assert "STAGING ONLY" in r["result"]["content"][0]["text"]

    r = m.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                  "params": {"name": "list_findings", "arguments": {"severity": "critical"}}}, ENG)
    import json
    data = json.loads(r["result"]["content"][0]["text"])
    assert len(data) == 1 and data[0]["title"] == "EternalBlue"


def test_get_attack_path_ok_and_missing():
    ok = m.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                   "params": {"name": "get_attack_path", "arguments": {"id": "AP-001"}}}, ENG)
    assert ok["result"]["isError"] is False and "T1190" in ok["result"]["content"][0]["text"]

    bad = m.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                    "params": {"name": "get_attack_path", "arguments": {"id": "AP-999"}}}, ENG)
    assert bad["result"]["isError"] is True


def test_unknown_method_errors():
    resp = m.handle({"jsonrpc": "2.0", "id": 7, "method": "does/not/exist"}, ENG)
    assert resp["error"]["code"] == -32601
