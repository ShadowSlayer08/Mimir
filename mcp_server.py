#!/usr/bin/env python3
"""
mcp_server.py — a READ-ONLY MCP server over an engagement.

Authorized / lab / CTF use only.

Exposes the engine's engagement JSON (from `assess --emit-json`) as Model Context
Protocol tools, so an operator's LLM (Claude Desktop, Claude Code, or a local model)
can QUERY the live engagement and reason about it — inventory, findings, staged
attack paths, next-best-actions, and the operator runbook.

BOUNDARY — this surface is strictly READ-ONLY and STAGING-ONLY:
  * Every tool only reads already-computed data. Nothing scans, nothing executes,
    nothing is written back. There is deliberately no run/exploit tool.
  * The engine stages methodology; a human operator runs each step manually, in scope.

Transport: JSON-RPC 2.0 over stdio, newline-delimited (one message per line) — the
standard MCP stdio framing. No third-party dependency.

    python mcp_server.py engagement.json          # serve over stdio
    python mcp_server.py engagement.json --selftest   # offline dispatch check

Wire into an MCP client (example, Claude Desktop config):
    "mimir": {"command": "python", "args": ["mcp_server.py", "/path/eng.json"]}
"""
from __future__ import annotations

import json
import sys

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "mimir-engagement", "version": "1.0.0"}

BOUNDARY = ("STAGING ONLY — read-only surface. These tools report already-computed "
            "engagement data; they scan nothing and execute nothing. A human operator "
            "runs each staged step manually, in authorized scope.")


def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr, sys.stdin):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                          # pragma: no cover
            pass


_force_utf8_stdio()


# --------------------------------------------------------------------------- #
# Tool catalogue (read-only). inputSchema is minimal JSON Schema.
def tool_defs():
    return [
        {"name": "get_engagement_summary",
         "description": "Engagement metadata: target, mode, severity counts, unique CVEs, "
                        "host/finding/path totals, and the staging-only boundary.",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "list_hosts",
         "description": "Inventory: hosts with OS, grade/score, open-port count and services.",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "list_findings",
         "description": "Findings, optionally filtered by severity and/or host label.",
         "inputSchema": {"type": "object", "properties": {
             "severity": {"type": "string",
                          "enum": ["critical", "high", "medium", "low", "info"]},
             "host": {"type": "string", "description": "host label / ip substring"}}}},
        {"name": "list_attack_paths",
         "description": "Staged ATT&CK attack paths (id, name, kind, severity, score, step count).",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "get_attack_path",
         "description": "Full detail of one staged attack path, including every ATT&CK step "
                        "with its tactic, technique id, host and methodology guidance.",
         "inputSchema": {"type": "object",
                         "properties": {"id": {"type": "string", "description": "path id, e.g. AP-001"}},
                         "required": ["id"]}},
        {"name": "get_next_actions",
         "description": "The co-pilot's ranked next-best-actions from the current state.",
         "inputSchema": {"type": "object",
                         "properties": {"top": {"type": "integer", "default": 10}}}},
        {"name": "get_runbook",
         "description": "The deterministic operator runbook (Markdown checklist of staged paths). "
                        "Methodology only; the operator runs each item manually, in scope.",
         "inputSchema": {"type": "object", "properties": {}}},
    ]


# --------------------------------------------------------------------------- #
# Tool implementations — pure reads over the loaded engagement dict.
def _text(obj):
    if isinstance(obj, str):
        return obj
    return json.dumps(obj, indent=2, ensure_ascii=False)


def call_tool(name, args, eng):
    """Return the tool result payload (str or JSON-able). Raises KeyError on bad path id."""
    args = args or {}
    if name == "get_engagement_summary":
        meta = eng.get("meta", {})
        return {"target": meta.get("target", ""), "mode": meta.get("mode", ""),
                "generated": meta.get("generated", ""), "offline": meta.get("offline"),
                "severity_counts": meta.get("severity_counts", {}),
                "unique_cves": meta.get("unique_cves", []),
                "hosts": len(eng.get("hosts", [])),
                "findings": len(eng.get("findings", [])),
                "attack_paths": len(eng.get("attack_paths", [])),
                "boundary": BOUNDARY}
    if name == "list_hosts":
        return [{"label": h.get("label"), "ip": h.get("ip"), "os": h.get("os"),
                 "grade": h.get("grade"), "score": h.get("score"),
                 "open_ports": h.get("open_ports"),
                 "services": [f"{p.get('port')}/{p.get('service')}" for p in h.get("ports", [])]}
                for h in eng.get("hosts", [])]
    if name == "list_findings":
        sev = (args.get("severity") or "").lower()
        host = (args.get("host") or "").lower()
        out = []
        for f in eng.get("findings", []):
            if sev and (f.get("severity") or "").lower() != sev:
                continue
            if host and host not in (f.get("host") or "").lower():
                continue
            out.append({"severity": f.get("severity"), "host": f.get("host"),
                        "port": f.get("port"), "title": f.get("title"),
                        "category": f.get("category"), "cve": f.get("cve", [])})
        return out
    if name == "list_attack_paths":
        return [{"id": p.get("id"), "name": p.get("name"), "kind": p.get("kind"),
                 "severity": p.get("severity"), "confidence": p.get("confidence"),
                 "score": p.get("score"), "steps": len(p.get("steps", []))}
                for p in eng.get("attack_paths", [])]
    if name == "get_attack_path":
        pid = args.get("id", "")
        for p in eng.get("attack_paths", []):
            if p.get("id") == pid:
                return p
        raise KeyError(f"no attack path with id {pid!r}")
    if name == "get_next_actions":
        from copilot import recommend_from_engagement
        return recommend_from_engagement(eng, int(args.get("top", 10) or 10))
    if name == "get_runbook":
        from advisor import basic_runbook_md
        return basic_runbook_md(eng)
    raise KeyError(f"unknown tool {name!r}")


# --------------------------------------------------------------------------- #
# JSON-RPC plumbing
def _result(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def handle(msg, eng):
    """Dispatch one JSON-RPC request. Returns a response dict, or None for notifications."""
    method = msg.get("method")
    msg_id = msg.get("id")
    if method == "initialize":
        return _result(msg_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
            "instructions": BOUNDARY})
    if method in ("notifications/initialized", "initialized"):
        return None                                        # notification — no reply
    if method == "ping":
        return _result(msg_id, {})
    if method == "tools/list":
        return _result(msg_id, {"tools": tool_defs()})
    if method == "tools/call":
        params = msg.get("params", {}) or {}
        name = params.get("name", "")
        try:
            payload = call_tool(name, params.get("arguments", {}), eng)
            return _result(msg_id, {"content": [{"type": "text", "text": _text(payload)}],
                                    "isError": False})
        except KeyError as exc:
            return _result(msg_id, {"content": [{"type": "text", "text": str(exc)}],
                                    "isError": True})
        except Exception as exc:                           # pragma: no cover
            return _result(msg_id, {"content": [{"type": "text", "text": f"error: {exc}"}],
                                    "isError": True})
    if msg_id is None:
        return None                                        # unknown notification
    return _error(msg_id, -32601, f"method not found: {method}")


def serve(eng, stdin=None, stdout=None):
    """Newline-delimited JSON-RPC loop over stdio (blocks until EOF)."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        resp = handle(msg, eng)
        if resp is not None:
            stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            stdout.flush()


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="mcp_server.py",
        description="read-only MCP server over an engagement JSON (assess --emit-json). "
                    "Query-only; stages and executes nothing.")
    ap.add_argument("engagement", help="engagement JSON file (from assess --emit-json)")
    ap.add_argument("--selftest", action="store_true",
                    help="run an offline dispatch check (no stdio loop) and exit")
    args = ap.parse_args(argv)
    eng = _load(args.engagement)

    if args.selftest:
        for req in ({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "get_engagement_summary", "arguments": {}}}):
            resp = handle(req, eng)
            tag = req["method"]
            if tag == "tools/list":
                print(f"[mcp] tools/list -> {len(resp['result']['tools'])} tools: "
                      + ", ".join(t["name"] for t in resp["result"]["tools"]))
            elif tag == "initialize":
                print(f"[mcp] initialize -> {resp['result']['serverInfo']['name']} "
                      f"(protocol {resp['result']['protocolVersion']})")
            else:
                print("[mcp] get_engagement_summary ->",
                      resp["result"]["content"][0]["text"][:200].replace("\n", " "))
        print("[mcp] selftest OK — read-only, staging-only surface")
        return 0

    serve(eng)
    return 0


if __name__ == "__main__":
    sys.exit(main())
