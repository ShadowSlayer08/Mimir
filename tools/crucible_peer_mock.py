#!/usr/bin/env python3
"""tools/crucible_peer_mock.py — a stand-in Crucible peer endpoint.

Phase 25 fix for "the Crucible /slm/peer-opinion endpoint isn't deployed on
the other side yet." This is a DEVELOPMENT-only mock: a minimal stdlib HTTP
server that speaks the same HMAC-signed protocol as `crucible_bridge._request`
so `slm.bridge.query_peer()` can actually exercise the full round-trip.

It is NOT a product feature. The real Crucible endpoint will replace it —
this mock lives under tools/ so it never leaks into the engine's packaging.

Routes:
  POST /slm/peer-opinion
       Body: {"prompt": str, "response": str, "role": str}
       Returns: {"verdict": "agree" | "disagree" | "unsure",
                 "reason": str, "confidence": 0..1}

Verdict heuristic — simple, deterministic, deliberately dumb so you can
assert against it in tests:
  * response empty / only whitespace          -> "disagree"
  * response contains an ATT&CK id (T####)    -> "agree"
  * response contains "<pass>" / "<key>" etc. -> "disagree" (secret leak)
  * otherwise                                 -> "unsure"

Usage:
  export CRUCIBLE_API_KEY=some-shared-secret
  python tools/crucible_peer_mock.py --port 8899

  # on Mimir's side
  export CRUCIBLE_URL=http://localhost:8899
  export CRUCIBLE_API_KEY=some-shared-secret
  mimir-slm peer-sync status            # -> available: true
  mimir-slm reward --with-peer          # fold peer signal into training
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                          # pragma: no cover
            pass


_force_utf8_stdio()


_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_SECRET_RE = re.compile(r"<(pass|key|token|secret|cred)>", re.I)


def _verdict_for(response_text):
    """The simple, deterministic heuristic the mock implements."""
    txt = (response_text or "").strip()
    if not txt:
        return "disagree", "empty response", 0.9
    if _SECRET_RE.search(txt):
        return "disagree", "response leaks a secret placeholder", 0.95
    if _ATTACK_RE.search(txt):
        return "agree", "response grounds in ATT&CK", 0.8
    return "unsure", "no strong signal", 0.3


def _constant_time_eq(a, b):
    try:
        return hmac.compare_digest(a or "", b or "")
    except Exception:                                              # pragma: no cover
        return False


def _sign(method, path, body, key):
    """Same formula as crucible_bridge._sign."""
    msg = (method + "\n" + path + "\n").encode("utf-8") + body
    return hmac.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("[crucible-mock] " + (fmt % args) + "\n")

    def _reply(self, obj, status=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _check_sig(self, body):
        key = self.server.api_key or ""
        if not key:
            return True
        sig = (self.headers.get("X-Mimir-Signature")
               or self.headers.get("X-Crucible-Signature") or "")
        expected = _sign(self.command, self.path, body, key)
        return _constant_time_eq(sig, expected)

    def do_GET(self):                                              # noqa: N802
        # /health is what crucible_bridge.available() probes.
        if not self._check_sig(b""):
            return self._reply({"error": "bad-signature"}, status=401)
        if self.path == "/health":
            return self._reply({"ok": True, "role": "crucible-peer-mock"})
        return self._reply({"error": "unknown-route",
                            "path": self.path}, status=404)

    def do_POST(self):                                             # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if not self._check_sig(body):
            return self._reply({"error": "bad-signature"}, status=401)
        if self.path != "/slm/peer-opinion":
            return self._reply({"error": "unknown-route",
                                "path": self.path}, status=404)
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except Exception:
            return self._reply({"error": "bad-json"}, status=400)
        response_text = payload.get("response") or ""
        verdict, reason, conf = _verdict_for(response_text)
        return self._reply({"verdict": verdict, "reason": reason,
                            "confidence": conf})


def make_server(host, port, api_key):
    srv = ThreadingHTTPServer((host, port), _Handler)
    srv.api_key = api_key
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="crucible-peer-mock",
        description="Dev-only mock of Crucible's /slm/peer-opinion endpoint. "
                    "Lets Mimir's slm.bridge.query_peer actually round-trip "
                    "before the real Crucible endpoint is deployed.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--key", default=os.environ.get("CRUCIBLE_API_KEY"),
                    help="shared secret (HMAC key). "
                         "Defaults to $CRUCIBLE_API_KEY. "
                         "Pass empty string to disable auth for pure dev.")
    args = ap.parse_args(argv)
    srv = make_server(args.host, args.port, args.key or "")
    print(f"[crucible-mock] POST /slm/peer-opinion  "
          f"listening on http://{args.host}:{args.port}  "
          f"({'HMAC on' if args.key else 'AUTH DISABLED (dev)'})",
          file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
