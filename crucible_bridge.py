#!/usr/bin/env python3
"""
crucible_bridge.py — bidirectional bridge between Mimir and Crucible (AI red-team).

Authorized / lab / CTF / VAPT / red-team use only.

Mimir pentests infrastructure + apps + AI endpoints (via `modules/ai_target.py`).
Crucible is the operator's AI-red-team tool specialising in adversarial LLM
testing. The bridge connects the two directions:

  Mimir -> Crucible:
    When Mimir stages an `ai_target` check and Crucible is configured, Mimir
    forwards the target + the relevant check metadata to Crucible so Crucible
    runs the deep adversarial probe. Mimir ingests Crucible's finding JSON back
    as additional findings on the engagement.

  Crucible -> Mimir:
    Mimir's MCP server (mcp_server.py) is the stable query surface — Crucible
    reads engagement context (hosts, findings, attack paths) through the MCP
    tools/list contract. Crucible also POSTs its own adversarial findings into
    Mimir via POST /bridge/crucible/finding on this bridge (operator-key gated).

Both directions STAGE results; neither executes anything on the target. Mimir
has no execution engine; Crucible is the operator's own tool and the operator
runs each adversarial probe deliberately.

Config (environment):
  CRUCIBLE_URL        e.g. http://127.0.0.1:9000     (Crucible API base)
  CRUCIBLE_API_KEY    operator-held secret           (HMAC auth, never logged)
  CRUCIBLE_TIMEOUT    seconds per request            (default 60)

Offline-safe: when CRUCIBLE_URL is unset or Crucible is unreachable, Mimir
runs its own in-tree ai_target methodology unchanged. The bridge adds depth
when both tools are on the operator's workstation; it never replaces either.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request


def _env(key, default=None):
    return (os.environ.get("MIMIR_" + key)
            or os.environ.get("VANTAGE_" + key)                  # historical
            or os.environ.get(key, default))


def _url():
    u = _env("CRUCIBLE_URL") or _env("CRUCIBLE_BASE_URL")
    return (u.rstrip("/") if u else "")


def _key():
    return _env("CRUCIBLE_API_KEY") or ""


def _timeout():
    try:
        return float(_env("CRUCIBLE_TIMEOUT", "60"))
    except (TypeError, ValueError):
        return 60.0


def available():
    """True if Crucible is configured AND reachable (one-shot ping)."""
    if not (_url() and _key()):
        return False
    try:
        return bool(_request("GET", "/health", timeout=min(_timeout(), 5)))
    except Exception:                                             # pragma: no cover
        return False


# --------------------------------------------------------------------------- #
def _sign(method, path, body_bytes):
    """HMAC-SHA256 request signature: op API key signs `method\\npath\\nbody`."""
    msg = f"{method}\n{path}\n".encode("utf-8") + (body_bytes or b"")
    return hmac.new(_key().encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _request(method, path, body=None, timeout=None):
    """Signed HTTP call to Crucible. Returns parsed JSON or None on failure."""
    base = _url()
    if not base:
        return None
    url = base + path
    data = json.dumps(body).encode("utf-8") if body is not None else b""
    headers = {
        "User-Agent": "mimir-crucible-bridge/1.0",
        "Accept": "application/json",
        "X-Mimir-Signature": _sign(method, path, data),
        "X-Mimir-Timestamp": str(int(time.time())),
    }
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=(data if data else None),
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout or _timeout()) as resp:
            raw = resp.read().decode("utf-8", "replace")
        return json.loads(raw) if raw else None
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError,
            ValueError):
        return None


# --------------------------------------------------------------------------- #
# Mimir -> Crucible
def forward_ai_target(target, mimir_engagement_id=None, timeout=None):
    """Hand off an `ai_target` to Crucible for deep adversarial probing.
    Returns Crucible's job id (string) or None if the bridge is offline."""
    if not available():
        return None
    body = {
        "mimir_engagement_id": mimir_engagement_id,
        "target": {
            "endpoint": target.get("ref") or target.get("host") or "",
            "host":     target.get("host", ""),
            "label":    target.get("label", ""),
        },
        "probe_sets": ["prompt-injection", "jailbreak", "output-handling",
                       "tool-abuse", "model-extraction"],
    }
    r = _request("POST", "/jobs/ai-target", body, timeout=timeout)
    if not isinstance(r, dict):
        return None
    return r.get("job_id") or r.get("id")


def collect_findings(job_id, timeout=None):
    """Pull Crucible's findings for a prior ai-target job. Returns a list of
    finding dicts in Mimir's shape (host/port/category/severity/title/cve) with
    an added `source: 'crucible'` tag — merge-ready."""
    if not job_id or not available():
        return []
    r = _request("GET", f"/jobs/{job_id}/findings", timeout=timeout)
    if not isinstance(r, dict):
        return []
    out = []
    for f in (r.get("findings") or []):
        if not isinstance(f, dict):
            continue
        out.append({
            "host":     f.get("endpoint") or f.get("host") or "ai",
            "port":     int(f.get("port") or 0),
            "category": f.get("category") or "AI (crucible)",
            "severity": (f.get("severity") or "info").lower(),
            "title":    (f.get("title") or "")[:200],
            "cve":      list(f.get("cve") or []),
            "owasp":    list(f.get("owasp") or []),
            "cwe":      list(f.get("cwe") or []),
            "detail":   (f.get("detail") or "")[:500],
            "fix":      (f.get("fix") or "")[:500],
            "source":   "crucible",
            "crucible_job": job_id,
            "crucible_url": f.get("url", ""),
        })
    return out


# --------------------------------------------------------------------------- #
# Crucible -> Mimir  (verifier for the inbound POST /bridge/crucible/finding)
def verify_inbound_signature(method, path, body_bytes, signature):
    """Verify an inbound signature from Crucible using the SAME shared API key.
    This is called by mimir_web.app when Crucible POSTs findings back to Mimir."""
    if not _key() or not signature:
        return False
    expected = _sign(method, path, body_bytes)
    try:
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
def status():
    """Diagnostic snapshot — for `mimir-crucible status`."""
    return {
        "url_configured": bool(_url()),
        "key_configured": bool(_key()),
        "url": _url() or "(unset)",
        "reachable": available(),
    }


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="mimir-crucible",
                                 description="Mimir <-> Crucible bridge (AI red-team integration)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="show whether the bridge is configured + reachable")
    f = sub.add_parser("forward", help="forward one AI target to Crucible")
    f.add_argument("endpoint", help="LLM endpoint URL or provider:model id")
    f.add_argument("--engagement", type=int, help="Mimir engagement id (optional)")
    c = sub.add_parser("collect", help="pull findings from a Crucible job id")
    c.add_argument("job_id")
    args = ap.parse_args(argv)
    if args.cmd == "status":
        s = status()
        for k, v in s.items():
            print(f"  {k:<16} {v}")
        return 0
    if args.cmd == "forward":
        job = forward_ai_target({"ref": args.endpoint, "host": args.endpoint,
                                 "label": args.endpoint},
                                mimir_engagement_id=args.engagement)
        if not job:
            print("[crucible] forward failed (bridge offline?)", file=sys.stderr)
            return 1
        print(f"[crucible] job queued: {job}")
        return 0
    if args.cmd == "collect":
        findings = collect_findings(args.job_id)
        print(json.dumps(findings, indent=2))
        return 0


if __name__ == "__main__":
    sys.exit(main())
