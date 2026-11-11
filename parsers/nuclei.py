"""parsers.nuclei — nuclei JSONL output -> ParseResult.

nuclei's `-json` / `-jsonl` output is newline-delimited JSON, one finding per
line. Each entry carries at minimum template-id, info.name, info.severity,
host and matched-at — plenty to emit a Mimir finding.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse
from .base import ParseResult


_SEVERITY_MAP = {
    "info": "info", "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "info",
}


def _host_from_url(url):
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def parse(stdout, stderr="", exit_code=0):
    r = ParseResult(source_tool="nuclei")
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue

        info = e.get("info") or {}
        name = info.get("name") or e.get("template-id") or "nuclei hit"
        sev = _SEVERITY_MAP.get(
            (info.get("severity") or "").strip().lower(), "info")
        tpl = e.get("template-id") or e.get("template") or ""
        host_url = e.get("host") or e.get("matched-at") or ""
        host = _host_from_url(host_url) or host_url
        if host and host not in r.new_hosts:
            r.new_hosts.append(host)

        cve = ""
        classif = info.get("classification") or {}
        for c in (classif.get("cve-id") or [])[:1]:
            cve = c
        cwe = ""
        for cw in (classif.get("cwe-id") or [])[:1]:
            cwe = cw

        r.new_findings.append({
            "host": host,
            "port": None,
            "severity": sev,
            "category": "Nuclei",
            "title": f"{name} [{tpl}]".strip(),
            "cve": cve,
            "cwe": cwe,
            "owasp": "",
            "exploit_refs": [],
            "source_tool": "nuclei",
            "matched_at": e.get("matched-at", ""),
        })
    return r
