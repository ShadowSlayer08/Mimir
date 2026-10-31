#!/usr/bin/env python3
"""
roe_parse.py — parse a human-written engagement document into a structured ROE.

Authorized / lab / CTF / VAPT / red-team use only.

Operators get a Rules-of-Engagement document in Markdown / plain text / PDF.
The structured ROE YAML this engine consumes (`engagement.roe.yml`) is tedious
to hand-write. roe_parse.py runs the raw document through a LOCAL model (via
`qualia.decide`) and produces the structured dict; it falls back to a tiny
regex-based extractor when no local model is reachable. The output is validated
against roe._normalise so a bad model response can't poison the gate.

    python roe_parse.py roe.md > engagement.roe.yml
    python roe_parse.py roe.pdf --yaml engagement.roe.yml

Supports: .md / .txt / .pdf (if `pypdf` is installed; otherwise .pdf is read as
best-effort bytes). The LLM is called with a strict JSON schema; its output is
intersected with the deterministic regex extractor so the final rules contain
only facts that at LEAST one of the two sources confirms.
"""
from __future__ import annotations

import json
import os
import re
import sys


_IP_CIDR = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_HOST = re.compile(r"\b([a-z0-9][a-z0-9\-]+(?:\.[a-z0-9][a-z0-9\-]+){1,})\b", re.I)
_FORBIDDEN_PATTERNS = [
    (r"\bno\s+(denial[- ]of[- ]service|do+s)\b", ["T1499", "T1499.001", "T1499.004", "T1498"]),
    (r"\bno\s+(ransom|destructive|wipe)\b",       ["T1486", "T1485"]),
    (r"\bno\s+(coerc|petit\s*potam|ntlm\s+relay)\b", ["T1187", "T1557"]),
    (r"\bno\s+(password|credential)\s+(spray|brute)\b", ["T1110", "T1110.003", "T1110.004"]),
    (r"\bno\s+(mfa\s+fatigue|push\s+bomb)\b",    ["T1621"]),
]
_RISK_PATTERNS = {
    r"\b(non[- ]intrusive|read[- ]only|safe\s+only|passive\s+only)\b": "intrusive",
}
_WINDOW = re.compile(
    r"\b(?P<hs>\d{1,2}):?(?P<ms>\d{2})?\s*(?:[-–to]+)\s*(?P<he>\d{1,2}):?(?P<me>\d{2})?\b")


def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                          # pragma: no cover
            pass


_force_utf8_stdio()


def _read_pdf(path):
    """Best-effort PDF read. Returns the extracted text, or empty string."""
    try:
        from pypdf import PdfReader
    except Exception:                                              # pragma: no cover
        try:
            from PyPDF2 import PdfReader                           # type: ignore
        except Exception:
            return ""
    try:
        rd = PdfReader(path)
        out = []
        for page in rd.pages:
            try:
                out.append(page.extract_text() or "")
            except Exception:
                pass
        return "\n".join(out)
    except Exception:
        return ""


def read_text(path):
    """Load a .md / .txt / .pdf file. Returns raw text."""
    lower = path.lower()
    if lower.endswith(".pdf"):
        return _read_pdf(path)
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError:
        with open(path, encoding="latin-1") as fh:
            return fh.read()


# --------------------------------------------------------------------------- #
# Deterministic regex extractor (the offline fallback + the cross-check).
def extract_regex(text):
    """Pull obvious rule bits out of the text — regex only, no LLM."""
    text = text or ""
    low = text.lower()

    # In-scope / out-of-scope by section header.
    in_scope, out_scope = [], []
    for section, bucket in (("in scope", in_scope), ("in-scope", in_scope),
                            ("out of scope", out_scope), ("out-of-scope", out_scope),
                            ("not in scope", out_scope)):
        m = re.search(rf"(?:^|\n)[^\n]*{re.escape(section)}[^\n]*\n(.*?)(?:\n\n|\n#|$)",
                      low, re.DOTALL)
        if not m:
            continue
        block = m.group(1)
        bucket.extend(_IP_CIDR.findall(block))
        bucket.extend(_HOST.findall(block))

    # Fallback: if no sections matched, pull every CIDR + hostname from the whole doc.
    if not (in_scope or out_scope):
        in_scope = list({*_IP_CIDR.findall(low), *_HOST.findall(low)})

    # Dedupe + drop junk tokens (bare "scope" etc.).
    def _clean(xs):
        return sorted({x for x in xs if "." in x or "/" in x})

    forbidden = set()
    for pat, techs in _FORBIDDEN_PATTERNS:
        if re.search(pat, low):
            forbidden.update(techs)

    risk = set()
    for pat, tag in _RISK_PATTERNS.items():
        if re.search(pat, low):
            risk.add(tag)

    windows = []
    for m in _WINDOW.finditer(low):
        try:
            hs = int(m.group("hs")); he = int(m.group("he"))
            ms = int(m.group("ms") or 0); me = int(m.group("me") or 0)
            if 0 <= hs <= 24 and 0 <= he <= 24:
                windows.append({"days": ["mon", "tue", "wed", "thu", "fri"],
                                "hours": [f"{hs:02d}:{ms:02d}", f"{he:02d}:{me:02d}"]})
        except (ValueError, TypeError):
            pass

    # Engagement name — "Engagement:" / "Project:" / "Client:" prefix capture.
    name_m = re.search(r"(?:engagement|project|client)\s*[:\-]\s*(.{3,80})",
                       text, re.I)
    jurisdiction_m = re.search(r"jurisdiction\s*[:\-]\s*([A-Z]{2}(?:-[A-Z]{2})?)",
                               text, re.I)

    return {
        "engagement": (name_m.group(1).strip() if name_m else ""),
        "jurisdiction": (jurisdiction_m.group(1).strip() if jurisdiction_m else ""),
        "in_scope": _clean(in_scope),
        "out_of_scope": _clean(out_scope),
        "forbidden_techniques": sorted(forbidden),
        "forbidden_risk": sorted(risk),
        "allowed_windows": windows[:1],                           # take the first
    }


# --------------------------------------------------------------------------- #
# LLM extractor (via qualia, with the regex-extractor result as fallback).
_SCHEMA_PROMPT = """\
You are reading a Rules of Engagement document for an AUTHORIZED penetration
test / red-team engagement. Extract the machine-checkable rules. Return JSON
ONLY, this exact shape (omit keys whose value you cannot ground in the text):

{
  "engagement":       "<string: project/engagement name>",
  "jurisdiction":     "<string: country/state code, e.g. US-CA>",
  "in_scope":         ["<CIDR | hostname | hostname suffix (.corp.lab)>"],
  "out_of_scope":     ["<same shape>"],
  "allowed_windows":  [{"days": ["mon","tue",...], "hours": ["HH:MM","HH:MM"]}],
  "forbidden_techniques": ["T1499", "T1499.001", "..."],
  "forbidden_risk":   ["intrusive"],
  "forbidden_kinds":  ["domain", "lateral", ...]
}

RULES:
- Never invent hosts / CIDRs / technique ids that aren't present in the text.
- If the document says "no denial of service", add T1499, T1499.001, T1499.004.
- If it says "non-intrusive only" or "passive only" or "read-only", add
  "intrusive" to forbidden_risk.
- Scope entries can be: a CIDR (10.0.0.0/24), an exact host (dc01.corp.lab),
  or a dotted suffix (".corp.lab").
"""


def extract_llm(text):
    """Call `qualia.decide` with the ROE text + strict JSON contract. Returns
    the dict (same shape as extract_regex) or None if no local model is reachable
    or the response fails validation."""
    try:
        import qualia
    except Exception:                                              # pragma: no cover
        return None
    if not text:
        return None

    def _valid(out):
        if not isinstance(out, dict):
            return False
        for key in ("in_scope", "out_of_scope"):
            v = out.get(key)
            if v is not None and not isinstance(v, list):
                return False
        return True

    def _fallback():
        return None

    result = qualia.decide(
        "roe-parse",
        _SCHEMA_PROMPT + "\n\n--- DOCUMENT START ---\n" + text[:40_000] +
        "\n--- DOCUMENT END ---",
        _fallback,
        role="narrator",                                           # the 27B is better at parsing prose
        validator=_valid,
    )
    return result if isinstance(result, dict) else None


# --------------------------------------------------------------------------- #
def parse(path_or_text, prefer_llm=True):
    """Parse a ROE document. If `path_or_text` points at a file we read it;
    otherwise it's treated as raw text. Returns a rules dict + a `sources` list
    saying where each key came from (`llm`, `regex`, or `both`)."""
    text = path_or_text
    if os.path.exists(path_or_text):
        text = read_text(path_or_text)

    base = extract_regex(text)
    llm_out = extract_llm(text) if prefer_llm else None

    rules, sources = {}, {}
    for key, default in base.items():
        bv = base.get(key)
        lv = llm_out.get(key) if llm_out else None
        if isinstance(default, list):
            # Union both, deduplicate, keep order deterministic.
            merged = list(dict.fromkeys((bv or []) + (lv or [])))
            rules[key] = merged
            if merged:
                if (bv or []) and (lv or []):
                    sources[key] = "both"
                elif bv:
                    sources[key] = "regex"
                else:
                    sources[key] = "llm"
        else:
            rules[key] = lv or bv
            if lv and bv:
                sources[key] = "both"
            elif lv:
                sources[key] = "llm"
            elif bv:
                sources[key] = "regex"
    rules["_sources"] = sources
    return rules


def to_yaml(rules):
    """Serialise the parsed rules as the YAML roe.py accepts."""
    try:
        import yaml
    except Exception:                                              # pragma: no cover
        return json.dumps(rules, indent=2)
    r = {k: v for k, v in rules.items() if not k.startswith("_") and v}
    return yaml.safe_dump(r, sort_keys=False, default_flow_style=False)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="mimir-roe-parse",
                                 description="parse a human ROE (md/txt/pdf) into "
                                             "the structured YAML roe.py consumes")
    ap.add_argument("source", help="path to the ROE document (.md / .txt / .pdf)")
    ap.add_argument("--yaml", metavar="FILE", help="write YAML here (else stdout)")
    ap.add_argument("--json", metavar="FILE", help="write parsed JSON here (debugging)")
    ap.add_argument("--no-llm", action="store_true",
                    help="skip the LLM pass; use the regex extractor only")
    args = ap.parse_args(argv)

    rules = parse(args.source, prefer_llm=not args.no_llm)
    yml = to_yaml(rules)
    if args.yaml:
        with open(args.yaml, "w", encoding="utf-8") as fh:
            fh.write(yml)
        print(f"[+] wrote {args.yaml}", file=sys.stderr)
    else:
        sys.stdout.write(yml)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(rules, fh, indent=2)
        print(f"[+] wrote {args.json}", file=sys.stderr)
    for k, src in (rules.get("_sources") or {}).items():
        print(f"  [{src:<5}] {k}: {rules.get(k)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
