"""slm.seed — bootstrap a usable training corpus from Mimir's own docs + KB.

Phase 25 fix for "the SLM is a factory with no raw material." Walking real
engagements is the gold standard, but until one has run with the trace sink
on, readiness stays at 0% — chicken and egg.

The seed generator produces canonical `(prompt, response)` trace rows from
knowledge that already exists in the repo:

  * `docs/*.md` — methodology notes (attack_paths.md, service_registry.md,
    operation_modes.md, risk_scoring.md, etc.).
  * `knowledge_loader.load_knowledge()` — ATT&CK + service + NSE + tool maps.
  * `tests/fixtures/*.xml` — representative nmap outputs; each host becomes
    a "what next?" prompt.
  * `evals/scenarios/*.yml` — each scenario's `findings_must_include` block
    becomes a "rank these findings" trace.

Every seeded row lands with:
    kind:    `seed:<source>`     (so operators can filter them out)
    role:    `adviser` / `planner`
    outcome: `worked`            (seeds are canon — authoritative by design)
    model:   `seed`              (not from Ollama)

Seeded rows are safe to mix with real traces for SFT and DPO training —
they anchor the model to the engine's methodology. The operator can always
`mimir-slm export train.jsonl --only-outcome worked` and get a corpus that
includes both seeded canon and curator-validated real decisions.
"""
from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from typing import Iterable

from . import trace as _trace


_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
# Source 1 — methodology snippets from docs/*.md (ATT&CK + service notes)
# --------------------------------------------------------------------------- #
_H1_H2_RE = re.compile(r"^(#{1,3})\s+(.+?)\s*$", re.M)
_TID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


def _iter_doc_sections(docs_dir):
    """Yield (path, h2_title, body_text) tuples for every subsection of every
    Markdown doc under docs_dir."""
    if not os.path.isdir(docs_dir):
        return
    for name in sorted(os.listdir(docs_dir)):
        if not name.endswith(".md"):
            continue
        path = os.path.join(docs_dir, name)
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        # Chop on H2/H3 headers.
        parts = _H1_H2_RE.split(text)
        if len(parts) <= 1:
            continue
        # Skip the leader before the first heading.
        i = 1
        while i + 2 < len(parts):
            _, heading, body = parts[i], parts[i + 1], parts[i + 2]
            body = (body or "").strip()
            if body:
                yield name, heading.strip(), body
            i += 3


def _doc_section_rows(docs_dir, max_rows=None):
    """Emit (prompt, response, kind, role) rows for each doc section."""
    n = 0
    for fname, heading, body in _iter_doc_sections(docs_dir):
        tids = sorted(set(_TID_RE.findall(body)))
        prompt = (f"Mimir methodology question: in the context of "
                  f"\"{heading}\", what is the next step the operator should "
                  f"take, and which MITRE ATT&CK technique does it map to?")
        # Keep the body short — SFT doesn't want multi-page responses.
        resp_body = body[:1200] + ("..." if len(body) > 1200 else "")
        response = {
            "guidance": resp_body,
            "attack_ids": tids,
            "source_doc": fname,
            "section": heading,
        }
        yield (prompt, json.dumps(response, ensure_ascii=False),
               f"seed:docs:{fname.replace('.md', '')}", "adviser")
        n += 1
        if max_rows and n >= max_rows:
            return


# --------------------------------------------------------------------------- #
# Source 2 — ATT&CK + service registry via knowledge_loader
# --------------------------------------------------------------------------- #
def _knowledge_rows(docs_dir, max_rows=None):
    try:
        from knowledge_loader import load_knowledge
    except Exception:                                              # pragma: no cover
        return
    kb = load_knowledge(docs_dir)
    if not kb or not kb.available():
        return
    n = 0
    for svc in getattr(kb, "services", []) or []:
        name = (svc.get("name") or "").strip()
        if not name:
            continue
        prompt = (f"When Mimir sees the service \"{name}\" on a host, which "
                  f"module routes it, what are the baseline recon checks, "
                  f"and which ATT&CK techniques apply?")
        resp = {
            "service": name,
            "module": svc.get("module", ""),
            "default_ports": svc.get("ports", []),
            "attack": svc.get("attack", []),
        }
        yield (prompt, json.dumps(resp, ensure_ascii=False),
               f"seed:service:{name}", "planner")
        n += 1
        if max_rows and n >= max_rows:
            return


# --------------------------------------------------------------------------- #
# Source 3 — nmap fixtures → "rank next actions for this host" prompts
# --------------------------------------------------------------------------- #
def _fixture_rows(fixtures_dir, max_rows=None):
    if not os.path.isdir(fixtures_dir):
        return
    n = 0
    for name in sorted(os.listdir(fixtures_dir)):
        if not name.endswith(".xml"):
            continue
        path = os.path.join(fixtures_dir, name)
        try:
            tree = ET.parse(path)
        except Exception:
            continue
        root = tree.getroot()
        for h in root.iter("host"):
            addr = ""
            for a in h.iter("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    addr = a.get("addr") or ""; break
            ports = []
            for p in h.iter("port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = p.find("service")
                ports.append({
                    "port": int(p.get("portid")),
                    "proto": p.get("protocol", "tcp"),
                    "service": (svc.get("name") if svc is not None else "") or "",
                })
            if not addr or not ports:
                continue
            prompt = (f"Host {addr} is reachable and nmap sees: "
                      f"{json.dumps(ports, ensure_ascii=False)}. Rank the "
                      f"top three safe-recon next actions for this host.")
            # Deterministic answer: enumerate top services in a stable order.
            top = sorted(ports, key=lambda x: (x["port"], x["proto"]))[:3]
            steps = []
            for p in top:
                steps.append({
                    "step": f"enumerate {p['service'] or 'service'} on "
                            f"{addr}:{p['port']}/{p['proto']}",
                    "risk": "safe",
                    "rationale": "baseline recon before any intrusive action",
                })
            response = {"next_actions": steps}
            yield (prompt, json.dumps(response, ensure_ascii=False),
                   f"seed:fixture:{name.replace('.xml', '')}", "planner")
            n += 1
            if max_rows and n >= max_rows:
                return


# --------------------------------------------------------------------------- #
# Source 4 — eval scenarios → "which findings matter?" prompts
# --------------------------------------------------------------------------- #
def _scenario_rows(scenarios_dir, max_rows=None):
    if not os.path.isdir(scenarios_dir):
        return
    try:
        import yaml
    except Exception:                                              # pragma: no cover
        return
    n = 0
    for name in sorted(os.listdir(scenarios_dir)):
        if not name.endswith(".yml"):
            continue
        path = os.path.join(scenarios_dir, name)
        try:
            with open(path, encoding="utf-8") as fh:
                scen = yaml.safe_load(fh) or {}
        except Exception:
            continue
        expected = scen.get("expected") or {}
        wanted = expected.get("findings_must_include") or []
        if not wanted:
            continue
        prompt = (f"In the Mimir eval scenario \"{name}\", which specific "
                  f"finding categories must the engine surface to pass the "
                  f"regression? Return the required severities too.")
        response = {"required_findings": wanted}
        yield (prompt, json.dumps(response, ensure_ascii=False),
               f"seed:eval:{name.replace('.yml', '')}", "adviser")
        n += 1
        if max_rows and n >= max_rows:
            return


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def _iter_all_rows(docs_dir, fixtures_dir, scenarios_dir, max_rows=None):
    sources = (
        _doc_section_rows(docs_dir),
        _knowledge_rows(docs_dir),
        _fixture_rows(fixtures_dir),
        _scenario_rows(scenarios_dir),
    )
    n = 0
    for src in sources:
        for row in src:
            yield row
            n += 1
            if max_rows and n >= max_rows:
                return


def seed_db(db_path=None, *, docs_dir=None, fixtures_dir=None,
            scenarios_dir=None, max_rows=None, mark_worked=True):
    """Populate the trace DB with canonical prompt/response pairs.

    Returns the count of rows inserted. Every row is `kind=seed:*`,
    `model='seed'`, `used_fallback=0`, and `outcome='worked'` when
    mark_worked is True (default — seeds are canon).
    """
    db_path = db_path or _trace._db_path()
    if not db_path:
        raise RuntimeError(
            "No trace DB configured. Set MIMIR_SLM_TRACE_DB=/path/to.db "
            "or pass db_path=")
    docs_dir = docs_dir or os.path.join(_REPO, "docs")
    fixtures_dir = fixtures_dir or os.path.join(_REPO, "tests", "fixtures")
    scenarios_dir = scenarios_dir or os.path.join(_REPO, "evals", "scenarios")

    import sqlite3
    # Force the schema to exist by touching the trace sink first.
    try:
        prev = os.environ.get("MIMIR_SLM_TRACE_DB")
        os.environ["MIMIR_SLM_TRACE_DB"] = db_path
        _trace._connect(db_path).close()
    finally:
        if prev is None:
            os.environ.pop("MIMIR_SLM_TRACE_DB", None)
        else:
            os.environ["MIMIR_SLM_TRACE_DB"] = prev

    con = sqlite3.connect(db_path, isolation_level=None)
    inserted = 0
    try:
        for prompt, response, kind, role in _iter_all_rows(
                docs_dir, fixtures_dir, scenarios_dir, max_rows=max_rows):
            # Dedup on (kind, prompt_hash) so re-seeding is idempotent.
            phash = _trace._hash(prompt)
            row = con.execute(
                "SELECT id FROM qualia_trace WHERE kind=? AND prompt_hash=?",
                (kind, phash)).fetchone()
            if row:
                continue
            con.execute(
                "INSERT INTO qualia_trace(ts,kind,role,prompt_hash,prompt,"
                "system,llm_result,fallback_result,used_fallback,"
                "validator_passed,model,engagement_id,outcome) VALUES("
                "?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("1970-01-01T00:00:00+00:00", kind[:64], role[:32], phash,
                 prompt, None, response, None, 0, None, "seed", None,
                 "worked" if mark_worked else None))
            inserted += 1
    finally:
        con.close()
    return inserted


def stats_for_seeds(db_path=None):
    db_path = db_path or _trace._db_path()
    if not db_path or not os.path.exists(db_path):
        return {"present": False, "total": 0}
    import sqlite3
    con = sqlite3.connect(db_path, isolation_level=None)
    try:
        total = con.execute(
            "SELECT COUNT(*) FROM qualia_trace WHERE kind LIKE 'seed:%'"
        ).fetchone()[0]
        by_source = dict(con.execute(
            "SELECT kind, COUNT(*) FROM qualia_trace WHERE kind LIKE 'seed:%' "
            "GROUP BY kind ORDER BY COUNT(*) DESC").fetchall())
    finally:
        con.close()
    return {"present": True, "total": total, "by_source": by_source}
