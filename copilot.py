#!/usr/bin/env python3
"""
copilot.py — engagement co-pilot: rank the NEXT BEST ACTIONS from current state.

Authorized / lab / CTF use only.

Turns the engine's output (findings + staged attack paths) into a ranked
"do these first" list, so an operator facing dozens of hosts and hundreds of
staged steps knows where the leverage is.

LLM-first with deterministic fallback: when a LOCAL Ollama model is reachable the
ranking is decided by the model (senior-consultant reasoning over the full context),
via `qualia.decide()`. When Ollama is offline, or the model returns an invalid shape,
the deterministic weighted score below is used — the engine still works airgapped.
Every action carries a `trace` explaining why it was ranked; `--why` prints it.

    python copilot.py engagement.json            # ranked next actions from an --emit-json export
"""
from __future__ import annotations

import qualia

_SEV = {"critical": 100, "high": 75, "medium": 45, "low": 20, "info": 5}
_CONF = {"high": 100, "medium": 60, "low": 30}
# finding titles that signal an immediate foothold (direct, high-ROI)
_FOOTHOLD = ("docker api", "eternalblue", "ms17-010", "sambacry", "default cred",
             "anonymous", "redis exposed", "unauth", "no auth", "world-read",
             "public exploit", " rce")


def _sev(s):
    return _SEV.get((s or "").lower(), 5)


def _conf(c):
    return _CONF.get((c or "").lower(), 40)


_PATH_W = {"impact": 0.40, "confidence": 0.25, "proximity": 0.25, "low_effort": 0.10}


def _trace(weights, components, basis):
    """Auditable score breakdown: the weighted contribution of each component."""
    contrib = {k: round(weights[k] * components[k], 1) for k in weights}
    return {"weights": weights, "components": {k: round(v) for k, v in components.items()},
            "contributions": contrib, "basis": basis}


def _from_path(p):
    steps = p.get("steps", []) or []
    kind = (p.get("kind") or "").lower()
    proximity = 100 if kind == "domain" else (82 if kind in ("rce", "rce_system", "webapp") else 62)
    low_effort = 100 - min(len(steps), 6) / 6 * 100
    comp = {"impact": _sev(p.get("severity")), "confidence": _conf(p.get("confidence")),
            "proximity": proximity, "low_effort": low_effort}
    score = round(sum(_PATH_W[k] * comp[k] for k in _PATH_W))
    first = steps[0] if steps else {}
    cat = "objective" if kind == "domain" else ("foothold" if proximity >= 82 else "lateral")
    tail = (f" to {p['hosts'][-1]}" if p.get("hosts") else "")
    why = (f"{len(steps)}-step path{tail} · {p.get('confidence', '?')} confidence "
           f"· path score {p.get('score', 0)}")
    return {"category": cat, "title": p.get("name") or p.get("id", "path"), "why": why,
            "command": first.get("command") or first.get("guidance") or "",
            "attack": first.get("technique_id", ""), "risk": "",
            "source": p.get("id", ""), "score": score,
            "trace": _trace(_PATH_W, comp,
                            f"kind={kind or '?'}, {len(steps)} step(s); "
                            f"proximity {proximity} (objective-nearness), "
                            f"low-effort {round(low_effort)} (fewer steps = higher)")}


def _from_finding(f):
    sev = (f.get("severity") or "").lower()
    if sev not in ("critical", "high"):
        return None
    title = (f.get("title") or "").lower()
    if not (f.get("category") == "CVE (vulners)" or any(k in title for k in _FOOTHOLD)):
        return None
    fw = {"impact": 0.55, "confidence": 0.20, "proximity": 0.15, "low_effort": 0.10}
    comp = {"impact": _sev(sev), "confidence": 70, "proximity": 90, "low_effort": 80}
    score = round(sum(fw[k] * comp[k] for k in fw))
    tgt = f.get("host", "?") + (f":{f['port']}" if f.get("port") else "")
    return {"category": "quick-win", "title": f.get("title", ""),
            "why": f"Confirmed {sev} exposure on {tgt} - likely immediate foothold; validate in scope.",
            "command": "", "attack": "T1190", "risk": "", "source": tgt, "score": score,
            "trace": _trace(fw, comp, f"confirmed {sev} exposure on {tgt} -> likely direct foothold")}


def _deterministic_recommend(findings, paths, top=12):
    """Weighted-score ranking (the offline fallback). Same shape as `recommend`."""
    actions = [_from_path(p) for p in (paths or [])]
    actions += [a for a in (_from_finding(f) for f in (findings or [])) if a]
    actions.sort(key=lambda a: (-a["score"], a["category"], a["title"]))
    out, seen = [], set()
    for a in actions:
        key = (a["category"], a["title"], a["source"])
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(a, rank=len(out) + 1))
        if len(out) >= top:
            break
    return out


# ---- LLM-first ranking ---------------------------------------------------- #
def _candidate_pool(findings, paths):
    """Build the candidate action pool the LLM ranks. Same builder as the
    deterministic branch — the LLM decides the ORDER, not the candidate set."""
    pool = [_from_path(p) for p in (paths or [])]
    pool += [a for a in (_from_finding(f) for f in (findings or [])) if a]
    # dedup on the same key the deterministic branch uses
    out, seen = [], set()
    for a in pool:
        key = (a["category"], a["title"], a["source"])
        if key in seen:
            continue
        seen.add(key)
        out.append(a)
    return out


def _rank_prompt(pool, top):
    """Ask the local model to re-rank the pool by objective-proximity, confidence
    and blast radius, and to explain its reasoning for each action."""
    cards = [{"i": i, "category": a["category"], "title": a["title"],
              "why": a["why"], "attack": a.get("attack", ""),
              "source": a.get("source", ""), "det_score": a["score"]}
             for i, a in enumerate(pool)]
    return (
        f"Re-rank the following authorized-engagement action candidates. Return the "
        f"top {top} in priority order for the operator. Prioritize objective proximity "
        "(paths that reach a Domain Admin / high-value target rank first), then "
        "confidence, then blast radius, then low effort. "
        "Return JSON only: "
        '{"ranked":[{"i":<original_index>,"score":<0-100>,"why":"<one-sentence rationale>"}]}\n\n'
        + qualia.compact({"top": top, "candidates": cards})
    )


def _valid_ranking(out, pool, top):
    """Structural + semantic validation. Reject anything that would hurt callers."""
    if not isinstance(out, dict):
        return False
    r = out.get("ranked")
    if not isinstance(r, list) or not r:
        return False
    seen = set()
    for item in r[:top]:
        if not isinstance(item, dict):
            return False
        i = item.get("i")
        if not isinstance(i, int) or not (0 <= i < len(pool)) or i in seen:
            return False
        seen.add(i)
    return True


def _apply_ranking(pool, ranking, top):
    """Materialise the LLM ordering back onto the pool actions."""
    out = []
    for rank, item in enumerate(ranking["ranked"][:top], 1):
        base = dict(pool[item["i"]])
        try:
            s = int(item.get("score", base["score"]))
            base["score"] = max(0, min(100, s))
        except (TypeError, ValueError):
            pass                                                # keep deterministic score
        why = str(item.get("why", "") or "").strip()
        if why:
            base["why"] = why[:400]
        base["rank"] = rank
        base["trace"] = {**(base.get("trace") or {}),
                         "source": "llm", "kind": "rank-actions"}
        out.append(base)
    return out


def recommend(findings, paths, top=12, *, lessons_db=None):
    """Ranked next-best-action list. LLM-first via qualia; falls back to the
    deterministic weighted ranker when Ollama is offline or returns bad output.

    When `lessons_db` (SQLite path) is provided, applies bounded score bias from
    past operator outcomes (see lessons.py) BEFORE truncating to `top` — so
    consistently-successful (technique, ctx) combos rise, consistently-failing
    ones sink. Never drops candidates; only re-orders."""
    pool = _candidate_pool(findings, paths)
    if not pool:
        return []
    prompt = _rank_prompt(pool, top)

    def _fallback():
        return _deterministic_recommend(findings, paths, top)

    result = qualia.decide(
        "rank-actions", prompt, _fallback, role="adviser",
        validator=lambda o: _valid_ranking(o, pool, top))
    # If qualia returned a list, it's already the fallback's output — pass through.
    if isinstance(result, list):
        actions = result
    else:
        actions = _apply_ranking(pool, result, top)

    if lessons_db:
        try:
            import lessons
            actions = lessons.rerank_with_lessons(actions, lessons_db)
        except Exception:                                              # pragma: no cover
            pass                                                       # bias is opt-in; never break the caller
    return actions


def recommend_from_engagement(eng, top=12, *, lessons_db=None):
    return recommend(eng.get("findings", []), eng.get("attack_paths", []), top,
                     lessons_db=lessons_db)


def main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(prog="copilot.py",
                                 description="rank the next best actions from an engagement JSON "
                                             "(assess --emit-json)")
    ap.add_argument("engagement", help="engagement JSON file")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--why", action="store_true",
                    help="show the score breakdown (weighted component contributions) per action")
    ap.add_argument("--lessons", metavar="DB",
                    help="engagement ledger SQLite path — apply what-worked bias "
                         "(record outcomes with lessons.py)")
    args = ap.parse_args(argv)
    with open(args.engagement, encoding="utf-8") as fh:
        eng = json.load(fh)
    recs = recommend_from_engagement(eng, args.top, lessons_db=args.lessons)
    print(f"[+] {len(recs)} recommended next action(s):\n")
    for a in recs:
        print(f"  #{a['rank']:<2} [{a['score']:>3}] ({a['category']}) {a['title']}")
        print(f"      why: {a['why']}")
        if a["command"]:
            print(f"      run: {a['command']}")
        if args.why and a.get("trace"):
            t = a["trace"]
            src = t.get("source", "deterministic")
            if t.get("contributions"):
                parts = ", ".join(f"{k} {v:g}" for k, v in t["contributions"].items())
                print(f"      score [{src}]: {parts}  ({t.get('basis','')})")
            else:
                print(f"      score [{src}]: model re-ranked")
            if t.get("lessons_bias"):
                sign = "+" if t["lessons_bias"] > 0 else ""
                print(f"      lessons bias: {sign}{t['lessons_bias']}  "
                      f"(key: {t.get('lessons_key', '')})")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
