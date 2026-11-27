#!/usr/bin/env python3
"""
autopilot_loop.py — Autopilot v2: observe-decide-run.

Authorized / lab / CTF / VAPT / red-team use only.

v1 (autopilot.py) runs the staged plan one pass under the gate chain. v2
wraps v1 in an outer loop that CAPTURES output, PARSES it into structured
intel (parsers/), MERGES the intel back into the engagement JSON, and RE-
RANKS what's left (copilot.py) before the next pass.

The gate chain is reused unchanged — every v2 iteration is still gated by
institutional-TLD / ROE / noise / risk / command-safety. The loop never
relaxes any v1 safety. It just lets autopilot learn between iterations.

Convergence:
  * Hard cap: --max-iterations (default 3).
  * Early exit: if an iteration produces no new hosts / services / findings
    AND no new executed_ok steps compared to the prior iteration.
  * Per-iteration autopilot run still obeys --max-steps / --timeout / etc.

Each iteration writes a JSONL audit record:
    {"iteration": N, "ts": "...", "executed": M, "parsed": {...},
     "new_hosts": [...], "new_findings_count": X}
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

# Reuse the force_utf8_stdio + run_single_pass from autopilot.py.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import autopilot  # noqa: E402
import parsers    # noqa: E402

_force_utf8_stdio = autopilot._force_utf8_stdio
_force_utf8_stdio()

# Default knobs — conservative; raise with CLI flags.
DEFAULT_MAX_ITERATIONS = 3


# --------------------------------------------------------------------------- #
# Merge helpers — idempotent, dedup'd, never clobber operator-set fields.
# --------------------------------------------------------------------------- #
def _merge_hosts(engagement, new_hosts):
    """Append every new_host to engagement['hosts'] as a minimal stub. Returns
    the count of hosts actually added (duplicates ignored)."""
    added = 0
    hosts = engagement.setdefault("hosts", [])
    existing = {(h.get("address") or h.get("ip") or h.get("host") or "").lower()
                for h in hosts}
    for addr in new_hosts or []:
        a = (addr or "").lower().strip()
        if not a or a in existing:
            continue
        hosts.append({
            "address": addr, "ip": addr if _looks_like_ip(addr) else "",
            "hostname": addr if not _looks_like_ip(addr) else "",
            "ports": [], "os": "", "status": "unknown",
            "source": "autopilot-v2",
        })
        existing.add(a)
        added += 1
    return added


def _merge_services(engagement, new_services):
    """Attach new services to the matching host record. Services whose host
    is unknown spawn a stub host entry first. Returns (host_added, port_added)."""
    host_added = port_added = 0
    hosts = engagement.setdefault("hosts", [])
    by_addr = {(h.get("address") or h.get("ip") or "").lower(): h for h in hosts}
    for svc in new_services or []:
        addr = (svc.get("host") or "").lower().strip()
        if not addr:
            continue
        host = by_addr.get(addr)
        if host is None:
            host = {"address": svc.get("host"),
                    "ip": svc.get("host") if _looks_like_ip(svc.get("host") or "") else "",
                    "hostname": svc.get("host") if not _looks_like_ip(svc.get("host") or "") else "",
                    "ports": [], "source": "autopilot-v2"}
            hosts.append(host)
            by_addr[addr] = host
            host_added += 1
        ports = host.setdefault("ports", [])
        key = (svc.get("port"), (svc.get("proto") or "tcp").lower())
        existing_keys = {(p.get("port"), (p.get("protocol") or p.get("proto") or "tcp").lower())
                         for p in ports}
        if key in existing_keys:
            continue
        ports.append({
            "port": svc.get("port"), "protocol": svc.get("proto", "tcp"),
            "service": svc.get("service", ""), "version": svc.get("version", ""),
            "state": "open", "source": "autopilot-v2",
        })
        port_added += 1
    return host_added, port_added


def _merge_findings(engagement, new_findings):
    """Append new findings, dedup'd by (host, title, cve). Returns the count
    added."""
    findings = engagement.setdefault("findings", [])
    existing = {(f.get("host", ""), f.get("title", ""), f.get("cve", ""))
                for f in findings}
    added = 0
    for f in new_findings or []:
        key = (f.get("host", ""), f.get("title", ""), f.get("cve", ""))
        if key in existing:
            continue
        findings.append(f)
        existing.add(key)
        added += 1
    return added


def _looks_like_ip(s):
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def _rerank(engagement, lessons_db=None):
    """Re-rank next-best-actions via copilot.py. Updates
    engagement['recommendations'] in place. Safe no-op if copilot is absent."""
    try:
        import copilot
        recs = copilot.recommend_from_engagement(engagement, top=12,
                                                 lessons_db=lessons_db)
        engagement["recommendations"] = recs
        return len(recs)
    except Exception:                                              # pragma: no cover
        return 0


# --------------------------------------------------------------------------- #
# Re-dispatch — run the modules dispatcher against newly-discovered services
# so the plan GROWS mid-loop. Phase 25 fix for "v2 just re-ranks."
# --------------------------------------------------------------------------- #
def _synth_app_targets(new_urls, new_subdomains):
    """Build the app_targets list that `modules.dispatch_apps` expects from
    just the URLs + subdomains an iteration discovered.

    Each dict is {"kind": "web", "host": <host>, "ref": <url>, "label": ...}
    — the same shape apptargets.app_targets() emits. We deliberately don't
    guess API-ness here; a new URL is a web target by default. API/mobile/
    thick/cloud targets should come from the operator's launch args, not
    from inferred discovery.
    """
    from urllib.parse import urlparse
    targets = []
    seen = set()
    for u in new_urls or []:
        url = (u.get("url") if isinstance(u, dict) else str(u)) or ""
        if not url:
            continue
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            host = ""
        if not host or (host, url) in seen:
            continue
        seen.add((host, url))
        targets.append({"kind": "web", "host": host, "ref": url,
                        "label": f"autopilot-v2:{host}"})
    for sub in new_subdomains or []:
        sub = (sub or "").strip().lower().rstrip(".")
        if not sub:
            continue
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub}/"
            if (sub, url) in seen:
                continue
            seen.add((sub, url))
            targets.append({"kind": "web", "host": sub, "ref": url,
                            "label": f"autopilot-v2:{sub}"})
    return targets


def _synth_report_for_new_services(engagement, new_services):
    """Build a minimal Mimir report shape around just the new (host, port,
    service) tuples so modules.dispatch can emit methodology for them without
    re-scanning anything.

    modules.* reads `port["service"]` as a DICT ({name, version, ...}),
    which is why nmap_analyzer emits it that way. Match that shape here.
    """
    by_host = {}
    for s in new_services or []:
        addr = s.get("host") or ""
        if not addr:
            continue
        h = by_host.setdefault(addr, {"address": addr, "ip": addr,
                                      "hostname": addr, "ports": [],
                                      "os": "", "status": "up"})
        h["ports"].append({
            "port": s.get("port"),
            "protocol": s.get("proto", "tcp"),
            # modules expect a dict here — nmap_analyzer emits it this way.
            "service": {
                "name": s.get("service", ""),
                "version": s.get("version", ""),
                "product": "",
            },
            "state": "open",
        })
    return {
        "hosts": list(by_host.values()),
        "findings": [],
        "meta": {"source": "autopilot-v2 redispatch"},
    }


def _restage_from_discoveries(engagement, new_services, mode="vapt",
                              noise_ceiling=5, accept_risk=("safe",),
                              new_urls=None, new_subdomains=None):
    """Re-run the knowledge-driven modules dispatcher against new services
    AND new AppSec targets. Appends the resulting check steps as a synthetic
    attack path in the engagement. Returns (new_steps, modules_called).

    Phase 26 — AppSec in autopilot: new URLs from httpx/feroxbuster/etc.
    now get dispatched through `modules.dispatch_apps` as web targets, and
    new subdomains from subfinder get the same treatment (resolved as web
    app_targets). Infra path is unchanged.

    Safeguards:
      * dedup by (host, port, module, check-name) across iterations
      * respects the loop's noise_ceiling + accept_risk at append time
    """
    try:
        import modules as _modules
    except Exception:                                              # pragma: no cover
        return 0, 0
    if not (new_services or new_urls or new_subdomains):
        return 0, 0

    results = []
    report = _synth_report_for_new_services(engagement, new_services)
    try:
        if new_services:
            results.extend(_modules.dispatch(report, mode=mode))
    except Exception:                                              # pragma: no cover
        pass

    # AppSec re-dispatch — new URLs + subdomain -> dispatch_apps web targets.
    app_targets = _synth_app_targets(new_urls or [], new_subdomains or [])
    if app_targets:
        try:
            results.extend(_modules.dispatch_apps(
                app_targets, report, mode=mode))
        except Exception:                                          # pragma: no cover
            pass

    # Find or create the synthetic attack path.
    synth = None
    for p in (engagement.get("attack_paths") or []):
        if p.get("id") == "AUTOPILOT-V2-SYNTH":
            synth = p; break
    if synth is None:
        synth = {"id": "AUTOPILOT-V2-SYNTH",
                 "kind": "autopilot-synth",
                 "hosts": [], "steps": [],
                 "noise_max": 0, "noise_warn": False,
                 "source": "autopilot-v2"}
        engagement.setdefault("attack_paths", []).append(synth)

    existing_keys = {(s.get("host"), s.get("port"), s.get("module"),
                      s.get("name")) for s in synth["steps"]}
    accept = set(accept_risk or ("safe",))
    added_steps = 0
    modules_called = 0
    next_order = len(synth["steps"]) + 1

    for r in (results or []):
        modules_called += 1
        module = r.get("module", "")
        target = r.get("target", "")
        host = target
        if host.startswith(("http://", "https://")):
            host = host.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        port = None
        for svc in new_services:
            if (svc.get("host") or "").lower() == host.lower():
                port = svc.get("port"); break
        for c in (r.get("checks") or []):
            key = (host, port, module, c.get("name"))
            if key in existing_keys:
                continue
            risk = (c.get("risk") or "safe").lower()
            if risk not in accept:
                continue
            cmd = (c.get("command") or "").strip()
            if not cmd or cmd.startswith("#"):
                continue
            step = {
                "order": next_order,
                "technique_id": c.get("attack", "") or r.get("attack", ""),
                "technique": c.get("name", ""),
                "tactic": "Discovery" if risk == "safe" else "Active",
                "host": host,
                "port": port,
                "module": module,
                "name": c.get("name", ""),
                "command": cmd,
                "risk": risk,
                "noise": int(c.get("noise", 0) or 0),
                "source": f"autopilot-v2-redispatch:{module}",
            }
            if step["noise"] > noise_ceiling:
                continue
            synth["steps"].append(step)
            existing_keys.add(key)
            added_steps += 1
            next_order += 1

    if added_steps:
        synth["noise_max"] = max((s.get("noise", 0) for s in synth["steps"]),
                                 default=0)
    return added_steps, modules_called


# --------------------------------------------------------------------------- #
# Observation — per-step parse + merge.
# --------------------------------------------------------------------------- #
def _observe_results(engagement, results, *, fact_db=None, engagement_id=None):
    """Walk the autopilot run results, parse each executed step's stdout/stderr
    via parsers.dispatch, merge every ParseResult back into the engagement.
    Returns the aggregate counts PLUS the raw new_services list so the caller
    can re-dispatch modules against just-discovered ports.

    Phase 29+30 extensions:
      * `fact_db` / `engagement_id` — write a `parsed_result` Fact per
        parser hit (source_fact_id for every merged item below).
      * Hints emitted by parsers are persisted as `kind=hint` Facts and
        attached to `engagement["hints"]` for the copilot ranker.
    """
    agg = {"parsed_steps": 0, "new_hosts": [], "new_services": 0,
           "new_findings": 0, "new_credentials": 0,
           "new_urls": 0, "new_subdomains": 0, "new_hints": 0,
           "_raw_new_services": [], "_raw_new_urls": [],
           "_raw_new_subdomains": []}
    for r in results or []:
        if r.get("verdict") not in ("executed_ok", "executed_nonzero"):
            continue
        agg["parsed_steps"] += 1
        pr = parsers.dispatch(r.get("command", ""),
                              r.get("stdout_tail", ""),
                              r.get("stderr_tail", ""),
                              r.get("exit_code", 0))
        if pr.is_empty():
            continue
        # Phase 29 — link graphs: this parse result gets its own Fact that
        # cites the step's verdict Fact (if we can find it by io_nonce).
        source_fact_id = _record_parsed_fact(
            fact_db, engagement_id, r, pr)
        # Track which services are NEW to the engagement (merge returns the
        # added count, but we also want to re-dispatch them, so stash the
        # new rows before merging).
        existing = _service_keys(engagement)
        truly_new = [s for s in (pr.new_services or [])
                     if (s.get("host"), s.get("port"),
                         (s.get("proto") or "tcp").lower()) not in existing]
        agg["_raw_new_services"].extend(truly_new)
        # Phase 29 — tag every new row with source_fact_id (may be None
        # when fact_db is unset; parsers get their lineage either way).
        for svc in pr.new_services:
            svc.setdefault("source_fact_id", source_fact_id)
        for fnd in pr.new_findings:
            fnd.setdefault("source_fact_id", source_fact_id)
        for url in pr.new_urls:
            url.setdefault("source_fact_id", source_fact_id)
        agg["new_services"] += _merge_services(engagement, pr.new_services)[1]
        agg["new_hosts"] += [h for h in pr.new_hosts
                             if h not in agg["new_hosts"]]
        _merge_hosts(engagement, pr.new_hosts)
        agg["new_findings"] += _merge_findings(engagement, pr.new_findings)
        agg["new_credentials"] += len(pr.new_credentials)
        # Phase 26: track new AppSec surface (URLs + subdomains).
        existing_urls = _url_keys(engagement)
        truly_new_urls = [u for u in (pr.new_urls or [])
                          if u.get("url") not in existing_urls]
        agg["_raw_new_urls"].extend(truly_new_urls)
        agg["new_urls"] += _merge_urls(engagement, pr.new_urls)
        existing_subs = _subdomain_keys(engagement)
        truly_new_subs = [s for s in (pr.new_subdomains or [])
                          if s.lower() not in existing_subs]
        agg["_raw_new_subdomains"].extend(truly_new_subs)
        agg["new_subdomains"] += _merge_subdomains(engagement, pr.new_subdomains)
        # Phase 30 — Hints on the engagement + as Facts.
        added_hints = _merge_hints(engagement, pr.hints)
        agg["new_hints"] += added_hints
        _record_hint_facts(fact_db, engagement_id, pr.hints, source_fact_id)
    return agg


def _record_parsed_fact(fact_db, engagement_id, step_record, parse_result):
    """Phase 29 — append one `parsed_result` Fact per parser hit, citing
    the step's verdict Fact (looked up by io_nonce). Returns the new
    Fact's id, or None when fact_db is unset.
    """
    if not fact_db or not engagement_id:
        return None
    try:
        import fact_ledger
        step_nonce = step_record.get("io_nonce", "")
        step_fact_id = _fact_for_nonce(fact_db, engagement_id, step_nonce)
        fid = fact_ledger.record(
            db_path=fact_db, engagement_id=engagement_id,
            kind="parsed_result", source="autopilot-v2",
            from_fact_ids=[step_fact_id] if step_fact_id else [],
            data={"source_tool": parse_result.source_tool,
                  "counts": {"hosts": len(parse_result.new_hosts),
                             "services": len(parse_result.new_services),
                             "findings": len(parse_result.new_findings),
                             "urls": len(parse_result.new_urls),
                             "subdomains": len(parse_result.new_subdomains),
                             "hints": len(parse_result.hints),
                             "creds": len(parse_result.new_credentials)},
                  "step_nonce": step_nonce})
        return fid
    except Exception:                                              # pragma: no cover
        return None


def _fact_for_nonce(fact_db, engagement_id, nonce):
    """Return the Fact id whose data.io_nonce matches `nonce`, or None."""
    if not nonce or not fact_db:
        return None
    try:
        import sqlite3, json as _json
        con = sqlite3.connect(fact_db, isolation_level=None)
        try:
            # Narrow the search — most step Facts are the latest ones.
            rows = con.execute(
                "SELECT id, data FROM facts WHERE engagement_id=? "
                "ORDER BY id DESC LIMIT 100", (engagement_id,)).fetchall()
        finally:
            con.close()
        for fid, data_json in rows:
            try:
                if _json.loads(data_json or "{}").get("io_nonce") == nonce:
                    return fid
            except Exception:
                continue
    except Exception:                                              # pragma: no cover
        pass
    return None


def _merge_hints(engagement, new_hints):
    """Dedup-merge hint strings into engagement['hints']. Case-insensitive."""
    bucket = engagement.setdefault("hints", [])
    seen = {(h or "").strip().lower() for h in bucket if isinstance(h, str)}
    added = 0
    for h in new_hints or []:
        s = (h or "").strip()
        if not s:
            continue
        key = s.lower()
        if key in seen:
            continue
        bucket.append(s); seen.add(key); added += 1
    return added


def _record_hint_facts(fact_db, engagement_id, hints, source_fact_id):
    """Phase 30 — one `kind=hint` Fact per hint, citing the parsed Fact."""
    if not (fact_db and engagement_id and hints):
        return
    try:
        import fact_ledger
        for h in hints:
            fact_ledger.record(
                db_path=fact_db, engagement_id=engagement_id,
                kind="hint", source="autopilot-v2",
                from_fact_ids=[source_fact_id] if source_fact_id else [],
                data={"hint": h})
    except Exception:                                              # pragma: no cover
        pass


# --------------------------------------------------------------------------- #
# Phase 29 — situation key for rerank dedup
# --------------------------------------------------------------------------- #
def _situation_key(engagement):
    """Tuple summarizing the engagement's structural counts. When it hasn't
    changed since the prior iteration, there's nothing new to rank — we
    can reuse the last recommendations and skip the LLM call."""
    return (
        len(engagement.get("hosts") or []),
        len(engagement.get("findings") or []),
        len(engagement.get("attack_paths") or []),
        len(engagement.get("appsec_urls") or []),
        len(engagement.get("appsec_subdomains") or []),
        len(engagement.get("hints") or []),
    )


# --------------------------------------------------------------------------- #
# Phase 30 — sidequestion read: find the newest unanswered question Fact
# for this engagement. Answered when a later Fact (kind=sidequestion:answered)
# cites the pending Fact's id.
# --------------------------------------------------------------------------- #
def _pending_sidequestion(fact_db, engagement_id):
    if not fact_db or not engagement_id:
        return None
    try:
        import fact_ledger
        all_facts = list(fact_ledger.replay(fact_db, engagement_id))
    except Exception:                                              # pragma: no cover
        return None
    answered_ids = set()
    for f in all_facts:
        if f["kind"] == "sidequestion:answered":
            for src in (f.get("from_fact_ids") or []):
                answered_ids.add(int(src))
    pending = [f for f in all_facts
               if f["kind"] == "sidequestion:pending"
               and f["id"] not in answered_ids]
    if not pending:
        return None
    # Oldest unanswered wins — we never want to drop a question.
    return pending[0]


def _service_keys(engagement):
    """Return the set of (host, port, proto) tuples already in the engagement."""
    keys = set()
    for h in (engagement.get("hosts") or []):
        addr = h.get("address") or h.get("ip") or ""
        for p in (h.get("ports") or []):
            keys.add((addr, p.get("port"),
                      (p.get("protocol") or p.get("proto") or "tcp").lower()))
    return keys


# --------------------------------------------------------------------------- #
# Phase 26 — AppSec surface tracking (URLs + subdomains) on the engagement.
# --------------------------------------------------------------------------- #
def _url_keys(engagement):
    return {u.get("url") for u in (engagement.get("appsec_urls") or [])
            if isinstance(u, dict) and u.get("url")}


def _subdomain_keys(engagement):
    return {(s or "").lower() for s in (engagement.get("appsec_subdomains") or [])}


def _merge_urls(engagement, new_urls):
    bucket = engagement.setdefault("appsec_urls", [])
    seen = _url_keys(engagement)
    added = 0
    for u in new_urls or []:
        if not isinstance(u, dict) or not u.get("url"):
            continue
        if u["url"] in seen:
            continue
        bucket.append(u); seen.add(u["url"]); added += 1
    return added


def _merge_subdomains(engagement, new_subs):
    bucket = engagement.setdefault("appsec_subdomains", [])
    seen = _subdomain_keys(engagement)
    added = 0
    for s in new_subs or []:
        sl = (s or "").lower().strip()
        if not sl or sl in seen:
            continue
        bucket.append(s); seen.add(sl); added += 1
    return added


# --------------------------------------------------------------------------- #
# Loop driver.
# --------------------------------------------------------------------------- #
def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _append_jsonl(path, obj):
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except OSError:                                                # pragma: no cover
        pass


def run_loop(engagement, *, max_iterations=DEFAULT_MAX_ITERATIONS,
             autopilot_kwargs=None, engagement_path=None,
             loop_log_path=None, lessons_db=None, colorize=False):
    """Observe-decide-run loop.

    engagement:        dict (or dict-like) — mutated in place; written back to
                       `engagement_path` after every iteration if that path
                       is provided.
    max_iterations:    hard cap (default 3). Each iteration is one autopilot
                       pass + observe + merge + re-rank.
    autopilot_kwargs:  dict forwarded to autopilot.run() — the gate chain,
                       dry_run, log_path, ledger_db, etc.
    loop_log_path:     JSONL audit log (one line per iteration).

    Returns a dict:
      {"iterations": N, "merged": {hosts, services, findings},
       "autopilot_runs": [v1_summary_per_iter, ...]}
    """
    autopilot_kwargs = dict(autopilot_kwargs or {})
    agg = {"iterations": 0, "merged_hosts": 0, "merged_services": 0,
           "merged_findings": 0, "merged_hints": 0,
           "autopilot_runs": [], "per_iter": []}
    dry_streak = 0
    # Phase 29 — rerank dedup by situation key. First call always runs;
    # subsequent iterations skip the LLM ranker call when the situation
    # hasn't changed.
    last_situation = None
    cached_recs = 0
    # Phase 30 — pull fact_db + engagement_id out of autopilot_kwargs so
    # _observe_results and the sidequestion pause can see them.
    fact_db = autopilot_kwargs.get("fact_db")
    eid = autopilot_kwargs.get("engagement_id") or engagement.get("meta", {}).get("engagement_id") or "default"
    # Make sure autopilot.run gets a usable engagement_id.
    if fact_db and not autopilot_kwargs.get("engagement_id"):
        autopilot_kwargs["engagement_id"] = eid

    for i in range(1, max_iterations + 1):
        iter_start = _now()
        if colorize:
            sys.stderr.write(f"\n\033[1;35m[autopilot-v2] iteration {i}/{max_iterations}\033[0m\n")
            sys.stderr.flush()
        else:
            print(f"\n[autopilot-v2] iteration {i}/{max_iterations}", file=sys.stderr, flush=True)

        # Phase 30 — sidequestion pause: if there's a pending question
        # with no answer, we stop the loop and ask the operator to answer
        # it (via `mimir-facts answer`) before re-running.
        pending_q = _pending_sidequestion(fact_db, eid)
        if pending_q:
            print(f"[autopilot-v2] pending sidequestion #{pending_q['id']}: "
                  f"{pending_q['data'].get('question', '')!r} — "
                  f"run `mimir-facts answer {pending_q['id']} '...'` first",
                  file=sys.stderr)
            agg["halted_on"] = "sidequestion"
            agg["sidequestion_id"] = pending_q["id"]
            break

        v1 = autopilot.run(engagement, colorize=colorize, **autopilot_kwargs)
        agg["autopilot_runs"].append(v1["summary"])
        agg["iterations"] = i

        parsed = _observe_results(engagement, v1["results"],
                                  fact_db=fact_db, engagement_id=eid)
        agg["merged_hosts"] += len(parsed["new_hosts"])
        agg["merged_services"] += parsed["new_services"]
        agg["merged_findings"] += parsed["new_findings"]
        agg["merged_hints"] += parsed.get("new_hints", 0)

        # Phase 25+26: re-dispatch modules against the new discoveries so
        # the plan GROWS mid-loop instead of only being re-ranked. New
        # services -> infra modules. New URLs / subdomains -> AppSec
        # modules via dispatch_apps. Respects the same noise_ceiling +
        # accept_risk the loop was launched with.
        redispatch_mode = autopilot_kwargs.get("mode") or "vapt"
        new_steps, modules_called = _restage_from_discoveries(
            engagement, parsed["_raw_new_services"],
            mode=redispatch_mode,
            noise_ceiling=autopilot_kwargs.get("noise_ceiling", 5),
            accept_risk=autopilot_kwargs.get("accept_risk") or ("safe",),
            new_urls=parsed["_raw_new_urls"],
            new_subdomains=parsed["_raw_new_subdomains"])

        # Phase 29 — rerank dedup by situation key. Skip the LLM call
        # when nothing structural changed since the prior iteration.
        situation = _situation_key(engagement)
        if situation == last_situation:
            reranked = cached_recs
            rerank_skipped = True
        else:
            reranked = _rerank(engagement, lessons_db=lessons_db)
            cached_recs = reranked
            last_situation = situation
            rerank_skipped = False

        iter_rec = {
            "iteration": i, "ts_start": iter_start, "ts_end": _now(),
            "executed_steps": v1["summary"].get("started", 0),
            "verdicts": v1["summary"].get("verdicts", {}),
            "parsed_steps": parsed["parsed_steps"],
            "new_hosts": parsed["new_hosts"],
            "new_services": parsed["new_services"],
            "new_findings": parsed["new_findings"],
            "new_credentials": parsed["new_credentials"],
            "new_urls": parsed["new_urls"],
            "new_subdomains": parsed["new_subdomains"],
            "new_hints": parsed.get("new_hints", 0),
            "redispatched_steps": new_steps,
            "redispatched_modules": modules_called,
            "reranked_actions": reranked,
            "rerank_skipped": rerank_skipped,
            "aborted": bool(v1["summary"].get("aborted")),
            "aborted_by": v1["summary"].get("aborted_by"),
        }
        agg["per_iter"].append(iter_rec)
        _append_jsonl(loop_log_path, iter_rec)

        if engagement_path:
            try:
                with open(engagement_path, "w", encoding="utf-8") as fh:
                    json.dump(engagement, fh, indent=2, ensure_ascii=False)
            except OSError as exc:                                 # pragma: no cover
                print(f"[autopilot-v2] engagement write failed: {exc}",
                      file=sys.stderr)

        # Early exit — nothing learned AND no executions this round AND no
        # new steps were restaged. (Growth from re-dispatch keeps the loop
        # alive even when parsing yielded no new findings directly.)
        if (parsed["parsed_steps"] == 0 and parsed["new_services"] == 0
                and parsed["new_findings"] == 0 and not parsed["new_hosts"]
                and parsed["new_urls"] == 0 and parsed["new_subdomains"] == 0
                and new_steps == 0):
            dry_streak += 1
            if dry_streak >= 2 or v1["summary"].get("started", 0) == 0:
                print(f"[autopilot-v2] converged after {i} iteration(s) "
                      f"(nothing new learned)", file=sys.stderr, flush=True)
                break
        else:
            dry_streak = 0

        if v1["summary"].get("aborted"):
            print(f"[autopilot-v2] aborted after iteration {i}",
                  file=sys.stderr, flush=True)
            break

    agg["final_hosts"] = len(engagement.get("hosts") or [])
    agg["final_findings"] = len(engagement.get("findings") or [])
    _append_jsonl(loop_log_path, {"summary": agg})
    return agg


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="mimir-autopilot-loop",
        description="Autopilot v2 — observe-decide-run loop around autopilot "
                    "v1's gated executor. Opt-in; same safety chain.")
    ap.add_argument("engagement", help="engagement JSON (mimir-cli --emit-json)")
    ap.add_argument("--max-iterations", type=int, default=DEFAULT_MAX_ITERATIONS,
                    help=f"loop cap (default {DEFAULT_MAX_ITERATIONS})")
    # Autopilot v1 knobs — identical semantics:
    ap.add_argument("--roe")
    ap.add_argument("--accept-risk")
    ap.add_argument("--noise-ceiling", type=int, default=autopilot.DEFAULT_NOISE_CEILING)
    ap.add_argument("--max-steps", type=int, default=autopilot.DEFAULT_MAX_STEPS)
    ap.add_argument("--timeout", type=int, default=autopilot.DEFAULT_TIMEOUT_S)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--log", metavar="FILE",
                    help="per-step JSONL log (autopilot v1 contract)")
    ap.add_argument("--loop-log", metavar="FILE",
                    help="per-iteration JSONL log (autopilot v2)")
    ap.add_argument("--ledger", metavar="DB")
    ap.add_argument("--lessons", metavar="DB",
                    help="apply lessons.py bias when re-ranking")
    ap.add_argument("--yes-i-am-authorized", action="store_true",
                    help="mandatory confirmation the engagement is authorised")
    args = ap.parse_args(argv)

    if not args.yes_i_am_authorized:
        print("[autopilot-v2] refuse: pass --yes-i-am-authorized to confirm "
              "the engagement is in authorised scope.", file=sys.stderr)
        return 2

    with open(args.engagement, encoding="utf-8") as fh:
        engagement = json.load(fh)

    rules = None
    if args.roe:
        try:
            import roe as _roe
            rules = _roe.load(args.roe)
        except Exception as exc:
            print(f"[autopilot-v2] ROE load failed ({exc})", file=sys.stderr)

    accept = [t.strip().lower() for t in (args.accept_risk or "safe").split(",") if t.strip()]
    v1_kwargs = {
        "roe_rules": rules,
        "accept_risk": accept,
        "noise_ceiling": args.noise_ceiling,
        "max_steps": args.max_steps,
        "timeout_s": args.timeout,
        "dry_run": args.dry_run,
        "log_path": args.log,
        "ledger_db": args.ledger,
    }

    summary = run_loop(
        engagement,
        max_iterations=args.max_iterations,
        autopilot_kwargs=v1_kwargs,
        engagement_path=args.engagement if not args.dry_run else None,
        loop_log_path=args.loop_log,
        lessons_db=args.lessons,
        colorize=sys.stderr.isatty(),
    )

    print(f"\n[autopilot-v2] done  iterations={summary['iterations']}  "
          f"merged_hosts={summary['merged_hosts']}  "
          f"merged_services={summary['merged_services']}  "
          f"merged_findings={summary['merged_findings']}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
