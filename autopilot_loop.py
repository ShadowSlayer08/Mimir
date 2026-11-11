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
# Observation — per-step parse + merge.
# --------------------------------------------------------------------------- #
def _observe_results(engagement, results):
    """Walk the autopilot run results, parse each executed step's stdout/stderr
    via parsers.dispatch, merge every ParseResult back into the engagement.
    Returns a dict with the aggregate counts for the iteration record."""
    agg = {"parsed_steps": 0, "new_hosts": [], "new_services": 0,
           "new_findings": 0, "new_credentials": 0}
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
        agg["new_services"] += _merge_services(engagement, pr.new_services)[1]
        agg["new_hosts"] += [h for h in pr.new_hosts
                             if h not in agg["new_hosts"]]
        _merge_hosts(engagement, pr.new_hosts)
        agg["new_findings"] += _merge_findings(engagement, pr.new_findings)
        agg["new_credentials"] += len(pr.new_credentials)
    return agg


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
           "merged_findings": 0, "autopilot_runs": [], "per_iter": []}
    dry_streak = 0

    for i in range(1, max_iterations + 1):
        iter_start = _now()
        if colorize:
            sys.stderr.write(f"\n\033[1;35m[autopilot-v2] iteration {i}/{max_iterations}\033[0m\n")
            sys.stderr.flush()
        else:
            print(f"\n[autopilot-v2] iteration {i}/{max_iterations}", file=sys.stderr, flush=True)

        v1 = autopilot.run(engagement, colorize=colorize, **autopilot_kwargs)
        agg["autopilot_runs"].append(v1["summary"])
        agg["iterations"] = i

        parsed = _observe_results(engagement, v1["results"])
        agg["merged_hosts"] += len(parsed["new_hosts"])
        agg["merged_services"] += parsed["new_services"]
        agg["merged_findings"] += parsed["new_findings"]

        reranked = _rerank(engagement, lessons_db=lessons_db)

        iter_rec = {
            "iteration": i, "ts_start": iter_start, "ts_end": _now(),
            "executed_steps": v1["summary"].get("started", 0),
            "verdicts": v1["summary"].get("verdicts", {}),
            "parsed_steps": parsed["parsed_steps"],
            "new_hosts": parsed["new_hosts"],
            "new_services": parsed["new_services"],
            "new_findings": parsed["new_findings"],
            "new_credentials": parsed["new_credentials"],
            "reranked_actions": reranked,
            "aborted": bool(v1["summary"].get("aborted")),
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

        # Early exit — nothing learned AND no executions this round.
        if (parsed["parsed_steps"] == 0 and parsed["new_services"] == 0
                and parsed["new_findings"] == 0 and not parsed["new_hosts"]):
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
