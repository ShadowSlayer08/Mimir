#!/usr/bin/env python3
"""
evals/bench.py — evaluation harness for the pentest engine.

Authorized / lab / CTF use only.

Runs the engine over a corpus of scenario YAMLs (evals/scenarios/*.yml), computes
recall for expected findings / ATT&CK techniques / attack-path kinds, and prints
a per-scenario pass/fail table + JSON export. Exit code is non-zero on any miss,
so this drops straight into CI.

    python -m evals.bench                       # run all scenarios (deterministic)
    python -m evals.bench --scenario evals/scenarios/full_scan_dc.yml
    python -m evals.bench --compare-llm         # A/B: deterministic vs LLM-first
    python -m evals.bench --json out.json       # dump structured results

The harness is deliberately DETERMINISTIC by default — it forces
`llm.available() -> False` so results are reproducible in CI without an Ollama
runtime. `--compare-llm` opts in to A/B the LLM-first pipeline against the same
scenarios (needs a running Ollama on OLLAMA_HOST).
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import time

# Repo root on sys.path so `evals` can import the engine when run as a script.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# --------------------------------------------------------------------------- #
def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                          # pragma: no cover
            pass


_force_utf8_stdio()


def _load_scenario(path):
    """Parse a scenario YAML. Uses PyYAML if installed, else a tiny fallback that
    handles the flow-style fields we use (str, int, list, list-of-dicts)."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        import yaml
        return yaml.safe_load(text)
    except Exception:                                              # pragma: no cover
        return _tiny_yaml(text)


def _tiny_yaml(text):
    """A minimalist YAML reader — enough for our scenario file shape."""
    # Reuse the KB loader's parser (it handles the same flow-map style we use in docs/).
    from knowledge_loader import _parse_yaml_block
    return _parse_yaml_block(text)


_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_at_least(actual, threshold):
    return _SEV_ORDER.get((actual or "").lower(), -1) >= _SEV_ORDER.get(threshold, -1)


# --------------------------------------------------------------------------- #
# Engine invocation — pure, no side effects.
def _run_engine(fixture_path, *, deterministic=True, operator=None):
    """Run the engine over one nmap XML fixture. Returns (report, paths, recs, app_mods).

    `operator` is an optional dict shaped like a scenario's `operator:` block:
        {web: [urls], api: [...], mobile: [...], thick: [...], cloud: [...],
         wireless: [...], k8s: [...], source: [...], identity: [...], hypervisor: [...]}
    which is routed through `apptargets.app_targets` -> `dispatch_apps`, so a
    scenario can exercise the AppSec pillar without needing an nmap fixture that
    happens to expose that surface.
    """
    from nmap_analyzer import load_scan, analyze, build_report
    from attack_path_engine import generate_paths
    from apptargets import app_targets
    from modules import dispatch_apps
    import copilot
    import llm

    saved = llm.available
    if deterministic:
        llm.available = lambda: False
    try:
        hosts, meta, _ = load_scan(fixture_path)
        report = build_report(hosts, meta, analyze(hosts))
        paths = generate_paths(report)
        recs = copilot.recommend(report.get("findings", []), paths, top=5)
        app_mods = []
        op = operator or {}
        if any(op.get(k) for k in ("web", "api", "mobile", "thick", "cloud",
                                   "wireless", "k8s", "source", "identity", "hypervisor")):
            targets = app_targets(
                report,
                web=op.get("web", []) or [], api=op.get("api", []) or [],
                mobile=op.get("mobile", []) or [], thick=op.get("thick", []) or [],
                cloud=op.get("cloud", []) or [], wireless=op.get("wireless", []) or [],
                k8s=op.get("k8s", []) or [], source=op.get("source", []) or [],
                identity=op.get("identity", []) or [], hypervisor=op.get("hypervisor", []) or [])
            app_mods = dispatch_apps(targets, report)
        return report, paths, recs, app_mods
    finally:
        llm.available = saved


# --------------------------------------------------------------------------- #
# Scoring — pure, testable.
def _evaluate(scenario, report, paths, recs, app_mods=None):
    """Score one scenario's expected assertions against actual engine output."""
    exp = scenario.get("expected", {}) or {}
    findings = report.get("findings", []) or []
    hosts = report.get("host_summary", []) or []
    misses = []
    hits = 0
    total = 0

    # counts
    total += 1
    if len(hosts) >= int(exp.get("hosts_min", 0)):
        hits += 1
    else:
        misses.append(f"hosts_min: {len(hosts)} < {exp.get('hosts_min')}")

    total += 1
    if len(findings) >= int(exp.get("findings_min", 0)):
        hits += 1
    else:
        misses.append(f"findings_min: {len(findings)} < {exp.get('findings_min')}")

    # per-finding matches
    for m in (exp.get("findings_must_include") or []):
        total += 1
        needle = (m.get("title_contains") or "").lower()
        wants_sev = m.get("severity")
        wants_sev_min = m.get("severity_min")
        matched = None
        for f in findings:
            title = (f.get("title") or "").lower()
            if needle and needle not in title:
                continue
            sev = f.get("severity", "")
            if wants_sev and sev.lower() != wants_sev.lower():
                continue
            if wants_sev_min and not _sev_at_least(sev, wants_sev_min):
                continue
            matched = f
            break
        if matched:
            hits += 1
        else:
            misses.append(f"finding not surfaced: {needle!r} "
                          f"(sev={wants_sev or wants_sev_min or 'any'})")

    # ATT&CK techniques (in any staged step)
    seen_tech = {(s.get("technique_id") or "") for p in paths for s in p.get("steps", [])}
    for t in (exp.get("techniques_must_include") or []):
        total += 1
        if t in seen_tech:
            hits += 1
        else:
            misses.append(f"technique missing from any staged step: {t}")

    # path kinds
    seen_kinds = {(p.get("kind") or "") for p in paths}
    for k in (exp.get("path_kinds_must_include") or []):
        total += 1
        if k in seen_kinds:
            hits += 1
        else:
            misses.append(f"path kind missing: {k!r}")

    # AppSec-pillar assertions — ModuleResult uses `module` as the id (web_app,
    # api, mobile, thick, cloud, wireless, k8s, source, identity, hypervisor).
    app_ids_seen = {(m.get("module") or "") for m in (app_mods or [])}
    for k in (exp.get("appsec_modules_must_include") or []):
        total += 1
        if k in app_ids_seen:
            hits += 1
        else:
            misses.append(f"AppSec module not dispatched: {k!r}")

    # appsec_checks: [{module, name_contains, attack?}]
    for want in (exp.get("appsec_checks_must_include") or []):
        total += 1
        mod = (want.get("module") or "").lower()
        needle = (want.get("name_contains") or "").lower()
        want_attack = (want.get("attack") or "").strip()
        matched = False
        for m in (app_mods or []):
            if mod and (m.get("module") or "").lower() != mod:
                continue
            for c in m.get("checks", []):
                cn = (c.get("name") or "").lower()
                if needle and needle not in cn:
                    continue
                if want_attack and (c.get("attack") or "") != want_attack:
                    continue
                matched = True
                break
            if matched:
                break
        if matched:
            hits += 1
        else:
            misses.append(f"AppSec check not staged: module={mod or '*'} "
                          f"name~={needle!r} attack={want_attack or 'any'}")

    # top-action regex
    if exp.get("top_action_title_regex") and recs:
        total += 1
        rx = re.compile(exp["top_action_title_regex"], re.I)
        title = recs[0].get("title", "") if recs else ""
        if rx.search(title):
            hits += 1
        else:
            misses.append(f"top action title {title!r} does not match "
                          f"/{exp['top_action_title_regex']}/i")

    return {
        "hits": hits, "total": total,
        "recall": (hits / total) if total else 1.0,
        "misses": misses,
        "counts": {"hosts": len(hosts), "findings": len(findings),
                   "paths": len(paths), "techniques_seen": len(seen_tech),
                   "app_modules": len(app_mods or [])},
    }


# --------------------------------------------------------------------------- #
def _run_scenario(path, *, compare_llm=False):
    scenario = _load_scenario(path)
    fixture = os.path.join(_ROOT, scenario["fixture"])
    if not os.path.exists(fixture):
        return {"scenario": path, "error": f"fixture not found: {fixture}"}

    operator = scenario.get("operator") or {}
    t0 = time.perf_counter()
    report, paths, recs, app_mods = _run_engine(fixture, deterministic=True, operator=operator)
    det = _evaluate(scenario, report, paths, recs, app_mods)
    det["elapsed_s"] = round(time.perf_counter() - t0, 2)

    out = {"scenario": os.path.relpath(path, _ROOT),
           "fixture": scenario["fixture"],
           "difficulty": scenario.get("difficulty", "?"),
           "notes": (scenario.get("notes") or "").strip(),
           "deterministic": det}

    if compare_llm:
        import llm
        if llm.available():
            t0 = time.perf_counter()
            report_l, paths_l, recs_l, app_l = _run_engine(fixture, deterministic=False,
                                                           operator=operator)
            llm_res = _evaluate(scenario, report_l, paths_l, recs_l, app_l)
            llm_res["elapsed_s"] = round(time.perf_counter() - t0, 2)
            llm_res["top_action_title"] = recs_l[0].get("title", "") if recs_l else ""
            out["llm"] = llm_res
        else:
            out["llm"] = {"skipped": "Ollama not reachable"}

    out["passed"] = det["hits"] == det["total"]
    return out


def _print_summary(results):
    print(f"\n{'scenario':<40} {'diff':<6} {'recall':<12} {'time':<8} {'status'}")
    print("-" * 84)
    all_pass = True
    for r in results:
        if "error" in r:
            print(f"{r['scenario']:<40} {'-':<6} {'-':<12} {'-':<8} ERROR: {r['error']}")
            all_pass = False
            continue
        det = r["deterministic"]
        rec = f"{det['hits']}/{det['total']} ({det['recall']*100:.0f}%)"
        status = "PASS" if r["passed"] else "MISS"
        if not r["passed"]:
            all_pass = False
        print(f"{r['scenario']:<40} {r['difficulty']:<6} {rec:<12} "
              f"{det['elapsed_s']:>5.2f}s  {status}")
        for m in det["misses"]:
            print(f"    - {m}")
        if r.get("llm") and "recall" in r["llm"]:
            l = r["llm"]
            drec = det["recall"]
            lrec = l["recall"]
            arrow = ("=", "▲" if lrec > drec else "▼")[lrec != drec]
            print(f"    LLM: {l['hits']}/{l['total']} ({l['recall']*100:.0f}%)  "
                  f"{l['elapsed_s']:.1f}s   det->llm {arrow} "
                  f"({drec*100:.0f}% -> {lrec*100:.0f}%)")
            if l.get("top_action_title"):
                print(f"    LLM top: {l['top_action_title'][:70]}")
        elif r.get("llm", {}).get("skipped"):
            print(f"    LLM: skipped ({r['llm']['skipped']})")
    return all_pass


def main(argv=None):
    ap = argparse.ArgumentParser(prog="evals.bench",
                                 description="pentest engine eval harness — measured coverage")
    ap.add_argument("--scenario", help="single scenario file (else all evals/scenarios/*.yml)")
    ap.add_argument("--compare-llm", action="store_true",
                    help="also run each scenario with the LLM-first pipeline (needs Ollama)")
    ap.add_argument("--json", help="write full structured results to this JSON file")
    args = ap.parse_args(argv)

    if args.scenario:
        files = [args.scenario]
    else:
        files = sorted(glob.glob(os.path.join(_HERE, "scenarios", "*.yml")))
    if not files:
        print("no scenarios found under evals/scenarios/")
        return 2

    results = [_run_scenario(p, compare_llm=args.compare_llm) for p in files]
    all_pass = _print_summary(results)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"results": results, "all_passed": all_pass}, fh, indent=2)
        print(f"\n[+] wrote {args.json}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
