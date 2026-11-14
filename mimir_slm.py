#!/usr/bin/env python3
"""
mimir_slm.py — operator CLI for the Mimir SLM (Specialised Language Model)
training pipeline.

The engine already routes every qualitative decision through `qualia.decide`
and `qualia.prose`. Phase 23 adds `slm.trace` — an opt-in append-only SQLite
log of those decisions — and this CLI, which lets the operator:

  status          — snapshot of the trace corpus + readiness score
  trace           — tail recent decision traces (filterable by kind)
  export          — emit curated training JSONL (ready for QLoRA)
  curate          — label a trace as worked / no_signal / muted
  train           — PLACEHOLDER: prints the recipe + prereqs (no trainer
                    ships in-tree in Phase 23; the first LoRA lands after a
                    curated corpus exists).
  eval            — PLACEHOLDER: planned eval harness (vs. deterministic).
  promote         — PLACEHOLDER: planned registry hand-off to Ollama.

The sink is operator-controlled: set `MIMIR_SLM_TRACE_DB=/path/to.db` to
start capturing, leave it unset to run entirely as before. No tracing
happens, and there is zero import-time overhead, when the env is unset.

Example — a one-engagement capture + stats:

    export MIMIR_SLM_TRACE_DB=~/mimir-slm.db
    export MIMIR_SLM_TRACE_ENGAGEMENT=acme-2026Q3
    mimir-cli --from-xml scan.xml --yes --llm --emit-json eng.json
    mimir-slm status
    mimir-slm export curated.jsonl --only-outcome worked
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from slm import trace as _trace       # noqa: E402
from slm import reward as _reward     # noqa: E402
from slm import distill as _distill   # noqa: E402
from slm import rl as _rl             # noqa: E402
from slm import bridge as _bridge     # noqa: E402


def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                          # pragma: no cover
            pass


_force_utf8_stdio()


# --------------------------------------------------------------------------- #
# Sub-commands
# --------------------------------------------------------------------------- #
def cmd_status(args):
    path = args.db or _trace._db_path()
    if not path:
        print("[mimir-slm] No trace DB configured. Set MIMIR_SLM_TRACE_DB=/path/to.db "
              "or pass --db.", file=sys.stderr)
        return 1
    s = _trace.stats(path)
    if not s.get("present"):
        print(f"[mimir-slm] trace DB not present yet at: {path}")
        print(f"[mimir-slm] it will be created on the next qualia.decide call "
              f"with the env set.")
        return 0
    print(f"[mimir-slm] db       : {path}")
    print(f"[mimir-slm] total    : {s['total']}")
    print(f"[mimir-slm] fallback : {s['fallback_rate']*100:.1f}% of rows "
          f"(lower = more LLM-driven decisions)")
    if s.get("validator_pass_rate") is not None:
        print(f"[mimir-slm] validator-pass: {s['validator_pass_rate']*100:.1f}%")
    print(f"[mimir-slm] curated  : {dict(s['curated']) or '{}'}  "
          f"readiness={s['readiness']*100:.1f}%  (target: 500 'worked' traces)")
    if s["by_kind"]:
        print("[mimir-slm] by kind  :")
        for k, c in sorted(s["by_kind"].items(), key=lambda kv: -kv[1])[:10]:
            print(f"             {c:>6}  {k}")
    if s["by_role"]:
        print("[mimir-slm] by role  :", dict(s["by_role"]))
    return 0


def cmd_trace(args):
    rows = _trace.recent(args.db, limit=args.limit, kind=args.kind)
    if not rows:
        print("[mimir-slm] (no traces)", file=sys.stderr)
        return 0
    for r in rows:
        tag = "FB " if r["used_fallback"] else "LLM"
        outc = r["outcome"] or "-"
        print(f"#{r['id']:>5} {r['ts'][:19]} [{tag}] "
              f"{r['kind']:<20} role={r['role']:<9} outcome={outc}")
        p = (r["prompt"] or "").replace("\n", " ")[:120]
        res = (r["result"] or "").replace("\n", " ")[:120]
        print(f"        prompt: {p}")
        print(f"        result: {res}")
    return 0


def cmd_curate(args):
    path = args.db or _trace._db_path()
    if not path:
        print("[mimir-slm] no DB configured", file=sys.stderr)
        return 1
    try:
        _trace.set_outcome(path, args.id, args.outcome)
    except ValueError as exc:
        print(f"[mimir-slm] {exc}", file=sys.stderr)
        return 2
    print(f"[mimir-slm] #{args.id} -> {args.outcome}")
    return 0


def cmd_export(args):
    path = args.db or _trace._db_path()
    if not path:
        print("[mimir-slm] no DB configured", file=sys.stderr)
        return 1
    if args.out == "-":
        n = _trace.export_jsonl(path, sys.stdout, only_outcome=args.only_outcome)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            n = _trace.export_jsonl(path, fh, only_outcome=args.only_outcome)
    print(f"[mimir-slm] exported {n} row(s)"
          + (f" (only outcome={args.only_outcome})" if args.only_outcome else ""),
          file=sys.stderr)
    return 0


def cmd_reward(args):
    """Score every trace with slm.reward — signals from lessons + autopilot +
    curator + optional peer. Writes `reward` + `reward_breakdown` columns."""
    path = args.db or _trace._db_path()
    if not path:
        print("[mimir-slm] no DB configured", file=sys.stderr); return 1
    weights = {}
    for kv in (args.weight or []):
        if "=" in kv:
            k, v = kv.split("=", 1)
            weights[k.strip()] = v.strip()
    peer_signals = None
    if args.with_peer:
        if not _bridge.available():
            print("[mimir-slm] peer bridge unavailable — scoring without peer signal",
                  file=sys.stderr)
        else:
            print("[mimir-slm] querying Crucible peer for up to "
                  f"{args.peer_limit} rows...", file=sys.stderr)
            peer_signals = _bridge.query_peer_batch(
                path, only_outcome="worked", limit=args.peer_limit)
            print(f"[mimir-slm] got {len(peer_signals)} peer signals",
                  file=sys.stderr)
    n, stats = _reward.score_all(
        path, lessons_db=args.lessons, ledger_db=args.ledger,
        peer_signals=peer_signals, weights=weights or None,
        only_curated=args.only_curated)
    print(f"[mimir-slm] scored {n} row(s)  mean={stats['mean']}  "
          f"+{stats['positive']} / -{stats['negative']}  "
          f"range=[{stats['min']}, {stats['max']}]")
    return 0


def cmd_distill(args):
    path = args.db or _trace._db_path()
    if not path:
        print("[mimir-slm] no DB configured", file=sys.stderr); return 1
    include_teacher = not args.no_teacher
    if args.out == "-":
        n = _distill.export_jsonl(path, sys.stdout,
                                  only_outcome=args.only_outcome,
                                  include_teacher=include_teacher)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            n = _distill.export_jsonl(path, fh,
                                      only_outcome=args.only_outcome,
                                      include_teacher=include_teacher)
    print(f"[mimir-slm] wrote {n} distillation row(s) "
          + (f"(teacher: {_distill.pick_teacher_model() or 'offline'})"
             if include_teacher else "(no teacher)"), file=sys.stderr)
    return 0


def cmd_rl(args):
    if args.sub == "export":
        path = args.db or _trace._db_path()
        if not path:
            print("[mimir-slm] no DB configured", file=sys.stderr); return 1
        peer_signals = None
        if args.with_peer and _bridge.available():
            peer_signals = {}
            raw = _bridge.query_peer_batch(path, only_outcome=args.only_outcome,
                                           limit=args.peer_limit)
            for tid, sig in raw.items():
                # Convert id→signal to prompt_hash→signal.
                import sqlite3
                con = sqlite3.connect(path, isolation_level=None)
                try:
                    r = con.execute(
                        "SELECT prompt_hash FROM qualia_trace WHERE id=?",
                        (tid,)).fetchone()
                finally:
                    con.close()
                if r:
                    peer_signals[r[0]] = sig
        if args.out == "-":
            n = _rl.export_jsonl(
                path, sys.stdout, lessons_db=args.lessons,
                ledger_db=args.ledger,
                samples_per_prompt=args.samples_per_prompt,
                only_outcome=args.only_outcome,
                peer_signals=peer_signals)
        else:
            with open(args.out, "w", encoding="utf-8") as fh:
                n = _rl.export_jsonl(
                    path, fh, lessons_db=args.lessons,
                    ledger_db=args.ledger,
                    samples_per_prompt=args.samples_per_prompt,
                    only_outcome=args.only_outcome,
                    peer_signals=peer_signals)
        print(f"[mimir-slm] wrote {n} GRPO group(s) "
              f"(samples_per_prompt={args.samples_per_prompt})",
              file=sys.stderr)
        return 0
    # rl recipe
    print(_rl.recipe())
    return 0


def cmd_peer_sync(args):
    if args.sub == "status":
        s = _bridge.peer_status()
        print(json.dumps(s, indent=2))
        return 0
    if args.sub == "export":
        path = args.db or _trace._db_path()
        if not path:
            print("[mimir-slm] no DB configured", file=sys.stderr); return 1
        stream = sys.stdout if args.out == "-" else open(args.out, "w", encoding="utf-8")
        try:
            n = _bridge.export_dump(path, stream,
                                    only_outcome=args.only_outcome,
                                    only_role=args.only_role,
                                    limit=args.limit)
        finally:
            if stream is not sys.stdout:
                stream.close()
        print(f"[mimir-slm] exported {n} row(s) for Crucible", file=sys.stderr)
        return 0
    if args.sub == "import":
        path = args.db or _trace._db_path()
        if not path:
            print("[mimir-slm] no DB configured", file=sys.stderr); return 1
        src = sys.stdin if args.src == "-" else open(args.src, encoding="utf-8")
        try:
            n = _bridge.import_dump(path, src)
        finally:
            if src is not sys.stdin:
                src.close()
        print(f"[mimir-slm] imported {n} peer row(s) (kind=peer:*, outcome=NULL)",
              file=sys.stderr)
        return 0
    return 0


def cmd_train(args):
    """Documented recipe — the trainer runs outside the engine."""
    print("mimir-slm train — recipe follows (no trainer ships in-tree)",
          file=sys.stderr)
    print()
    print("For supervised fine-tuning (SFT warm-up):")
    print("  1. mimir-slm reward  --lessons eng.db --ledger eng.db  --with-peer")
    print("  2. mimir-slm distill train.sft.jsonl  --only-outcome worked")
    print("  3. QLoRA via trl.SFTTrainer on qwen2.5:3b or phi-3-mini.")
    print("     rank=16, lr=2e-4, 1-3 epochs, seq-len 2048.")
    print("  4. Convert + quantise to GGUF via llama.cpp (Q5_K_M).")
    print("  5. Ollama Modelfile tagged mimir-slm:<yyyymmdd>; qualia.decide")
    print("     picks it up through llm.py's role abstraction.")
    print()
    print("For reinforcement learning (GRPO), see `mimir-slm rl recipe`.")
    return 0


def cmd_eval(args):
    print("mimir-slm eval — Phase 23 PLACEHOLDER", file=sys.stderr)
    print()
    print("Planned surface: run the existing scenario corpus (evals/scenarios/*.yml)")
    print("twice — once with the deterministic ranker, once with the SLM candidate —")
    print("and report A/B deltas on recall + path quality + ranking stability.")
    print("The harness lives in evals/bench.py; the SLM switch will be a --slm-model")
    print("flag. For now, 'python -m evals.bench --compare-llm' already does the")
    print("deterministic-vs-LLM A/B against whatever Ollama serves.")
    return 0


def cmd_promote(args):
    print("mimir-slm promote — Phase 23 PLACEHOLDER", file=sys.stderr)
    print()
    print("Planned surface:")
    print("  mimir-slm promote <model-tag>   # pins qualia.decide to this model")
    print("  mimir-slm promote --rollback    # restores whatever Ollama served before")
    print()
    print("Implementation: writes MIMIR_LLM_PLANNER / MIMIR_LLM_NARRATOR / MIMIR_LLM_ADVISER")
    print("into ~/.mimir/llm-pins so llm.py's role picker uses the promoted tag until rolled back.")
    return 0


# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="mimir-slm",
        description="Mimir SLM training-data pipeline — capture qualia decisions, "
                    "curate them, export training JSONL. Fine-tuning itself "
                    "is a documented recipe (Phase 23 placeholder) until a "
                    "curated corpus exists.")
    sub = ap.add_subparsers(dest="cmd", required=False)

    p = sub.add_parser("status", help="corpus stats + readiness score")
    p.add_argument("--db")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("trace", help="tail recent traces")
    p.add_argument("--db")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--kind")
    p.set_defaults(fn=cmd_trace)

    p = sub.add_parser("curate", help="label a trace (worked / no_signal / muted)")
    p.add_argument("--db")
    p.add_argument("id", type=int)
    p.add_argument("outcome", choices=["worked", "no_signal", "muted"])
    p.set_defaults(fn=cmd_curate)

    p = sub.add_parser("export", help="emit curated training JSONL")
    p.add_argument("--db")
    p.add_argument("out", help="output JSONL path, or '-' for stdout")
    p.add_argument("--only-outcome", choices=["worked", "no_signal", "muted"])
    p.set_defaults(fn=cmd_export)

    # Phase 24 — reward / distill / rl / peer-sync
    p = sub.add_parser("reward", help="score traces (lessons + autopilot + peer)")
    p.add_argument("--db")
    p.add_argument("--lessons", help="lessons.py DB for technique outcome signal")
    p.add_argument("--ledger", help="autopilot ledger DB for verdict signal")
    p.add_argument("--only-curated", action="store_true",
                   help="score only rows the operator has labelled")
    p.add_argument("--with-peer", action="store_true",
                   help="also query Crucible's SLM for a peer-opinion signal")
    p.add_argument("--peer-limit", type=int, default=200)
    p.add_argument("--weight", action="append", metavar="KEY=VAL",
                   help="override one reward weight; repeatable")
    p.set_defaults(fn=cmd_reward)

    p = sub.add_parser("distill", help="emit teacher-student SFT dataset JSONL")
    p.add_argument("--db")
    p.add_argument("out", help="output JSONL path, or '-' for stdout")
    p.add_argument("--only-outcome", choices=["worked", "no_signal", "muted"],
                   default="worked")
    p.add_argument("--no-teacher", action="store_true",
                   help="skip the teacher re-ask (produces student-only rows)")
    p.set_defaults(fn=cmd_distill)

    p = sub.add_parser("rl", help="GRPO dataset export + recipe")
    rl_sub = p.add_subparsers(dest="sub", required=True)
    pe = rl_sub.add_parser("export", help="emit GRPO JSONL (prompt + N samples)")
    pe.add_argument("--db")
    pe.add_argument("out", help="output JSONL path, or '-' for stdout")
    pe.add_argument("--samples-per-prompt", type=int, default=4)
    pe.add_argument("--only-outcome", choices=["worked", "no_signal", "muted"],
                    default="worked")
    pe.add_argument("--lessons")
    pe.add_argument("--ledger")
    pe.add_argument("--with-peer", action="store_true")
    pe.add_argument("--peer-limit", type=int, default=200)
    rl_sub.add_parser("recipe", help="print the GRPO training recipe")
    p.set_defaults(fn=cmd_rl)

    p = sub.add_parser("peer-sync", help="exchange curated corpora with Crucible")
    ps_sub = p.add_subparsers(dest="sub", required=True)
    ps_sub.add_parser("status", help="peer bridge availability + URL/key presence")
    pse = ps_sub.add_parser("export", help="emit JSONL dump for Crucible")
    pse.add_argument("--db")
    pse.add_argument("out", help="output JSONL path, or '-' for stdout")
    pse.add_argument("--only-outcome", choices=["worked", "no_signal", "muted"])
    pse.add_argument("--only-role")
    pse.add_argument("--limit", type=int)
    psi = ps_sub.add_parser("import", help="ingest a Crucible dump as peer:* rows")
    psi.add_argument("--db")
    psi.add_argument("src", help="input JSONL path, or '-' for stdin")
    p.set_defaults(fn=cmd_peer_sync)

    for n, fn in (("train", cmd_train), ("eval", cmd_eval), ("promote", cmd_promote)):
        p = sub.add_parser(n, help=f"{n} the SLM (documented recipe)")
        p.set_defaults(fn=fn)

    args = ap.parse_args(argv)
    if not getattr(args, "fn", None):
        ap.print_help()
        return 0
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
