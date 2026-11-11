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


def cmd_train(args):
    """Placeholder — prints the recipe + prereqs. The engine does NOT ship a
    trainer in Phase 23. This is intentional: fine-tuning needs a GPU and
    hours; shipping the harness only after the first curated corpus exists
    avoids the "elaborate pipeline / no data" trap."""
    print("mimir-slm train — Phase 23 PLACEHOLDER", file=sys.stderr)
    print()
    print("Recipe once the corpus is ready (>= 500 'worked' traces):")
    print("  1. Export:  mimir-slm export train.jsonl --only-outcome worked")
    print("  2. Prepare: HF datasets format — one {'prompt','response'} per row.")
    print("  3. Base:    qwen2.5:3b-instruct (planner/adviser role) OR")
    print("              phi-3-mini-4k-instruct (narrator role).")
    print("  4. Train:   QLoRA via trl.SFTTrainer or unsloth; local GPU; 1-3 epochs;")
    print("              rank 16 adapter; lr 2e-4; sequence length 2048.")
    print("  5. Convert: llama.cpp 'convert-hf-to-gguf' + 'quantize' (Q5_K_M).")
    print("  6. Serve:   create an Ollama Modelfile pulling base + the GGUF adapter,")
    print("              name it 'mimir-slm:<yyyymmdd>'; qualia.decide picks it up")
    print("              automatically through the existing llm.py role abstraction.")
    print()
    print("Why not ship it today?  Without a curated corpus, fine-tuning adds")
    print("noise rather than signal. Start capturing with MIMIR_SLM_TRACE_DB=,")
    print("curate with 'mimir-slm curate', watch readiness climb, then train.")
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

    for n, fn in (("train", cmd_train), ("eval", cmd_eval), ("promote", cmd_promote)):
        p = sub.add_parser(n, help=f"{n} the SLM (Phase 23 placeholder)")
        p.set_defaults(fn=fn)

    args = ap.parse_args(argv)
    if not getattr(args, "fn", None):
        ap.print_help()
        return 0
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
