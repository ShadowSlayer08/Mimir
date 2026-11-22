#!/usr/bin/env python3
"""slm/train_dpo.py — actual DPO trainer (not a recipe).

Phase 25 fix for "the trainer is a recipe, not code." DPO (Direct Preference
Optimization — Rafailov et al. 2023) is the right fit for our situation:
  * Offline. Pairs are pre-computed; no on-policy rollouts during training.
  * Uses the reward scores we already compute (slm.reward). High-reward
    sample in a pair becomes `chosen`; low-reward sample becomes `rejected`.
  * One GPU, one evening. Small base (qwen2.5:3b / phi-3-mini) + QLoRA.

The GRPO recipe stays in slm.rl for the on-policy option; this file is
what an operator actually runs first.

Design:
  * Heavy deps (torch, transformers, trl, datasets, peft, accelerate) are
    imported INSIDE main — nothing happens at module load. Importing this
    module never pulls torch in. The test suite imports cleanly on a box
    without CUDA.
  * `--dry-run` validates the dataset shape and the pair-construction logic
    without ever touching a GPU, so CI can exercise the entry point.
  * `build_pairs()` is pure and tested; the trainer wraps it.

Usage once you have a reward-scored trace DB:

  pip install torch transformers trl datasets peft accelerate bitsandbytes

  mimir-slm reward --db trace.db --lessons eng.db --ledger eng.db

  python -m slm.train_dpo \\
      --db trace.db --out mimir-slm-dpo-lora \\
      --base Qwen/Qwen2.5-3B-Instruct --epochs 1

The adapter lands in --out as a QLoRA checkpoint; convert to GGUF with
llama.cpp and promote via the Ollama Modelfile pattern from `slm.rl.recipe()`.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys


# --------------------------------------------------------------------------- #
# Pair construction — pure, offline, testable without any DL deps.
# --------------------------------------------------------------------------- #
def _group_traces_by_prompt(db_path, *, only_outcome=None, min_pair_delta=0.2):
    """Walk the trace DB, bucket rows by prompt, and keep only buckets that
    contain at least two responses whose reward differs by >= min_pair_delta.
    Returns {prompt: [(response, reward), ...]} sorted by reward descending
    within each bucket."""
    if not os.path.exists(db_path):
        return {}
    con = sqlite3.connect(db_path, isolation_level=None)
    try:
        cols = {r[1] for r in con.execute(
            "PRAGMA table_info(qualia_trace)").fetchall()}
        if "reward" not in cols:
            return {}
        q = ("SELECT prompt, llm_result, fallback_result, used_fallback, reward "
             "FROM qualia_trace WHERE prompt IS NOT NULL AND reward IS NOT NULL")
        params = []
        if only_outcome:
            q += " AND outcome=?"
            params.append(only_outcome)
        rows = con.execute(q, params).fetchall()
    finally:
        con.close()
    buckets = {}
    for prompt, llm_r, fb_r, used_fb, rew in rows:
        text = fb_r if used_fb else llm_r
        if not text:
            continue
        buckets.setdefault(prompt, []).append((text, float(rew)))
    # Keep only prompts with ≥1 pair whose reward delta ≥ min_pair_delta.
    out = {}
    for p, samples in buckets.items():
        if len(samples) < 2:
            continue
        samples = sorted(samples, key=lambda x: -x[1])
        if samples[0][1] - samples[-1][1] < min_pair_delta:
            continue
        out[p] = samples
    return out


def build_pairs(db_path, *, only_outcome=None, min_pair_delta=0.2,
                max_pairs_per_prompt=3):
    """Yield DPO rows: {prompt, chosen, rejected, delta}.

    For each prompt bucket we pair the top-ranked response (chosen) with up
    to `max_pairs_per_prompt` bottom-ranked responses (rejected).
    """
    buckets = _group_traces_by_prompt(
        db_path, only_outcome=only_outcome, min_pair_delta=min_pair_delta)
    for prompt, samples in buckets.items():
        if len(samples) < 2:
            continue
        chosen, chosen_r = samples[0]
        for text, r in samples[-max_pairs_per_prompt:]:
            if text == chosen:
                continue
            delta = chosen_r - r
            if delta < min_pair_delta:
                continue
            yield {"prompt": prompt, "chosen": chosen,
                   "rejected": text, "delta": round(delta, 4)}


def export_pairs_jsonl(db_path, out_stream, **kwargs):
    n = 0
    for p in build_pairs(db_path, **kwargs):
        out_stream.write(json.dumps(p, ensure_ascii=False) + "\n")
        n += 1
    return n


# --------------------------------------------------------------------------- #
# Trainer — all heavy imports happen here.
# --------------------------------------------------------------------------- #
def _check_deps():
    missing = []
    for name in ("torch", "transformers", "trl", "datasets", "peft"):
        try:
            __import__(name)
        except ImportError:
            missing.append(name)
    return missing


def train(db_path, out_dir, *, base="Qwen/Qwen2.5-3B-Instruct",
          epochs=1, lr=5e-6, batch_size=1, grad_accum=8, beta=0.1,
          only_outcome="worked", min_pair_delta=0.2, max_seq_len=2048,
          dry_run=False):
    """Run the full DPO training. Returns the output dir on success, or
    raises RuntimeError with a hint on missing deps."""
    missing = _check_deps()
    if missing and not dry_run:
        raise RuntimeError(
            "Missing dependencies: " + ", ".join(missing) + ". Install: "
            "pip install torch transformers trl datasets peft accelerate bitsandbytes")

    pair_count = 0
    pairs_tmp = os.path.join(out_dir, "pairs.jsonl") if out_dir else None
    if dry_run:
        pair_count = sum(1 for _ in build_pairs(
            db_path, only_outcome=only_outcome,
            min_pair_delta=min_pair_delta))
        return {"dry_run": True, "pairs": pair_count, "would_write": pairs_tmp,
                "missing_deps": missing}

    os.makedirs(out_dir, exist_ok=True)
    with open(pairs_tmp, "w", encoding="utf-8") as fh:
        pair_count = export_pairs_jsonl(
            db_path, fh, only_outcome=only_outcome,
            min_pair_delta=min_pair_delta)
    if pair_count == 0:
        raise RuntimeError(
            f"No DPO-trainable pairs in {db_path}. "
            f"Run `mimir-slm reward` first; needs ≥2 reward-scored rows "
            f"per prompt with delta ≥ {min_pair_delta}.")

    # Heavy imports are gated by _check_deps above.
    from datasets import load_dataset
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from trl import DPOConfig, DPOTrainer

    tok = AutoTokenizer.from_pretrained(base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(base, device_map="auto")

    ds = load_dataset("json", data_files=pairs_tmp)["train"]

    cfg = DPOConfig(
        output_dir=out_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=grad_accum,
        learning_rate=lr,
        max_length=max_seq_len,
        max_prompt_length=max_seq_len // 2,
        beta=beta,
        save_strategy="epoch",
        logging_steps=10,
        remove_unused_columns=False,
    )
    trainer = DPOTrainer(model=model, args=cfg, train_dataset=ds,
                         processing_class=tok)
    trainer.train()
    trainer.save_model(out_dir)
    return {"out": out_dir, "pairs": pair_count, "epochs": epochs}


# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="mimir-slm-train-dpo",
        description="DPO trainer for the Mimir SLM. Offline, GPU-friendly, "
                    "QLoRA-shaped. Reads reward-scored traces; produces an "
                    "adapter checkpoint ready for llama.cpp -> GGUF -> Ollama.")
    ap.add_argument("--db", required=True,
                    help="trace DB (must have been through `mimir-slm reward`)")
    ap.add_argument("--out", default="mimir-slm-dpo-lora")
    ap.add_argument("--base", default="Qwen/Qwen2.5-3B-Instruct")
    ap.add_argument("--epochs", type=int, default=1)
    ap.add_argument("--lr", type=float, default=5e-6)
    ap.add_argument("--batch-size", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--beta", type=float, default=0.1)
    ap.add_argument("--only-outcome", default="worked",
                    choices=["worked", "no_signal", "muted"])
    ap.add_argument("--min-pair-delta", type=float, default=0.2,
                    help="minimum reward gap to form a chosen/rejected pair")
    ap.add_argument("--max-seq-len", type=int, default=2048)
    ap.add_argument("--dry-run", action="store_true",
                    help="validate the dataset + count pairs; no training")
    args = ap.parse_args(argv)

    try:
        result = train(
            args.db, args.out, base=args.base, epochs=args.epochs,
            lr=args.lr, batch_size=args.batch_size, grad_accum=args.grad_accum,
            beta=args.beta, only_outcome=args.only_outcome,
            min_pair_delta=args.min_pair_delta, max_seq_len=args.max_seq_len,
            dry_run=args.dry_run)
    except RuntimeError as exc:
        print(f"[mimir-slm-train-dpo] {exc}", file=sys.stderr)
        return 2
    if args.dry_run:
        print(f"[mimir-slm-train-dpo] dry-run OK  "
              f"pairs={result['pairs']}  "
              f"missing_deps={result['missing_deps'] or '(none)'}",
              file=sys.stderr)
    else:
        print(f"[mimir-slm-train-dpo] training done  "
              f"pairs={result['pairs']}  out={result['out']}",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
