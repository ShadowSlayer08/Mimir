"""slm.rl — reinforcement-learning training harness for Mimir SLM.

Phase 24. Group-relative policy optimisation (GRPO) is the right fit:

  * Needs no separate critic/value model (DeepSeek-R1 paper, Shao et al. 2024)
  * Works well with small bases (qwen2.5:3b, phi-3-mini) on a single GPU
  * Reward can be a plain scalar function, not a learned reward model

The data pipeline:

  1. `mimir-slm trace` / curate → the sink captures real decisions.
  2. `mimir-slm reward` → populate the `reward` column per trace (see
     slm.reward).
  3. `mimir-slm distill` → produce a teacher-student JSONL for SFT warm-up.
  4. `mimir-slm rl export <out.jsonl>` → emit GRPO groups:
        {"prompt": ..., "samples": [{"text": ..., "reward": ...}, ...]}
     with the teacher sampling N responses per prompt and this module
     scoring each one via `slm.reward.compute_reward`.
  5. Operator trains locally with the documented GRPO recipe below.

No trainer ships in-tree (same policy as Phase 23). The engine is a
data factory; the trainer is a small external script the operator runs
on whatever GPU they have, with whatever base model they prefer.
"""
from __future__ import annotations

import json
import os
import sqlite3

from . import distill as _distill
from . import reward as _reward


# --------------------------------------------------------------------------- #
# Group builder with reward scoring.
# --------------------------------------------------------------------------- #
def _normalise_group_rewards(samples):
    """Per-group z-score (GRPO's group-relative advantage). Writes
    `advantage` onto every sample in place."""
    rewards = [s["reward"] for s in samples if s.get("reward") is not None]
    if not rewards:
        for s in samples:
            s["advantage"] = 0.0
        return
    mean = sum(rewards) / len(rewards)
    var = sum((r - mean) ** 2 for r in rewards) / len(rewards)
    std = (var ** 0.5) or 1e-8
    for s in samples:
        r = s.get("reward")
        s["advantage"] = round(((r - mean) / std) if r is not None else 0.0, 4)


def _score_sample(sample, prompt_row, *, lessons_db, ledger_db, peer_signal,
                  weights):
    """Score a single sample with slm.reward using a synthetic trace row."""
    tr = {
        "ts": "", "kind": prompt_row.get("kind", ""),
        "role": prompt_row.get("role", "adviser"),
        "prompt": prompt_row.get("prompt", ""),
        "llm_result": sample.get("text", ""),
        "fallback_result": None,
        "used_fallback": False,
        "validator_passed": None,
        "engagement_id": prompt_row.get("engagement_id"),
        "outcome": prompt_row.get("outcome"),
    }
    r, br = _reward.compute_reward(
        tr, lessons_db=lessons_db, ledger_db=ledger_db,
        peer_signal=peer_signal, weights=weights)
    sample["reward"] = r
    sample["reward_breakdown"] = br
    return r


def build_rl_dataset(trace_db, *, lessons_db=None, ledger_db=None,
                     samples_per_prompt=4, only_outcome="worked",
                     peer_signals=None, weights=None, timeout=None):
    """Full GRPO-ready dataset. Yields group dicts:
         {"prompt": str, "role": str, "samples": [{text, reward, advantage}, ...]}

    `peer_signals` is an optional {prompt_hash: ±1} map from
    `slm.bridge.query_peer_batch` (we re-hash each prompt to look up).
    """
    peer_signals = peer_signals or {}
    for group in _distill.build_rl_groups(
            trace_db,
            samples_per_prompt=samples_per_prompt,
            only_outcome=only_outcome,
            timeout=timeout):
        prompt_row = {
            "prompt": group["prompt"], "role": group.get("role"),
            "kind": "", "engagement_id": None, "outcome": only_outcome,
        }
        # Resolve peer signal by prompt hash if available.
        try:
            from . import trace as _trace
            peer = peer_signals.get(_trace._hash(group["prompt"]))
        except Exception:                                          # pragma: no cover
            peer = None
        for sample in group["samples"]:
            _score_sample(sample, prompt_row,
                          lessons_db=lessons_db, ledger_db=ledger_db,
                          peer_signal=peer, weights=weights)
        _normalise_group_rewards(group["samples"])
        yield group


def export_jsonl(trace_db, out_stream, **kwargs):
    n = 0
    for grp in build_rl_dataset(trace_db, **kwargs):
        out_stream.write(json.dumps(grp, ensure_ascii=False) + "\n")
        n += 1
    return n


# --------------------------------------------------------------------------- #
# Recipe printer — the trainer that ships OUTSIDE the repo.
# --------------------------------------------------------------------------- #
GRPO_RECIPE = """
GRPO training recipe — run OUTSIDE the engine, on your GPU host.

Prereqs:
  pip install torch transformers trl datasets peft bitsandbytes accelerate
  # trl >= 0.11 ships GRPOTrainer.

Dataset (produced by this engine):
  mimir-slm rl export train.grpo.jsonl --samples-per-prompt 4 \\
      --only-outcome worked --lessons eng.db --ledger eng.db

Each JSONL row is:
  {"prompt": "...", "role": "...",
   "samples": [{"text":"...", "reward":0.42, "advantage":1.03}, ...]}

Trainer skeleton (save as train_grpo.py and run with accelerate):

  from datasets import load_dataset
  from transformers import AutoTokenizer, AutoModelForCausalLM
  from trl import GRPOConfig, GRPOTrainer
  import json

  BASE = "Qwen/Qwen2.5-3B-Instruct"     # or microsoft/Phi-3-mini-4k-instruct
  tok = AutoTokenizer.from_pretrained(BASE)
  model = AutoModelForCausalLM.from_pretrained(BASE, device_map="auto")

  ds = load_dataset("json", data_files="train.grpo.jsonl")["train"]

  def reward_fn(prompts, completions, **kwargs):
      # Re-derive the per-sample reward from the file row — or recompute
      # by running the engagement signals through slm.reward live.
      return [0.0] * len(completions)   # replace with your lookup

  cfg = GRPOConfig(
      output_dir="out", num_generations=4, max_prompt_length=1024,
      max_completion_length=512, beta=0.04,                 # KL penalty
      learning_rate=5e-6, per_device_train_batch_size=1,
      gradient_accumulation_steps=8, num_train_epochs=1,
  )

  trainer = GRPOTrainer(model=model, processing_class=tok,
                        reward_funcs=[reward_fn], args=cfg,
                        train_dataset=ds)
  trainer.train()
  trainer.save_model("mimir-slm-grpo-lora")

Convert + serve:
  python -m llama_cpp.convert_hf_to_gguf mimir-slm-grpo-lora \\
      --outfile mimir-slm.gguf --outtype q5_k_m

  # Modelfile pulls base + the adapter:
  cat > Modelfile <<'EOF'
  FROM qwen2.5:3b-instruct
  ADAPTER ./mimir-slm.gguf
  EOF
  ollama create mimir-slm:$(date +%Y%m%d) -f Modelfile
  export MIMIR_LLM_PLANNER=mimir-slm:$(date +%Y%m%d)
  export MIMIR_LLM_ADVISER=mimir-slm:$(date +%Y%m%d)
  mimir-cli --from-xml scan.xml --yes --llm   # qualia.decide now routes to the SLM
"""


def recipe():
    return GRPO_RECIPE
