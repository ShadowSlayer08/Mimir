"""slm.distill — teacher-student dataset builder for Mimir SLM training.

Phase 24. Two uses:

  1. Baseline distillation. Mimir uses a BIG local model (qwen2.5:7b,
     hauhaucs-cybersec-27b) as the teacher; we re-ask the teacher every
     stored prompt and emit rows `{prompt, teacher, student, reward}`
     ready for GRPO / DPO / SFT-with-reward training of the small SLM
     (qwen2.5:3b / phi-3-mini) student.

  2. Cross-SLM distillation. Crucible's SLM acts as a *peer* teacher via
     `slm.bridge.query_peer`. Its agreement/disagreement is folded into
     the reward (`slm.reward.compute_reward(..., peer_signal=...)`).

Both stay inside the existing airgap-safe stack: `llm.generate_json`
hits only the local Ollama daemon; cloud models remain excluded unless
the operator sets `MIMIR_LLM_ALLOW_CLOUD=1`.

The actual trainer is NOT shipped in-tree (same policy as Phase 23 train
placeholder). We ship the dataset builder so an operator can run
`mimir-slm distill train.jsonl` locally, then feed the JSONL to a
QLoRA/GRPO script of their choice.
"""
from __future__ import annotations

import json
import os
import sqlite3

try:
    import llm as _llm
except Exception:                                                  # pragma: no cover
    _llm = None


# --------------------------------------------------------------------------- #
# Teacher selection
# --------------------------------------------------------------------------- #
def pick_teacher_model(role="adviser"):
    """Return the strongest local model available for this role, or None."""
    if _llm is None:
        return None
    try:
        picks = _llm.info().get("picks") or {}
    except Exception:                                              # pragma: no cover
        return None
    return picks.get(role) or picks.get("adviser") or picks.get("planner")


def ask_teacher(prompt, role="adviser", timeout=None, system=None):
    """Re-ask the teacher model. Returns the raw text response, or ""
    when offline / errored."""
    if _llm is None or not _llm.available():
        return ""
    try:
        text = _llm.generate(prompt, role=role, system=system,
                             model=pick_teacher_model(role),
                             timeout=timeout)
        return (text or "").strip()
    except Exception:                                              # pragma: no cover
        return ""


# --------------------------------------------------------------------------- #
# Dataset builders
# --------------------------------------------------------------------------- #
def build_distillation_rows(trace_db, *, only_outcome="worked",
                            include_teacher=True, timeout=None):
    """Walk the trace DB and yield distillation rows:
      {
        "prompt":          str,
        "student":         str (the stored llm_result or fallback_result),
        "teacher":         str (freshly asked; empty if offline / disabled),
        "reward":          float or None (if already scored),
        "role":            str, "kind": str,
        "outcome":         "worked" / "no_signal" / "muted" / None,
        "source":          "self-distill" | "peer-import",
      }

    `only_outcome` filters the student set. Peer-imported rows (kind
    starting with `peer:`) are tagged source="peer-import" and included
    only when their outcome matches, same rule.
    """
    if not os.path.exists(trace_db):
        return
    con = sqlite3.connect(trace_db, isolation_level=None)
    try:
        cols = {r[1] for r in con.execute(
            "PRAGMA table_info(qualia_trace)").fetchall()}
        has_reward = "reward" in cols
        q = ("SELECT prompt, llm_result, fallback_result, role, kind, outcome"
             + (", reward" if has_reward else "") +
             " FROM qualia_trace WHERE prompt IS NOT NULL")
        params = []
        if only_outcome:
            q += " AND outcome=?"
            params.append(only_outcome)
        rows = con.execute(q, params).fetchall()
    finally:
        con.close()

    for row in rows:
        prompt, llm_r, fb_r, role, kind, outcome = row[:6]
        reward = row[6] if has_reward and len(row) > 6 else None
        student = llm_r if llm_r is not None else fb_r
        if not student:
            continue
        teacher = ask_teacher(prompt, role=role or "adviser",
                              timeout=timeout) if include_teacher else ""
        source = "peer-import" if (kind or "").startswith("peer:") else "self-distill"
        yield {
            "prompt": prompt, "student": student, "teacher": teacher,
            "reward": reward, "role": role, "kind": kind,
            "outcome": outcome, "source": source,
        }


def export_jsonl(trace_db, out_stream, *, only_outcome="worked",
                 include_teacher=True, timeout=None):
    """Write distillation rows as JSONL. Returns the number written."""
    n = 0
    for row in build_distillation_rows(
            trace_db, only_outcome=only_outcome,
            include_teacher=include_teacher, timeout=timeout):
        out_stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        n += 1
    return n


# --------------------------------------------------------------------------- #
# Group-relative samples — RL training needs multiple responses per prompt.
# --------------------------------------------------------------------------- #
def build_rl_groups(trace_db, *, samples_per_prompt=4, only_outcome="worked",
                    timeout=None):
    """For each curated prompt, sample N responses from the live teacher so
    GRPO (group-relative policy optimisation) has a cohort to rank.

    Returns a generator of:
      {"prompt": p, "samples": [{"text": r, "reward": None}, ...]}

    Reward population happens later (either via `slm.reward` once more
    traces accumulate, or via a reward model operator plugs in). This
    function just creates the sampling scaffold; it's the piece a QLoRA
    trainer wraps.
    """
    if not os.path.exists(trace_db) or _llm is None:
        return
    con = sqlite3.connect(trace_db, isolation_level=None)
    try:
        q = ("SELECT DISTINCT prompt, role FROM qualia_trace WHERE prompt IS NOT NULL")
        params = []
        if only_outcome:
            q += " AND outcome=?"
            params.append(only_outcome)
        rows = con.execute(q, params).fetchall()
    finally:
        con.close()

    for prompt, role in rows:
        samples = []
        if _llm.available():
            seen = set()
            tries = 0
            while len(samples) < samples_per_prompt and tries < samples_per_prompt * 3:
                tries += 1
                try:
                    text = _llm.generate(
                        prompt, role=role or "adviser",
                        model=pick_teacher_model(role or "adviser"),
                        timeout=timeout,
                        options={"temperature": 0.9, "top_p": 0.95})
                except Exception:                                  # pragma: no cover
                    break
                text = (text or "").strip()
                if text and text not in seen:
                    seen.add(text)
                    samples.append({"text": text, "reward": None})
        if not samples:
            # Offline fallback: at least one "placeholder" sample so trainers
            # can still iterate schema without a live LLM.
            samples = [{"text": "(offline — no sample)", "reward": None}]
        yield {"prompt": prompt, "role": role, "samples": samples}
