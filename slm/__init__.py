"""slm — Mimir Specialised Language Model groundwork.

Phase 23 scope — the TRAINING INFRASTRUCTURE around specialising a small
local model on Mimir's own curated decision traces. The first actual model
ships only after a corpus of curated, high-quality traces exists; this
phase lands the data pipeline that MAKES that corpus possible.

Components:
  * `slm.trace`          — append-only SQLite log of every `qualia.decide`
                            / `qualia.prose` call when the opt-in env var
                            `MIMIR_SLM_TRACE_DB` is set. Zero cost when
                            unset. Never raises. Redacts secret-shaped
                            tokens via `vault.redact` before persistence.
  * `slm.export`         — walks the trace sink + `lessons.py` ledger and
                            emits curated training JSONL for a QLoRA run.
  * `mimir_slm.py`       — operator CLI: `mimir-slm status / trace /
                            export / curate / train / eval / promote`.

Boundary:
  * The sink is opt-in. Without `MIMIR_SLM_TRACE_DB`, no tracing happens
    and the module adds no runtime cost.
  * Cloud models stay excluded. Fine-tuning is local-only and operator-
    driven; the CLI's `train` subcommand prints the recipe and prereqs
    rather than shipping a trainer in-tree.
  * Trace rows are secondary-scrubbed with `vault.redact` before write.
    Primary rule remains "don't put the plaintext in a logged string in
    the first place" — the scrubber is belt-and-braces.
"""
from __future__ import annotations

from . import trace  # noqa: F401

__all__ = ["trace"]
