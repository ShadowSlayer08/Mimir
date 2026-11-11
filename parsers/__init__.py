"""parsers — tool-output parsers for Autopilot v2's observe step.

Each parser extracts structured intel (hosts, services, findings, credentials)
from a tool's captured stdout + stderr tails. The Autopilot v2 loop calls
`parsers.dispatch(command, stdout, stderr, exit_code)` after every executed
step, then merges the returned `ParseResult` back into the engagement JSON so
the next iteration can plan with fresh knowledge.

Design contract — every parser:
  * is pure and side-effect-free (no filesystem writes, no network);
  * accepts `(stdout: str, stderr: str, exit_code: int)` and returns a
    `ParseResult` populated with whatever it could extract;
  * never raises on malformed input (regressions here would brick the loop) —
    it returns an empty ParseResult instead.

Dispatch is by command prefix. Add new parsers to _ROUTES and the registry
below picks them up without further wiring.
"""
from __future__ import annotations

from .base import ParseResult
from . import nmap as _nmap
from . import nuclei as _nuclei
from . import generic as _generic


_ROUTES = (
    (("nmap",),         _nmap.parse),
    (("nuclei",),       _nuclei.parse),
    # add more here: (("httpx",), _httpx.parse), (("subfinder",), ...), ...
)


def dispatch(command, stdout, stderr="", exit_code=0):
    """Route the command to its dedicated parser; fall back to the generic
    regex parser. Returns a ParseResult (empty on parser failure)."""
    cmd = (command or "").strip().lower()
    for prefixes, fn in _ROUTES:
        for p in prefixes:
            if cmd.startswith(p):
                try:
                    return fn(stdout or "", stderr or "", int(exit_code or 0))
                except Exception:                                  # pragma: no cover
                    return ParseResult()
    try:
        return _generic.parse(stdout or "", stderr or "", int(exit_code or 0))
    except Exception:                                              # pragma: no cover
        return ParseResult()


__all__ = ["ParseResult", "dispatch"]
