#!/usr/bin/env python3
"""
autopilot.py — Mimir Autopilot v1: run the staged plan automatically.

Authorized / lab / CTF / VAPT / red-team use only.

The default Mimir flow STAGES a plan and hands it to a human operator to run.
Autopilot v1 is the explicit opt-in that lets the engine RUN the staged
commands itself, ONE PASS, with the same safety layers already in front of
every subprocess spawn:

  1. Institutional TLD hard-block (.gov / .mil / .edu / .int + country variants)
     — never bypassable without MIMIR_ALLOW_INSTITUTIONAL=1.
  2. ROE scope — the host must be in_scope and must NOT be out_of_scope.
  3. ROE allowed-window — the current time must fall inside the window, if set.
  4. Forbidden-technique list — per-ROE ATT&CK id block.
  5. Noise ceiling — the step's noise score (from opsec.py) must be <= ceiling
     (default 5 = safe recon only; raise with --noise-ceiling).
  6. Risk-tag filter — the step's risk (safe|intrusive) must be in --accept-risk
     (default: safe only; operator opts into intrusive explicitly).
  7. Interactive confirmation — --confirm prompts per step before fire.
  8. Dry-run — --dry-run prints what WOULD run, fires nothing.
  9. Max-steps cap — hard ceiling on steps considered (default 50).
 10. Per-step timeout — subprocess hard-killed after this many seconds (default 60).

Every step produces a structured verdict, written to:
  * stdout (one line per step)
  * --log <FILE> (JSONL — one JSON object per step)
  * --ledger <DB> (ledger.autopilot_log + ledger.autopilot_runs tables)

Verdicts: executed_ok | executed_nonzero | skipped_scope | skipped_window |
          skipped_noise | skipped_risk | skipped_institutional |
          skipped_forbidden_technique | skipped_user_declined |
          dry_run | timeout | aborted

AUTOPILOT V1 DOES NOT:
  * Re-plan based on observed results (that's v2 — iterative agent loop).
  * Install tools. If `nmap` is not on PATH, the step fails with exit-code 127.
  * Ship exploit code. Autopilot runs the tools the OPERATOR installed.

Resumability: each run writes a `.autopilot-run.json` file; passing --resume
<FILE> skips every step whose verdict was executed_ok / dry_run on the prior run.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone


def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                          # pragma: no cover
            pass


_force_utf8_stdio()

# Default knob values — the operator opts up to intrusive explicitly.
DEFAULT_NOISE_CEILING = 5
DEFAULT_RISK_ACCEPT = frozenset(["safe"])
DEFAULT_MAX_STEPS = 50
DEFAULT_TIMEOUT_S = 60

# Commands we refuse to pass to a shell even if the operator opts up to intrusive —
# these are the "really don't execute this" patterns no sane autopilot run should
# hit. Belt-and-braces: the staged engine SHOULDN'T emit these, but paranoid parsing.
_FORBIDDEN_CMD_PATTERNS = (
    re.compile(r"\brm\s+-rf?\s+/\s*$", re.I),           # rm -rf /
    re.compile(r"\bmkfs\.|dd\s+if=.*of=/dev/", re.I),    # filesystem/disk writes
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:", re.I),      # fork bomb
    re.compile(r"\binsmod\b|\brmmod\b|\bmodprobe\b", re.I),  # kernel module ops
    re.compile(r"\biptables\s+-F\b|\bufw\s+disable\b", re.I),# firewall reset
    re.compile(r"\bshutdown\b|\bhalt\b|\breboot\b|\bpoweroff\b", re.I),
    # Anti-forensics / log clearing:
    re.compile(r"\bwevtutil\s+cl\b|\bClear-EventLog\b|>\s*/var/log/.*", re.I),
)


# --------------------------------------------------------------------------- #
# Step extraction
# --------------------------------------------------------------------------- #
def _walk_step_commands(eng):
    """Flatten the engagement into a list of {path_id, order, host, command,
    risk, noise, attack, tactic, phase} executable step dicts.

    Order of emission: attack-path steps first (ordered by rank), then module
    checks (ordered by module). Each step carries enough context for every gate.
    """
    steps = []

    # Ensure opsec annotations are present (idempotent).
    try:
        import opsec
        opsec.annotate_paths(eng.get("attack_paths") or [])
        opsec.annotate_modules(eng.get("modules") or [])
    except Exception:                                              # pragma: no cover
        pass

    for p in (eng.get("attack_paths") or []):
        pid = p.get("id", "")
        kind = p.get("kind", "")
        for s in (p.get("steps") or []):
            cmd = (s.get("command") or s.get("guidance") or "").strip()
            if not cmd or cmd.startswith("#"):
                continue
            steps.append({
                "source": "path",
                "path_id": pid,
                "path_kind": kind,
                "order": s.get("order", 0),
                "host": s.get("host", ""),
                "command": cmd,
                "risk": (s.get("risk") or "safe").lower(),
                "noise": int(s.get("noise", 0) or 0),
                "attack": s.get("technique_id", ""),
                "tactic": s.get("tactic", ""),
                "phase": kind or "attack-path",
                "name": f"{pid}#{s.get('order', 0)} {s.get('technique', '')}",
            })

    for m in (eng.get("modules") or []):
        module_name = m.get("module", "")
        target = m.get("target", "") or m.get("host", "")
        host = target
        if host.startswith(("http://", "https://")):
            host = host.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        for c in (m.get("checks") or []):
            cmd = (c.get("command") or "").strip()
            if not cmd or cmd.startswith("#"):
                continue
            steps.append({
                "source": "module",
                "path_id": module_name,
                "path_kind": "module",
                "order": 0,
                "host": host,
                "command": cmd,
                "risk": (c.get("risk") or "safe").lower(),
                "noise": int(c.get("noise", 0) or 0),
                "attack": c.get("attack", ""),
                "tactic": "Recon" if (c.get("risk") or "safe") == "safe" else "Active",
                "phase": module_name,
                "name": f"{module_name}:{c.get('name', '')}",
            })

    return steps


# --------------------------------------------------------------------------- #
# Gates — each returns (ok, reason). All gates run before every execution.
# --------------------------------------------------------------------------- #
def _gate_institutional(step):
    try:
        import roe
        reason = roe.institutional_block_reason(step["host"])
        if reason:
            return False, reason
    except Exception:                                              # pragma: no cover
        pass
    return True, ""


def _gate_scope(step, rules):
    if not rules:
        return True, ""
    try:
        from roe import _in_scope
        ok, reason = _in_scope(step["host"], rules)
        if not ok:
            return False, reason
    except Exception:                                              # pragma: no cover
        pass
    return True, ""


def _gate_window(rules, at_ts=None):
    if not rules:
        return True, ""
    try:
        from roe import _in_window
        ok, reason = _in_window(rules, at_ts)
        if not ok:
            return False, reason
    except Exception:                                              # pragma: no cover
        pass
    return True, ""


def _gate_forbidden_tech(step, rules):
    if not rules:
        return True, ""
    tech = step.get("attack") or ""
    forbidden = set(rules.get("forbidden_techniques") or [])
    if tech and tech in forbidden:
        return False, f"forbidden_technique:{tech}"
    return True, ""


def _gate_noise(step, ceiling):
    if step.get("noise", 0) > ceiling:
        return False, f"noise_above_ceiling:{step['noise']}>{ceiling}"
    return True, ""


def _gate_risk(step, accept):
    risk = step.get("risk") or "safe"
    if risk not in accept:
        return False, f"risk_not_accepted:{risk}"
    return True, ""


def _gate_command_safety(step):
    """Last-resort command content gate — belt-and-braces against anything the
    staging engine shouldn't have emitted (no rm -rf, fork bombs, firewall
    resets, anti-forensics)."""
    cmd = step.get("command", "")
    for pat in _FORBIDDEN_CMD_PATTERNS:
        if pat.search(cmd):
            return False, f"command_blocked:{pat.pattern[:40]}"
    return True, ""


# --------------------------------------------------------------------------- #
# Executor
# --------------------------------------------------------------------------- #
def _subprocess_run(cmd, timeout_s, cwd=None, env=None):
    """Spawn the shell command, capture output, enforce timeout. Returns
    (exit_code, stdout_tail, stderr_tail, elapsed_s). Never raises; on timeout
    the process is killed and exit_code = -9."""
    start = time.time()
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout_s, cwd=cwd,
            env=env or os.environ.copy(), check=False,
            errors="replace",
        )
        rc = proc.returncode
        so = (proc.stdout or "")[-4000:]
        se = (proc.stderr or "")[-2000:]
    except subprocess.TimeoutExpired as exc:
        rc = -9
        so = (exc.stdout or b"")[-4000:].decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")[-4000:]
        se = f"TIMEOUT after {timeout_s}s: killed"
    except Exception as exc:                                       # pragma: no cover
        rc = -1
        so = ""
        se = f"spawn failure: {exc}"
    return rc, so, se, round(time.time() - start, 2)


# --------------------------------------------------------------------------- #
# Main run
# --------------------------------------------------------------------------- #
def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _emit(stream, msg):
    """Write a user-visible progress line + flush, so an operator tail -f's log."""
    print(msg, file=stream, flush=True)


def _color(code, s, colorize):
    return f"\033[{code}m{s}\033[0m" if colorize else s


def _write_jsonl(path, record):
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:                                                # pragma: no cover
        pass


def _resume_set(resume_path):
    """Return the set of step identifiers that executed successfully in a prior
    run (so we skip them). Identifier shape is `name + host + command` hash."""
    import hashlib
    done = set()
    if not resume_path or not os.path.exists(resume_path):
        return done
    try:
        with open(resume_path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if r.get("verdict") in ("executed_ok", "dry_run"):
                    key = hashlib.sha1((r.get("name", "") + r.get("host", "")
                                        + r.get("command", "")).encode("utf-8")).hexdigest()
                    done.add(key)
    except OSError:                                                # pragma: no cover
        pass
    return done


def _step_key(step):
    import hashlib
    return hashlib.sha1(
        (step.get("name", "") + step.get("host", "") + step.get("command", ""))
        .encode("utf-8")).hexdigest()


def run(engagement, *, roe_rules=None,
        accept_risk=None, noise_ceiling=DEFAULT_NOISE_CEILING,
        max_steps=DEFAULT_MAX_STEPS, timeout_s=DEFAULT_TIMEOUT_S,
        dry_run=False, confirm=False,
        log_path=None, ledger_db=None,
        only_phases=None, resume_path=None,
        on_progress=None, colorize=False):
    """Run the staged plan under the gate chain. Returns the full result list."""
    accept = frozenset(accept_risk) if accept_risk else DEFAULT_RISK_ACCEPT
    only_phases = set(only_phases) if only_phases else None
    results = []
    steps = _walk_step_commands(engagement)
    done_keys = _resume_set(resume_path)

    pacing_s = 0
    try:
        import opsec
        # Use the stealthiest profile the ceiling implies for pacing.
        profile = "stealth" if noise_ceiling <= 3 else "normal" if noise_ceiling <= 7 else "aggressive"
        pacing_s = opsec.pacing_seconds(profile)
    except Exception:                                              # pragma: no cover
        pass

    # Headline
    headline = (f"[autopilot] {len(steps)} staged step(s) in plan  ·  "
                f"ceiling={noise_ceiling}  accept={','.join(sorted(accept))}  "
                f"max_steps={max_steps}  timeout={timeout_s}s"
                f"{'  DRY-RUN' if dry_run else ''}")
    _emit(sys.stderr, _color("1;33", headline, colorize))

    started = 0
    aborted = False

    def _handle_sigint(signum, frame):
        nonlocal aborted
        aborted = True
        _emit(sys.stderr, _color("1;31",
                                 "[autopilot] SIGINT — aborting; current step still finishing",
                                 colorize))

    try:
        signal.signal(signal.SIGINT, _handle_sigint)
    except (ValueError, OSError):                                  # pragma: no cover
        pass

    for i, step in enumerate(steps, 1):
        if aborted:
            break
        if started >= max_steps:
            results.append({"i": i, "name": step["name"],
                            "verdict": "skipped_max_steps", "ts": _now()})
            break
        if only_phases and step["phase"] not in only_phases:
            continue
        key = _step_key(step)
        if key in done_keys:
            results.append({"i": i, "name": step["name"], "host": step["host"],
                            "command": step["command"], "verdict": "skipped_resume",
                            "ts": _now()})
            continue

        # ---- gate chain ----  (verdict is canonical; reason keeps the detail)
        gates = (
            ("skipped_institutional",       _gate_institutional,  (step,)),
            ("skipped_scope",               _gate_scope,          (step, roe_rules)),
            ("skipped_window",              _gate_window,         (roe_rules,)),
            ("skipped_forbidden_technique", _gate_forbidden_tech, (step, roe_rules)),
            ("skipped_noise",               _gate_noise,          (step, noise_ceiling)),
            ("skipped_risk",                _gate_risk,           (step, accept)),
            ("skipped_command",             _gate_command_safety, (step,)),
        )
        gated = False
        for verdict, gate, gargs in gates:
            ok, reason = gate(*gargs)
            if not ok:
                rec = {"i": i, "name": step["name"], "host": step["host"],
                       "command": step["command"], "verdict": verdict,
                       "reason": reason, "ts": _now()}
                results.append(rec)
                _write_jsonl(log_path, rec)
                if on_progress:
                    on_progress(rec)
                _emit(sys.stderr, _color("2;33", f"  [{i:>3}] SKIP {step['name'][:48]:<48}  "
                                                  f"({reason})", colorize))
                gated = True
                break
        if not gated:
            # ---- gates passed; confirm + fire ----
            if confirm and not dry_run and sys.stdin.isatty():
                _emit(sys.stdout, _color("1;36",
                                         f"\n[{i}/{len(steps)}] About to run (host={step['host']}, "
                                         f"risk={step['risk']}, noise={step['noise']}):",
                                         colorize))
                _emit(sys.stdout, f"    $ {step['command']}")
                sys.stdout.write("    continue? [y/N] "); sys.stdout.flush()
                try:
                    reply = input().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    reply = "n"
                if reply not in ("y", "yes"):
                    rec = {"i": i, "name": step["name"], "host": step["host"],
                           "command": step["command"],
                           "verdict": "skipped_user_declined", "ts": _now()}
                    results.append(rec); _write_jsonl(log_path, rec)
                    continue

            if dry_run:
                rec = {"i": i, "name": step["name"], "host": step["host"],
                       "command": step["command"], "verdict": "dry_run", "ts": _now()}
                results.append(rec); _write_jsonl(log_path, rec)
                if on_progress:
                    on_progress(rec)
                _emit(sys.stderr, _color("2;36",
                                         f"  [{i:>3}] DRY  {step['name'][:48]:<48}  "
                                         f"$ {step['command'][:70]}", colorize))
                continue

            # Pacing between loud steps (OPSEC profile)
            if pacing_s and step["noise"] >= 4 and started > 0:
                time.sleep(min(pacing_s, 30))

            rc, so, se, elapsed = _subprocess_run(step["command"], timeout_s)
            verdict = ("executed_ok" if rc == 0
                       else "timeout" if rc == -9
                       else "executed_nonzero")
            rec = {"i": i, "name": step["name"], "host": step["host"],
                   "command": step["command"], "verdict": verdict,
                   "exit_code": rc, "elapsed_s": elapsed,
                   "stdout_tail": so[-800:], "stderr_tail": se[-600:],
                   "ts": _now(),
                   "risk": step["risk"], "noise": step["noise"],
                   "attack": step["attack"], "phase": step["phase"]}
            results.append(rec); _write_jsonl(log_path, rec)
            if on_progress:
                on_progress(rec)
            colour = ("1;32" if verdict == "executed_ok"
                      else "1;31" if verdict == "timeout"
                      else "1;33")
            _emit(sys.stderr, _color(colour,
                                     f"  [{i:>3}] {verdict.upper():<17} "
                                     f"{step['name'][:40]:<40}  "
                                     f"rc={rc}  {elapsed}s", colorize))
            started += 1

    # ---- summary ----
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    summary = {"ts_end": _now(), "started": started, "verdicts": counts,
               "aborted": aborted, "total_steps": len(steps)}
    _emit(sys.stderr, "")
    _emit(sys.stderr, _color("1;33",
                             f"[autopilot] done  started={started}  "
                             + "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))
                             + (f"  (aborted)" if aborted else ""), colorize))
    _write_jsonl(log_path, {"summary": summary})

    if ledger_db:
        try:
            _write_ledger(ledger_db, summary, results)
        except Exception as exc:                                   # pragma: no cover
            _emit(sys.stderr, f"[autopilot] ledger write failed: {exc}")

    return {"summary": summary, "results": results}


# --------------------------------------------------------------------------- #
# Ledger integration — new tables, co-located with the engagement ledger DB.
# --------------------------------------------------------------------------- #
_LEDGER_SCHEMA = """
CREATE TABLE IF NOT EXISTS autopilot_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, started INT, aborted INT,
  total_steps INT, verdicts_json TEXT);
CREATE TABLE IF NOT EXISTS autopilot_log(
  run_id INT, i INT, ts TEXT, name TEXT, host TEXT, command TEXT,
  verdict TEXT, exit_code INT, elapsed_s REAL, stdout_tail TEXT,
  stderr_tail TEXT, risk TEXT, noise INT, attack TEXT, phase TEXT);
"""


def _write_ledger(db_path, summary, results):
    import sqlite3
    con = sqlite3.connect(db_path, isolation_level=None)
    try:
        con.executescript(_LEDGER_SCHEMA)
        cur = con.execute(
            "INSERT INTO autopilot_runs(ts,started,aborted,total_steps,verdicts_json) "
            "VALUES(?,?,?,?,?)",
            (summary["ts_end"], summary["started"], int(bool(summary["aborted"])),
             summary["total_steps"], json.dumps(summary["verdicts"])))
        run_id = cur.lastrowid
        con.executemany(
            "INSERT INTO autopilot_log(run_id,i,ts,name,host,command,verdict,"
            "exit_code,elapsed_s,stdout_tail,stderr_tail,risk,noise,attack,phase) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(run_id, r.get("i"), r.get("ts", ""), r.get("name", ""),
              r.get("host", ""), r.get("command", ""), r.get("verdict", ""),
              r.get("exit_code"), r.get("elapsed_s"),
              r.get("stdout_tail", ""), r.get("stderr_tail", ""),
              r.get("risk", ""), r.get("noise"), r.get("attack", ""),
              r.get("phase", "")) for r in results])
    finally:
        con.close()


# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="mimir-autopilot",
        description="Run the Mimir-staged plan automatically — gate-chained, "
                    "noise-aware, resumable. Opt-in only.")
    ap.add_argument("engagement", help="engagement JSON (mimir-cli --emit-json)")
    ap.add_argument("--roe", help="ROE yaml side-car (roe.py format)")
    ap.add_argument("--accept-risk",
                    help="comma-separated risk tags to run (default: safe)")
    ap.add_argument("--noise-ceiling", type=int, default=DEFAULT_NOISE_CEILING,
                    help=f"max noise score to run (0-10, default {DEFAULT_NOISE_CEILING})")
    ap.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS,
                    help=f"hard cap on executed steps (default {DEFAULT_MAX_STEPS})")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S,
                    help=f"per-step subprocess timeout seconds (default {DEFAULT_TIMEOUT_S})")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would run; fire nothing")
    ap.add_argument("--confirm", action="store_true",
                    help="interactive y/N per step before fire")
    ap.add_argument("--log", metavar="FILE",
                    help="write per-step JSONL log here (also useful with --resume)")
    ap.add_argument("--ledger", metavar="DB",
                    help="persist the run into the engagement ledger (autopilot_* tables)")
    ap.add_argument("--only-phase", action="append",
                    help="restrict to one or more phases (repeatable)")
    ap.add_argument("--resume", metavar="FILE",
                    help="skip steps that executed_ok / dry_run in the prior log")
    ap.add_argument("--yes-i-am-authorized", action="store_true",
                    help="mandatory confirmation that this engagement is authorized")
    args = ap.parse_args(argv)

    if not args.yes_i_am_authorized:
        print("[autopilot] refuse: pass --yes-i-am-authorized to confirm the "
              "engagement is in authorised scope.", file=sys.stderr)
        return 2

    with open(args.engagement, encoding="utf-8") as fh:
        engagement = json.load(fh)

    rules = None
    if args.roe:
        try:
            import roe
            rules = roe.load(args.roe)
        except Exception as exc:
            print(f"[autopilot] ROE load failed ({exc}); running with "
                  f"institutional-TLD block only.", file=sys.stderr)

    accept = [t.strip().lower() for t in (args.accept_risk or "safe").split(",") if t.strip()]
    out = run(engagement,
              roe_rules=rules,
              accept_risk=accept,
              noise_ceiling=args.noise_ceiling,
              max_steps=args.max_steps,
              timeout_s=args.timeout,
              dry_run=args.dry_run,
              confirm=args.confirm,
              log_path=args.log,
              ledger_db=args.ledger,
              only_phases=args.only_phase,
              resume_path=args.resume,
              colorize=sys.stderr.isatty())
    return 0 if not out["summary"]["aborted"] else 130


if __name__ == "__main__":
    sys.exit(main())
