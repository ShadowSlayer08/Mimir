# Contributing to Vantage

Thanks for considering a contribution. Vantage is a knowledge-driven pentest
orchestration engine for authorized use only; please read
[`docs/instructions.md`](docs/instructions.md) (the constitution) first — the
rules there decide what's accepted and what's rejected.

## Hard rules (non-negotiable)

- **No exploit payloads, exploit runners, C2, or auto-exploitation.** Vantage
  stages methodology; the human operator executes. PRs that add any of these
  are closed, not merged.
- **ATT&CK is the shared vocabulary.** Every check or path step carries a
  valid technique id (`T####[.###]`). AppSec checks additionally carry an
  OWASP (WSTG / API Top 10 / MASVS) reference and a CWE id.
- **Prefer a doc edit over a code change.** Methodology lives in `docs/*.md`
  as fenced YAML; the Python is a generic loader.
- **Measured, not asserted.** New capability lands with a scenario that will
  fail if the capability regresses (`vantage-bench`).

## Before you open a PR

```bash
python run_tests.py        # 193/193 must pass
python validate_kb.py      # KB must be clean
python -m evals.bench      # all scenarios must stay at 100 % recall
```

If you're adding a new assessment module:

1. Write the methodology in `docs/modules/<name>.md` (or
   `docs/appsec/<name>.md` for target-driven AppSec). Fenced ```yaml block
   with `module:`, `scope:`, `matches:` and a `checks:` list — every check
   needs `attack`, `risk` (`safe`|`intrusive`), and `name`.
2. Add a Python module under `modules/` using an existing module as a
   template; keep the built-in `BUILTIN_CHECKS` list in sync with the doc so
   the engine runs even if `docs/` is absent.
3. Add an eval scenario asserting the new coverage under
   `evals/scenarios/<name>.yml` — at least one positive assertion + one
   negative-space assertion.
4. Run `python validate_kb.py && python run_tests.py && python -m evals.bench`.

## Style

- CLI-first. Every capability must run headless (`--no-gui` / `--selftest`).
- Windows + Python 3.11: force UTF-8 stdio (see `nmap_analyzer._force_utf8_stdio`).
- Avoid Python 3.12-only f-string syntax (no backslash inside `{...}`).
- `black`-compatible formatting; no linter hard-required but keep it clean.
- Don't commit secrets, engagement data, or client-identifiable fixtures.

## Reporting a bug

Use GitHub issues. Include: Vantage version (`vantage --version`), platform,
Python version, the command you ran, the output, and (if relevant) the
`nmap` XML / evidence fixture that reproduces it — scrubbed of real client
data.

## Reporting a security issue

**Do not open a public issue for security.** See [`SECURITY.md`](SECURITY.md).

## License

Contributions are licensed under AGPL-3.0-or-later (see
[`LICENSE`](LICENSE)). By submitting a PR you agree your contribution is
offered under that license.
