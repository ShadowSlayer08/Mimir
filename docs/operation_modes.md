# Operation Modes

The target-acquisition dashboard (the toolbar in `pentest_console.py`, and the
`--mode` flag in `assess.py`) runs the pipeline in one of two **operation
modes**. A mode tunes only the **Stage-1 enumeration scan** (nmap script set,
timing, host discovery, OS detection) and the operator warning shown — it does
**not** change what happens after the scan.

| Mode | Profile | Scan posture |
|------|---------|--------------|
| **VAPT** | safe (default) | Detection-only enumeration. No brute / dos / exploit categories. Gentle timing (`-T3`). |
| **Red Team** | in-depth | Intrusive **enumeration**: vuln-detection scripts, SMB share/user enumeration, zone transfer, broader probing, faster timing (`-T4`, `-Pn`). Higher detection & account-lockout risk. |

## The boundary (applies to BOTH modes)

This engine is **methodology + staging**, never weaponization (see
`docs/instructions.md`). Therefore:

- **Neither mode auto-exploits.** Both feed the same chain: analysis → ATT&CK
  methodology → attack-path **staging**. Every attack step is executed
  **manually by a human operator** within an authorized engagement.
- **Red Team selects detection/enumeration scripts only.** It never enables
  nmap's `exploit` or `dos` categories. "Higher risk" means *intrusive
  enumeration* (more traffic, vuln probes, possible lockouts) — not the tool
  firing exploits.
- The dashboard's scope gate (`Authorized scope` checkbox / `assess.py` scope
  file + confirmation) must pass before any scan runs.

Profiles live in `profiles.py` (`PROFILES`); edit there to tune a mode's scan.
