# Attack Paths

Attack-path generation + execution logic.

## Path kinds
```yaml
kinds:
  rce:      "Initial Access → RCE → Post-Exploitation"
  lateral:  "Credential reuse / pivot across hosts"
  domain:   "Domain dominance path"
  c2:       "C2 establishment and persistence"
Step model
Each step includes: order, tactic, technique_id, technique, host, basis, payload, command, guidance.
Execution: Paths can be staged and executed directly from the console when operator confirms.
CLI
Bashpython3 attack_path_engine.py scan.xml --execute