# Correlation Engine

Correlates findings into meaningful risks (capabilities) and feeds attack-path
generation. Implemented in `attack_path_engine.py`.

## From findings to capabilities
Each finding is mapped to a *capability* — what it lets an attacker do — plus an
ATT&CK technique and a confidence. The current mapping (in code; a candidate to
externalise into this doc later):

```yaml
capabilities:
  rce_system:    {trigger: "ms17-010 / ms08-067 / sambacry", attck: T1190, confidence: high}
  rce:           {trigger: "exploitable CVE / unauth redis", attck: T1190, confidence: medium}
  cred_exposure: {trigger: "heartbleed / cleartext / default creds", attck: "T1552/T1040", confidence: medium-high}
  data_access:   {trigger: "anonymous ftp / exposed database", attck: "T1078/T1213", confidence: medium}
  remote_service:{trigger: "rdp / smb / ssh / db login surface", attck: "T1021.x", confidence: n/a}
```

## From capabilities to paths
Capabilities are chained across hosts (see `attack_paths.md`):
- an RCE capability becomes a single-host foothold path;
- a credential-exposure on host A plus a remote-service on host B becomes a
  lateral path (A → B), flagged speculative until reuse is confirmed;
- a path that lands on a domain controller is extended to a domain-compromise
  path.

## Confidence
`high` = confirmed by a vuln scan (state VULNERABLE); `medium` = version/exposure
inference; `low` = speculative cross-host assumption. Confidence never silently
upgrades.
