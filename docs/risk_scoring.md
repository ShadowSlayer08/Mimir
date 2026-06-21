# Risk Scoring

Composite model: **CVSS + EPSS + Exposure + Business Impact**, normalised to
0-100. EPSS and exposure are weighted heavily because most CVEs are never
exploited; CISA KEV membership is a hard override to critical.

```yaml
risk:
  # component weights (must sum to 1.0); each component is normalised to 0-1
  weights:
    cvss:     0.30      # CVSS base score / 10
    epss:     0.30      # EPSS exploit-probability (0-1)
    exposure: 0.25      # 1.0 internet-facing, 0.5 internal-segment, 0.2 isolated
    business: 0.15      # asset criticality (0-1)
  # severity bands applied to the 0-100 composite
  bands:
    critical: 80
    high:     60
    medium:   35
    low:      1
  # hard overrides (bypass the math)
  overrides:
    kev: critical            # CISA Known Exploited Vulnerabilities -> critical
    public_exploit: high     # vulners is_exploit=true -> at least high
  # fallbacks when not provided per-asset
  default_exposure: 0.5
  default_business: 0.5
```

The composite is wired into `nmap_analyzer` for CVE (vulners) findings via
`composite_risk()`. Any component with no signal is dropped and the remaining
weights are **renormalised**, so partial data still yields a sane 0-100 score.
KEV forces critical; a public exploit floors the band at high. exposure/business
are clamped to 0-1.

**Live enrichment (`assess.py --enrich`).** Pulls the CISA-KEV catalogue and
FIRST-EPSS scores from their public feeds (no target is contacted), cached under
the app data dir with a 24h TTL and an atomic, offline-safe write. `--offline`
uses the cache only (and implies `--enrich`); a non-empty stale cache is
preferred over no data. Each finding's EPSS is the **max EPSS over its CVEs**,
feeding the `epss` component, and any KEV CVE forces that finding to critical —
so scoring reflects what is *actually* exploited in the wild, not just CVSS.

**Per-asset risk (`assess.py --assets assets.yaml`).** A YAML/JSON map of
`host -> {exposure, business}` (level names — internet/internal/isolated,
low/medium/high/critical — or raw 0-1 floats, clamped) overrides the global
`--exposure/--business` per host. `--kev <file>` still works as a manual override.
