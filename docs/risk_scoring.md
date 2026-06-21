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
`composite_risk()`. Offline we have CVSS and the public-exploit flag but not
EPSS or KEV; any component with no signal (EPSS here) is dropped and the
remaining weights are **renormalised**, so partial data still yields a sane
0-100 score. `assess.py --exposure/--business/--kev` feed the exposure, business
and KEV-override inputs; KEV forces critical and a public exploit floors the
band at high.
