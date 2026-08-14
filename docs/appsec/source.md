# Source / Supply-Chain Module

**AppSec pillar — target-driven.** Assesses a source target (a repository path or
URL): SAST, secret scanning, SCA / SBOM, IaC and CI/CD review. Checks are ATT&CK +
CWE-mapped with a `safe|intrusive` risk tag (static review is safe). The engine runs
nothing and never exfiltrates code.

Targets come from `assess --source <path|repo-url>`. Tooling: semgrep, gitleaks,
trufflehog, grype, osv-scanner, dependency-check, syft, checkov, trivy,
bandit/gosec/brakeman/retire.js, cosign.

**Boundary:** methodology + staging only. **Cross-layer:** supply-chain findings
(T1195) feed directly into the CI/CD and cloud attack surface.

```yaml
module: source
title: Source / Supply Chain
scope: target
matches: [source, code, repo, sast, sca]
summary: "Source code and supply-chain review."
techniques_extra: []
checks:
  - {name: Secret & key scan, attack: T1552.001, owasp: "", cwe: CWE-798, risk: safe, when: always,
     command: "gitleaks detect --source {path}; trufflehog filesystem {path} --only-verified",
     purpose: "Find hardcoded secrets across the tree and git history."}
  - {name: SAST code weaknesses, attack: T1190, owasp: "", cwe: CWE-707, risk: safe, when: always,
     command: "semgrep --config auto {path}   # + language linters: bandit / gosec / brakeman",
     purpose: "Find injection, authz and crypto bugs in source."}
  - {name: Dependency CVEs (SCA), attack: T1195.001, owasp: "", cwe: CWE-1104, risk: safe, when: always,
     command: "grype dir:{path}   # or: osv-scanner -r {path}; dependency-check",
     purpose: "Flag vulnerable third-party dependencies."}
  - {name: SBOM generation, attack: T1195, owasp: "", cwe: CWE-1104, risk: safe, when: always,
     command: "syft {path} -o cyclonedx-json > sbom.json",
     purpose: "Produce a software bill of materials for the component inventory."}
  - {name: Dependency confusion / typosquat, attack: T1195.002, owasp: "", cwe: CWE-1357, risk: safe, when: always,
     command: "# check internal package names claimable on public registries; lockfile integrity; typosquats",
     purpose: "Test for dependency-confusion and typosquat exposure."}
  - {name: IaC misconfiguration, attack: T1610, owasp: "", cwe: CWE-1032, risk: safe, when: always,
     command: "checkov -d {path}; trivy config {path}   # Terraform / Kubernetes / Dockerfile",
     purpose: "Find infrastructure-as-code misconfigurations."}
  - {name: CI/CD pipeline security, attack: T1195, owasp: "", cwe: CWE-284, risk: safe, when: always,
     command: "# review GitHub Actions / GitLab CI for pull_request_target, unpinned actions, secret leakage",
     purpose: "Assess the build-pipeline attack surface."}
  - {name: Insecure crypto & defaults, attack: T1552, owasp: "", cwe: CWE-327, risk: safe, when: always,
     command: "# grep for weak crypto (MD5/DES/ECB), disabled TLS verification, debug flags",
     purpose: "Find weak cryptography and unsafe defaults."}
  - {name: Repository OSINT, attack: T1213.003, owasp: "", cwe: CWE-200, risk: safe, when: always,
     command: "# search public forks / gists / commits for leaked internal code and credentials",
     purpose: "Find exposed code and secrets outside the repository."}
  - {name: Malicious code review, attack: T1195.002, owasp: "", cwe: CWE-506, risk: safe, when: always,
     command: "# review for obfuscated code, suspicious postinstall scripts, unexpected network calls",
     purpose: "Detect implanted or backdoored code."}
```
