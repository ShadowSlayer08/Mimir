# SaaS Identity Module (Entra / Okta / Workspace)

**AppSec pillar — target-driven.** Assesses a SaaS identity provider (Entra ID /
M365, Okta, Google Workspace, ADFS) — the cloud-identity attack surface above
individual apps. Checks are ATT&CK + CWE-mapped with a `safe|intrusive` risk tag:
recon / user-enum / MFA-coverage review are safe; password spray, MFA fatigue, SAML
forgery and phishing are intrusive (VAPT-hidden, lockout-aware).

Targets come from `assess --identity entra|m365|okta|gworkspace|adfs[:tenant]`.
Provider-scoped checks use `when: entra|okta|gworkspace`. Tooling: ROADtools,
AADInternals, GraphRunner, o365spray, MFASweep, TeamFiltration, trevorspray, GAT/GAM.

**Boundary:** methodology + staging only — the operator runs these against their own
authorized tenant. **Cross-layer:** federation trust ties into on-prem AD (Golden SAML)
and the cloud module (Entra ↔ Azure).

```yaml
module: identity
title: SaaS Identity (Entra / Okta / Workspace)
scope: target
matches: [entra, m365, okta, gworkspace, adfs]
summary: "SaaS identity posture."
techniques_extra: []
checks:
  - {name: Tenant / federation recon, attack: T1590, owasp: "", cwe: CWE-200, risk: safe, when: always,
     command: "# check /{domain}/.well-known/openid-configuration; getuserrealm (managed vs federated); autodiscover",
     purpose: "Fingerprint the IdP and federation type."}
  - {name: User enumeration, attack: T1589.002, owasp: "", cwe: CWE-203, risk: safe, when: always,
     command: "o365spray --enum -d {domain}   # or Okta /api/v1 response + timing user-enum",
     purpose: "Enumerate valid accounts."}
  - {name: Password spray, attack: T1110.003, owasp: "", cwe: CWE-307, risk: intrusive, when: always,
     command: "# authorized: TeamFiltration / trevorspray - low-and-slow single-password spray (lockout-aware)",
     purpose: "Test for weak / reused passwords."}
  - {name: MFA coverage & legacy auth, attack: T1078.004, owasp: "", cwe: CWE-308, risk: safe, when: always,
     command: "MFASweep   # find legacy/basic-auth endpoints (EWS/IMAP/SMTP AUTH) that bypass MFA",
     purpose: "Find accounts and protocols without MFA."}
  - {name: MFA fatigue / push bombing, attack: T1621, owasp: "", cwe: CWE-287, risk: intrusive, when: always,
     command: "# authorized: repeated push prompts to a consented test account (measure user response)",
     purpose: "Test MFA-fatigue susceptibility."}
  - {name: Entra / M365 recon (authed), attack: T1526, owasp: "", cwe: "", risk: safe, when: entra,
     command: "roadrecon gather && roadrecon gui   # or AADInternals / GraphRunner (read-only)",
     purpose: "Enumerate tenant, roles, apps and Conditional Access policies."}
  - {name: OAuth app / consent surface, attack: T1528, owasp: "", cwe: CWE-287, risk: safe, when: entra,
     command: "# review app registrations, over-privileged Graph scopes, illicit-consent-grant risk",
     purpose: "Find token / consent-grant attack surface."}
  - {name: Conditional Access gaps, attack: T1078.004, owasp: "", cwe: CWE-284, risk: safe, when: entra,
     command: "# review CAPs for excluded users, legacy-auth allowances, device/location gaps",
     purpose: "Find Conditional-Access policy bypasses."}
  - {name: Okta configuration & policy, attack: T1526, owasp: "", cwe: "", risk: safe, when: okta,
     command: "# enumerate org apps, auth/sign-on policies, ThreatInsight, factor enrollment, API tokens",
     purpose: "Assess Okta configuration and policy."}
  - {name: Google Workspace recon, attack: T1526, owasp: "", cwe: "", risk: safe, when: gworkspace,
     command: "# GAT/GAM: enumerate users, OAuth tokens, super-admins, less-secure-app / OAuth scopes",
     purpose: "Assess Google Workspace configuration."}
  - {name: Federation / SAML forgery, attack: T1606.002, owasp: "", cwe: CWE-347, risk: intrusive, when: always,
     command: "# authorized: with the token-signing key, forge SAML (Golden SAML) to test federation trust",
     purpose: "Test federation trust and token forgery (ADFS / Entra)."}
  - {name: Credential phishing / device code, attack: T1566, owasp: "", cwe: CWE-1021, risk: intrusive, when: always,
     command: "# authorized red-team: device-code or evilginx AiTM to capture tokens (with consent)",
     purpose: "Test credential-phishing and token-theft resilience."}
```
