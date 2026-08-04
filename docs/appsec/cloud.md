# Cloud Module (AWS / Azure / GCP)

**AppSec pillar — target-driven.** Assesses a cloud environment (a provider +
optional account/subscription/project) against the MITRE **ATT&CK Cloud** matrix.
There is no single OWASP standard for cloud, so checks are ATT&CK + CWE-mapped
(`owasp` blank), with a `safe|intrusive` risk tag: unauthenticated storage/OSINT
recon and authenticated **read-only** posture scans are safe; active credential/role
abuse is intrusive (VAPT-hidden).

Targets come from `assess --cloud aws|azure|gcp[:account]`. Checks are
provider-scoped (`when: aws|azure|gcp`) plus cross-provider ones (`always`).
Tooling: cloud_enum, S3Scanner, gcpbucketbrute, ScoutSuite, Prowler, pmapper,
cloudsplaining, ROADtools, AzureHound, MicroBurst, pacu (see `docs/appsec/arsenal.md`).

**Boundary:** methodology + staging only — the operator runs these with their own
cloud credentials, in scope. **Cross-layer:** a web/API SSRF finding pivots straight
into cloud instance-metadata (IMDS) credential theft (T1552.005).

```yaml
module: cloud
title: Cloud (ATT&CK Cloud)
scope: target
matches: [aws, azure, gcp]
summary: "Cloud posture ({provider}) - ATT&CK Cloud methodology."
techniques_extra: []
checks:
  - {name: Public cloud asset discovery, attack: T1580, owasp: "", cwe: CWE-200, risk: safe, when: always,
     command: "cloud_enum -k <company> -k <company>-dev -k <company>-prod",
     purpose: "OSINT-enumerate public S3/Azure/GCP resources by keyword (unauthenticated)."}
  - {name: Open storage buckets, attack: T1619, owasp: "", cwe: CWE-284, risk: safe, when: always,
     command: "# S3: s3scanner scan -b <bucket> | GCS: gcpbucketbrute -k <kw> | Azure: <name>.blob.core.windows.net",
     purpose: "Find world-readable/-writable object storage."}
  - {name: Cloud secrets, attack: T1552, owasp: "", cwe: CWE-798, risk: safe, when: always,
     command: "# trufflehog over IaC/functions/repos; review env vars and lambda/function config",
     purpose: "Recover keys/tokens embedded in cloud code & config."}
  - {name: AWS posture scan, attack: T1526, owasp: "", cwe: "", risk: safe, when: aws,
     command: "prowler aws   (or: scoutsuite aws)",
     purpose: "Full CIS/best-practice posture assessment (read-only)."}
  - {name: AWS IAM privilege paths, attack: T1098.001, owasp: "", cwe: CWE-269, risk: safe, when: aws,
     command: "pmapper graph create && pmapper query 'preset privesc *'   (cloudsplaining / enumerate-iam)",
     purpose: "Map IAM privilege-escalation paths."}
  - {name: AWS public exposure, attack: T1580, owasp: "", cwe: CWE-284, risk: safe, when: aws,
     command: "# review public S3, security groups 0.0.0.0/0, public AMIs/snapshots/RDS/ELB",
     purpose: "Find internet-exposed AWS resources."}
  - {name: EC2 instance metadata (SSRF), attack: T1552.005, owasp: "", cwe: CWE-918, risk: safe, when: aws,
     command: "# via app SSRF: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     purpose: "Abuse IMDS for role creds - chains from a web/API SSRF finding."}
  - {name: Azure / Entra recon, attack: T1526, owasp: "", cwe: "", risk: safe, when: azure,
     command: "roadrecon gather   (or: scoutsuite azure; azurehound for BloodHound edges)",
     purpose: "Enumerate the tenant, roles and resources (read-only)."}
  - {name: Entra ID privilege paths, attack: T1078.004, owasp: "", cwe: CWE-269, risk: safe, when: azure,
     command: "# BloodHound Azure edges (AZAddMembers/AZOwns/AZResetPassword) toward Global Admin",
     purpose: "Map Entra ID privilege-escalation paths."}
  - {name: Azure storage public access, attack: T1530, owasp: "", cwe: CWE-284, risk: safe, when: azure,
     command: "# check blob containers for anonymous access (MicroBurst Invoke-EnumerateAzureBlobs)",
     purpose: "Find public Azure blob storage."}
  - {name: GCP posture scan, attack: T1526, owasp: "", cwe: "", risk: safe, when: gcp,
     command: "scoutsuite gcp   (or: prowler gcp)",
     purpose: "Full posture assessment of the project/org (read-only)."}
  - {name: GCP IAM / service accounts, attack: T1078.004, owasp: "", cwe: CWE-269, risk: safe, when: gcp,
     command: "# enumerate SA keys, roles, actAs/impersonation paths (gcloud iam; hayat)",
     purpose: "Map service-account impersonation / privilege paths."}
  - {name: Credential / role abuse, attack: T1098.003, owasp: "", cwe: CWE-269, risk: intrusive, when: always,
     command: "# authorized only: pacu (AWS) or execute the mapped privesc path (assume role / add creds)",
     purpose: "Execute the escalation - assume role / add credentials."}
```
