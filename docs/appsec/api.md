# API Module (OWASP API Security Top 10)

**AppSec pillar — target-driven.** Sibling of `web_app` for REST/GraphQL APIs.
Assesses an API target (a base URL, or a spec) with the OWASP **API Security Top
10 (2023)** as the backbone — spec-driven where possible (OpenAPI/Swagger
discovery, GraphQL introspection). Each check carries its ATT&CK technique plus an
OWASP API-Top-10 reference and a CWE, and a `safe|intrusive` risk tag (intrusive —
broken-auth testing, injection, resource-consumption — hidden in VAPT mode).

Targets come from `assess --api URL`. Tooling references the **WebHackersWeapons**
arsenal (`docs/appsec/arsenal.md`) plus API-specific tools (kiterunner, schemathesis,
graphw00f/clairvoyance, jwt_tool). Commands substitute
`{url} {host} {port} {scheme} {domain} {seclists}`.

**Boundary:** methodology + staging only. The engine emits these steps; the
operator runs them with their own tooling. No exploit is launched here.

```yaml
module: api
title: API (OWASP API Top 10)
scope: target
matches: [http, https, http-alt]
summary: "API at {url} (OWASP API Security Top 10)."
techniques_extra: []
checks:
  - {name: Spec / schema discovery, attack: T1595, owasp: "API9:2023", cwe: CWE-1059, risk: safe,
     command: "curl -sk {url}/openapi.json; curl -sk {url}/swagger.json; curl -sk {url}/v3/api-docs",
     purpose: "Locate the OpenAPI/Swagger spec (drives everything else)."}
  - {name: Endpoint enumeration, attack: T1595.003, owasp: "API9:2023", cwe: CWE-1059, risk: safe,
     command: "kr scan {url} -w routes-large.kite -x 20",
     purpose: "Brute API routes when no spec is exposed (kiterunner)."}
  - {name: Improper inventory (old/undoc versions), attack: T1595, owasp: "API9:2023", cwe: CWE-1059, risk: safe,
     command: "# probe /v1 /v2 /internal /docs /graphql; diff behaviour across versions",
     purpose: "Find deprecated/undocumented API versions and hosts."}
  - {name: GraphQL introspection, attack: T1595, owasp: "API8:2023", cwe: CWE-16, risk: safe,
     command: "# graphw00f {url}; then clairvoyance / InQL to dump the schema via introspection",
     purpose: "Fingerprint GraphQL and recover the schema if introspection is open."}
  - {name: Auth mechanism & JWT, attack: T1078, owasp: "API2:2023", cwe: CWE-287, risk: safe,
     command: "# identify auth (Bearer/JWT/API-key); test JWTs with jwt_tool (alg:none, weak/HS256 key)",
     purpose: "Review the auth scheme and token handling."}
  - {name: Broken authentication, attack: T1110.001, owasp: "API2:2023", cwe: CWE-307, risk: intrusive,
     command: "# authorized only: credential-stuff / rate-test the token endpoint",
     purpose: "Test the auth endpoints for weak/guessable credentials."}
  - {name: BOLA (object-level authz), attack: T1190, owasp: "API1:2023", cwe: CWE-639, risk: safe,
     command: "# swap object IDs across two accounts (Burp Autorize) to reach other users' objects",
     purpose: "Test broken object-level authorization / IDOR."}
  - {name: BFLA (function-level authz), attack: T1190, owasp: "API5:2023", cwe: CWE-285, risk: safe,
     command: "# call admin/privileged methods & routes as a low-priv token",
     purpose: "Test broken function-level authorization."}
  - {name: BOPLA / mass assignment, attack: T1190, owasp: "API3:2023", cwe: CWE-915, risk: safe,
     command: "# add unexpected properties (e.g. role=admin, isVerified=true) to requests",
     purpose: "Test object-property-level authz, mass assignment & excessive data exposure."}
  - {name: Unrestricted resource consumption, attack: T1499, owasp: "API4:2023", cwe: CWE-770, risk: intrusive,
     command: "# authorized only: test missing rate-limits / unbounded pagination / large payloads",
     purpose: "Test for resource-consumption / DoS controls (watch impact)."}
  - {name: Sensitive business flow abuse, attack: T1190, owasp: "API6:2023", cwe: CWE-799, risk: safe,
     command: "# script a sensitive flow (signup/checkout/reset) to test anti-automation",
     purpose: "Test unrestricted access to sensitive business flows."}
  - {name: SSRF (OOB), attack: T1190, owasp: "API7:2023", cwe: CWE-918, risk: safe,
     command: "# inject interactsh OAST payloads into URL/webhook/import params; watch for callbacks",
     purpose: "Test server-side request forgery, incl. blind via out-of-band."}
  - {name: Injection, attack: T1190, owasp: "API8:2023", cwe: CWE-89, risk: intrusive,
     command: "# authorized only: sqlmap / NoSQLi against API parameters and JSON bodies",
     purpose: "Test SQL/NoSQL/command injection on API inputs."}
  - {name: Schema-based fuzzing, attack: T1595, owasp: "API8:2023", cwe: CWE-20, risk: safe,
     command: "schemathesis run {url}/openapi.json --checks all",
     purpose: "Property-test every operation against its schema (authorized)."}
  - {name: Security misconfiguration, attack: T1595.002, owasp: "API8:2023", cwe: CWE-16, risk: safe,
     command: "nuclei -u {url} -tags misconfig,api,exposure",
     purpose: "CORS, verbose errors, missing headers, debug endpoints."}
  - {name: Unsafe consumption of upstream APIs, attack: T1190, owasp: "API10:2023", cwe: CWE-20, risk: safe,
     command: "# review trust in third-party/upstream APIs and validation of their responses",
     purpose: "Test unsafe consumption of integrated APIs."}
```
