# Web Application Module (OWASP WSTG)

**AppSec pillar — target-driven.** Where the `web` module covers an HTTP *service*
on a port, `web_app` covers the *application* at a URL: an OWASP **WSTG**-structured
methodology that a human operator runs in scope. Each check carries its ATT&CK
technique **plus** an OWASP (WSTG) reference, a CWE, and a `safe|intrusive` risk
tag (intrusive steps — credential testing, SQLi/sqlmap — are hidden in VAPT mode).

Targets are the URLs the engine derives (auto-promoted from discovered http/https
services, or supplied with `assess --web URL`). Commands substitute
`{url} {host} {port} {scheme} {label} {seclists} {users} {passwords}`.

**Boundary:** methodology + staging only. The engine emits these steps; the
operator runs them with their own tooling. No exploit is launched here.

```yaml
module: web_app
title: Web App (OWASP WSTG)
scope: target
matches: [http, https, http-alt, http-proxy, www, soap]
summary: "Web application at {url} (OWASP WSTG methodology)."
techniques_extra: []
checks:
  - {name: Fingerprint, attack: T1592.002, owasp: WSTG-INFO-02, cwe: CWE-200, risk: safe,
     command: "whatweb {url}", purpose: "Identify server, framework, CMS and technologies."}
  - {name: Crawl / map, attack: T1595, owasp: WSTG-INFO-01, cwe: CWE-200, risk: safe,
     command: "katana -u {url} -silent", purpose: "Map endpoints, parameters and the attack surface."}
  - {name: Content discovery, attack: T1595.003, owasp: WSTG-INFO-07, cwe: CWE-538, risk: safe,
     command: "feroxbuster -u {url} -k -w {seclists}/Discovery/Web-Content/raft-medium-directories.txt",
     purpose: "Enumerate hidden directories and files."}
  - {name: Robots / sitemap, attack: T1593, owasp: WSTG-INFO-03, cwe: CWE-200, risk: safe,
     command: "curl -sk {url}/robots.txt", purpose: "Surface disallowed or listed paths."}
  - {name: Security headers, attack: T1595.002, owasp: WSTG-CONF-12, cwe: CWE-693, risk: safe,
     command: "curl -skI {url}", purpose: "Check HSTS, CSP, X-Frame-Options and cookie flags."}
  - {name: HTTP methods, attack: T1595, owasp: WSTG-CONF-06, cwe: CWE-650, risk: safe,
     command: "curl -skX OPTIONS {url} -i", purpose: "Detect risky verbs (PUT/DELETE/TRACE/WebDAV)."}
  - {name: Exposed VCS / config / backups, attack: T1213, owasp: WSTG-CONF-04, cwe: CWE-538, risk: safe,
     command: "nuclei -u {url} -tags exposure,config,backup",
     purpose: "Find .git/.env/backups/admin consoles."}
  - {name: Template / known-CVE scan, attack: T1595.002, owasp: WSTG-INFO-08, cwe: CWE-1395, risk: safe,
     command: "nuclei -u {url}", purpose: "Run known-CVE and misconfiguration templates."}
  - {name: TLS posture, attack: T1595, owasp: WSTG-CRYP-01, cwe: CWE-326, risk: safe, when: tls,
     command: "sslscan {host}:{port}", purpose: "Enumerate protocols, ciphers and certificate issues."}
  - {name: Auth default/weak creds, attack: T1110.001, owasp: WSTG-ATHN-02, cwe: CWE-307, risk: intrusive,
     command: "# authorized only: hydra -L {users} -P {passwords} {host} http-post-form '<path>:<body>:<fail>'",
     purpose: "Test the login for default/weak credentials (in scope)."}
  - {name: Session & JWT, attack: T1539, owasp: WSTG-SESS-02, cwe: CWE-614, risk: safe,
     command: "# inspect Set-Cookie flags (Secure/HttpOnly/SameSite); decode JWTs with jwt_tool",
     purpose: "Review session-cookie flags and token handling."}
  - {name: Authorization / IDOR, attack: T1190, owasp: WSTG-ATHZ-04, cwe: CWE-639, risk: safe,
     command: "# replay object refs across roles/users (Burp Autorize) to find IDOR/BOLA",
     purpose: "Test access control on object and function references."}
  - {name: SQL injection, attack: T1190, owasp: WSTG-INPV-05, cwe: CWE-89, risk: intrusive,
     command: "# authorized only: sqlmap -u '{url}/?id=1' --batch --level 2",
     purpose: "Test parameters for SQL injection."}
  - {name: XSS, attack: T1190, owasp: WSTG-INPV-01, cwe: CWE-79, risk: safe,
     command: "# test reflected/stored/DOM XSS on identified inputs (in scope)",
     purpose: "Test for cross-site scripting on inputs and sinks."}
  - {name: SSTI, attack: T1190, owasp: WSTG-INPV-18, cwe: CWE-1336, risk: safe,
     command: "# probe template injection (e.g. 7*7) on server-rendered inputs",
     purpose: "Test for server-side template injection."}
  - {name: SSRF, attack: T1190, owasp: WSTG-INPV-19, cwe: CWE-918, risk: safe,
     command: "# test URL/host params for SSRF to internal services / cloud metadata",
     purpose: "Test for server-side request forgery."}
  - {name: Command injection, attack: T1190, owasp: WSTG-INPV-12, cwe: CWE-78, risk: safe,
     command: "# test OS command injection on inputs that reach a shell",
     purpose: "Test for OS command injection."}
  - {name: Deserialization / XXE / upload, attack: T1190, owasp: WSTG-INPV-13, cwe: CWE-502, risk: safe,
     command: "# test insecure deserialization, XXE and unrestricted file upload",
     purpose: "Test object/XML/upload handling."}
  - {name: Business logic, attack: T1190, owasp: WSTG-BUSL-01, cwe: CWE-840, risk: safe,
     command: "# test workflow, rate-limit and price/quantity-tampering abuse",
     purpose: "Test business-logic and anti-automation controls."}
  - {name: CORS / client-side, attack: T1539, owasp: WSTG-CLNT-07, cwe: CWE-942, risk: safe,
     command: "curl -skI {url} -H 'Origin: https://evil.example'",
     purpose: "Check CORS policy and client-side trust."}
```
