# Web Application Module (OWASP WSTG)

**AppSec pillar — target-driven.** Where the `web` module covers an HTTP *service*
on a port, `web_app` covers the *application* at a URL: an OWASP **WSTG**-structured
methodology a human operator runs in scope. Each check carries its ATT&CK technique
**plus** an OWASP (WSTG) reference, a CWE, and a `safe|intrusive` risk tag (intrusive
steps — credential testing, SQLi, OS-command injection — are hidden in VAPT mode).

Tooling references the **WebHackersWeapons** arsenal
(`github.com/hahwul/WebHackersWeapons`) — see `docs/appsec/arsenal.md` for the full
per-category tool map. Targets are the URLs the engine derives (auto-promoted from
discovered http/https services, or supplied with `assess --web URL`). Commands
substitute `{url} {host} {port} {scheme} {label} {domain} {seclists} {users} {passwords}`.

**Boundary:** methodology + staging only. The engine emits these steps; the operator
runs them with their own tooling. No exploit is launched here.

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
     command: "katana -u {url} -jc -silent", purpose: "Map endpoints, JS and the attack surface (katana)."}
  - {name: Passive URL gathering, attack: T1594, owasp: WSTG-INFO-01, cwe: CWE-200, risk: safe,
     command: "gau {domain}", purpose: "Collect known URLs/params from archives (gau/waymore)."}
  - {name: Content discovery, attack: T1595.003, owasp: WSTG-INFO-07, cwe: CWE-538, risk: safe,
     command: "feroxbuster -u {url} -k -w {seclists}/Discovery/Web-Content/raft-medium-directories.txt",
     purpose: "Enumerate hidden directories and files."}
  - {name: Parameter discovery, attack: T1595, owasp: WSTG-INFO-07, cwe: CWE-200, risk: safe,
     command: "arjun -u {url}", purpose: "Mine hidden request parameters (arjun/paramspider) as injection points."}
  - {name: Robots / sitemap, attack: T1593, owasp: WSTG-INFO-03, cwe: CWE-200, risk: safe,
     command: "curl -sk {url}/robots.txt", purpose: "Surface disallowed or listed paths."}
  - {name: JS secret mining, attack: T1552.001, owasp: WSTG-INFO-05, cwe: CWE-200, risk: safe,
     command: "# harvest JS, then: SecretFinder -i <app.js> -o cli  (or trufflehog/gitleaks)",
     purpose: "Extract API keys/tokens/endpoints leaked in client-side JS."}
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
     command: "# inspect Set-Cookie flags (Secure/HttpOnly/SameSite); test tokens with jwt_tool",
     purpose: "Review session-cookie flags and token handling."}
  - {name: Authorization / IDOR, attack: T1190, owasp: WSTG-ATHZ-04, cwe: CWE-639, risk: safe,
     command: "# replay object refs across roles/users (Burp Autorize / autorize) to find IDOR/BOLA",
     purpose: "Test access control on object and function references."}
  - {name: SQL injection, attack: T1190, owasp: WSTG-INPV-05, cwe: CWE-89, risk: intrusive,
     command: "# authorized only: sqlmap -u '{url}/?id=1' --batch --level 2   (alt: ghauri)",
     purpose: "Test parameters for SQL injection (sqlmap/ghauri)."}
  - {name: XSS, attack: T1059.007, owasp: WSTG-INPV-01, cwe: CWE-79, risk: safe,
     command: "dalfox url {url}", purpose: "Test reflected/stored/DOM XSS on inputs and sinks (dalfox)."}
  - {name: SSTI, attack: T1190, owasp: WSTG-INPV-18, cwe: CWE-1336, risk: safe,
     command: "# probe template injection with polyglot payloads on server-rendered inputs (tplmap)",
     purpose: "Test for server-side template injection."}
  - {name: SSRF (OOB), attack: T1190, owasp: WSTG-INPV-19, cwe: CWE-918, risk: safe,
     command: "# inject interactsh OAST payloads into URL/host params; watch interactsh-client for callbacks (SSRFmap for exploitation)",
     purpose: "Test for server-side request forgery, incl. blind via out-of-band."}
  - {name: Command injection, attack: T1190, owasp: WSTG-INPV-12, cwe: CWE-78, risk: intrusive,
     command: "# authorized only: commix -u '{url}?p=1' --batch",
     purpose: "Test for OS command injection (commix)."}
  - {name: Deserialization / XXE / upload, attack: T1190, owasp: WSTG-INPV-13, cwe: CWE-502, risk: safe,
     command: "# test insecure deserialization, XXE and unrestricted file upload",
     purpose: "Test object/XML/upload handling."}
  - {name: CRLF / open redirect, attack: T1595, owasp: WSTG-CLNT-04, cwe: CWE-601, risk: safe,
     command: "# test CRLF injection and open redirect on redirect/next params (crlfuzz, oralyzer)",
     purpose: "Test header/response splitting and unvalidated redirects."}
  - {name: Business logic, attack: T1190, owasp: WSTG-BUSL-01, cwe: CWE-840, risk: safe,
     command: "# test workflow, rate-limit and price/quantity-tampering abuse",
     purpose: "Test business-logic and anti-automation controls."}
  - {name: CORS misconfiguration, attack: T1539, owasp: WSTG-CLNT-07, cwe: CWE-942, risk: safe,
     command: "corsy -u {url}", purpose: "Check for permissive/broken CORS policy (corsy)."}
```
