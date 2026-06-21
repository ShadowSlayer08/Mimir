# Web Module

HTTP/HTTPS methodology. One assessment per web port. The engine substitutes
`{ip} {port} {scheme} {label} {domain}` into each command.

```yaml
module: web
title: Web (HTTP/HTTPS)
scope: port
matches: [http, https, http-proxy, http-alt, www, soap]
tls_ports: [443, 8443]
summary: "{SCHEME} service ({prod})."
attack_surface:
  - when: "not tls"
    note: "Cleartext HTTP — credentials and sessions exposed on-path."
  - when: "tls"
    note: "TLS endpoint — review TLS protocol/cipher/cert findings."
  - when: "has_cve"
    note: "Server version has known CVEs (see findings)."
techniques_extra: []
checks:
  - {name: Fingerprint,        attack: T1592.002, command: "whatweb {scheme}://{ip}:{port}",
     purpose: "Identify server, framework, CMS and technologies."}
  - {name: Security headers,   attack: T1595.002, command: "curl -skI {scheme}://{ip}:{port}",
     purpose: "Check HSTS, CSP, X-Frame-Options, cookie flags."}
  - {name: HTTP methods,       attack: T1595,     command: "curl -skX OPTIONS {scheme}://{ip}:{port} -i",
     purpose: "Detect risky verbs (PUT/DELETE/TRACE/WebDAV)."}
  - {name: Content discovery,  attack: T1595.003, command: "feroxbuster -u {scheme}://{ip}:{port} -k -w {seclists}/Discovery/Web-Content/raft-medium-directories.txt",
     purpose: "Enumerate hidden directories and files."}
  - {name: Vhost discovery,    attack: T1595,     command: "ffuf -u {scheme}://{ip}:{port} -H 'Host: FUZZ.{label}' -w subdomains.txt -fs 0",
     purpose: "Discover virtual hosts on the same service."}
  - {name: Template scan,      attack: T1595.002, command: "nuclei -u {scheme}://{ip}:{port}",
     purpose: "Run known-CVE / misconfiguration templates."}
  - {name: Robots / sitemap,   attack: T1593,     command: "curl -sk {scheme}://{ip}:{port}/robots.txt",
     purpose: "Surface disallowed or listed paths."}
  - {name: Input testing,      attack: T1190,     command: "# map inputs, then test injection in scope (e.g. sqlmap in test mode)",
     purpose: "Identify injection / auth-bypass surface (authorized)."}
  - {name: TLS posture,        attack: T1595,     when: tls, command: "sslscan {ip}:{port}",
     purpose: "Enumerate protocols, ciphers and certificate issues."}
```
