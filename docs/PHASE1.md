# Phase 1 — Assessment Modules

The per-domain assessment methodologies. **Status: implemented and
knowledge-driven** (methodology lives in `docs/modules/*.md`, rendered by the
generic engine in `modules/`).

| Module | Handles | Doc | Status |
| --- | --- | --- | --- |
| Web | http, https, http-proxy, http-alt, www, soap | `modules/web.md` | done |
| SMB | microsoft-ds, netbios-ssn, smb | `modules/smb.md` | done |
| Active Directory | kerberos, ldap, + DC heuristic | `modules/active_directory.md` | done |
| Database | mysql, mssql, postgres, mongo, redis, memcached, elastic, couchdb, oracle, cassandra | `modules/database.md` | done |

Each module contributes ATT&CK-mapped enumeration / authorized credential-testing
checks and attack-surface notes, and attaches the relevant `nmap_analyzer`
findings.

## Candidate next modules
Mail (SMTP/IMAP relay + user enum), DNS (zone transfer / subdomains), SNMP,
container (Docker API / kubelet). Adding one = a new `docs/modules/<name>.md`
plus a `service_registry.md` route — no engine change.
