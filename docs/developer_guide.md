# Developer Guide

Knowledge-driven development rules.

The golden rule: **methodology and mappings live in `docs/`, not in code.** The
Python is a generic engine that loads and renders the knowledge. Before adding
logic, check whether it belongs in a Markdown knowledge file instead.

## How to extend the platform (no code change)

**Route a new service to a module** — edit `service_registry.md`:
```yaml
registry:
  winrm: [smb]          # add a service-name fragment -> module list
```

**Add an enumeration step to a module** — edit `docs/modules/<module>.md`, add a
check to the `checks:` list:
```yaml
- {name: WinRM check, attack: T1021.006, command: "evil-winrm -i {ip} -u <user> -p <pass>",
   purpose: "Test authenticated WinRM access."}
```

**Add a tool or NSE script** — edit `tool_mapping.md` / `nse_mapping.md`.

**Tune risk** — edit the `risk:` weights/bands in `risk_scoring.md`.

## Module def schema (`docs/modules/*.md`)

```yaml
schema:
  module: "unique id (web, smb, ...)"
  title: "display name"
  scope: "port | host"            # one result per matching port, or per host
  matches: "[service-name fragments]"
  condition: "optional gate (e.g. is_dc)"
  summary: "templated one-liner"
  attack_surface: "[{when, note}]  # when: tls|not tls|unauth|has_cve|ms17010|samba|always"
  checks: "[{name, command, purpose, attack, when?}]"
  # optional: tls_ports, labels, connect, unauth_services, finding_categories, finding_keywords
```

## Conventions

- Commands are operator references for **authorized** engagements — enumeration
  and credential-testing only, never weaponized exploit payloads.
- Every check carries a MITRE ATT&CK technique id.
- Keep fallbacks working: the built-in module classes mirror the docs so the
  engine still runs if the knowledge base is missing.
- Validate after editing: `python3 knowledge_loader.py` should list your change.
