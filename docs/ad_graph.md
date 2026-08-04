# AD Relationship Graph (`ad_graph.py`)

BloodHound-style privilege-escalation analysis — **ingest + stage, not collect**.

## Boundary
Collecting AD data is an active, authenticated step, so it stays with the human
operator (it's a staged check in the `active_directory` module). The operator runs
their collector of choice — **SoapHound** (ADWS, stealthy), **RustHound-CE** (fast),
**bloodhound-python** (Linux) or **SharpHound** (Windows) — and the engine
**ingests** the BloodHound-compatible JSON, builds a graph, and **stages** the
abusable paths for the operator to execute. The engine launches nothing. This is
guided, human-led exploitation.

## Flow
```
operator:  soaphound.py … --bloodhound   (or rusthound-ce / bloodhound-python / SharpHound)
engine:    ad_graph.py bloodhound.zip --owned "DOMAIN USERS@DOMAIN"
           assess … --bloodhound bloodhound.zip      # merges AD paths into the engagement
```

## What it does
- **Ingest** a `.zip` / directory / `.json` (BloodHound legacy v4/5 and CE v6/7;
  SoapHound & RustHound-CE emit the same schema).
- **Graph** — nodes (User/Computer/Group/Domain/GPO/OU/CertTemplate/CA) and abusable
  edges from ACEs + membership + local-admin + sessions + delegation/RBCD: MemberOf,
  GenericAll/Write, WriteDacl/Owner, ForceChangePassword, AddMember,
  AddKeyCredentialLink, GetChanges(All)/DCSync, AdminTo, HasSession, CanRDP/PSRemote,
  AllowedToDelegate, AddAllowedToAct, Enroll (ESC).
- **Paths** — shortest routes from an **owned** start set (default: what *any*
  authenticated user can reach — Domain Users) to **high-value** targets (DA/EA/DCs
  via well-known RIDs or the `highvalue` flag). Each edge becomes a staged step with
  its ATT&CK technique and abuse insight (how + opsec), e.g. `GenericAll` → shadow
  credentials (certipy), `WriteDacl` on the domain → DCSync, `AddAllowedToAct` → RBCD
  s4u, `Enroll` → Certipy ESC.
- **Emit** — paths use the engine's `attack_path` shape, so they flow into the report,
  `--emit-json`, runbook, kill-chain, console and web GUI alongside the infra paths.

## Cross-layer
Seed `--owned` with a principal you already control (a recovered credential, or a
host compromised via the web/API/infra pillars) and the graph shows the route from
that foothold to Domain Admin — the full **app → host → domain** chain.
