# Security Policy

## Reporting a vulnerability

If you find a security issue in Vantage itself (not in a system you're
assessing with it), please report it privately rather than opening a public
issue.

**Preferred channel:** email `security@vantage-engine.dev` (replace with your
real address before publishing) with:

- the affected version (`vantage --version`),
- clear reproduction steps,
- an impact assessment, and
- any proof-of-concept you can share without harming third parties.

Please **do not** include real engagement data (client scope, hostnames,
credentials). Vantage's engagement data is operator-controlled; if an incident
affects engagement data in a way that must be disclosed, use your own
incident-response channel for that side.

We aim to acknowledge within **3 business days** and ship a fix for a confirmed
high-severity issue within **30 days**. Low-severity hardening lands on the
normal release cycle.

## In-scope for the policy

- Memory, logic, or deserialisation issues in Vantage's own code
- Weaknesses in the vault (`vault.py`) that let someone bypass AES-256-GCM
  authentication or recover plaintext without the password
- Scope-guard bypasses: a target that should be filtered by the ROE hard-gate
  or the institutional TLD guardrail but is not
- MCP server weaknesses (`mcp_server.py`) that let a client write engagement
  state outside the documented read-only surface
- Credential leaks in logs, reports, or the engagement JSON

## Not in scope

- Reports about systems you have scanned with Vantage — those belong in your
  own responsible-disclosure process with the asset owner.
- Content a local LLM generates when invoked through Vantage. Vantage is an
  operator-driven planner; the human operator is responsible for which steps
  they execute.
- Social-engineering content and anything specific to targets you don't own
  or aren't authorized to assess.

## Known constraints (not vulnerabilities)

- The engine runs **as the operator** and has whatever network access the
  operator's machine has — scope enforcement is a *policy* control, not a
  sandbox. Running Vantage as root/Administrator against an unapproved target
  is an operator error, not a Vantage bug.
- The institutional-TLD guardrail is overridable with
  `VANTAGE_ALLOW_INSTITUTIONAL=1`; using that override to attack a `.gov`
  domain you aren't authorized to assess is a *you* problem.
- The engine stores nothing on the network. There is no Vantage telemetry,
  no "phone home". Any observed outbound connection comes from an operator-
  invoked tool, an opt-in enrichment feed, or a local Ollama endpoint.

## Hall of fame

If you report a confirmed issue and want credit, we'd be delighted to list
you here on the next release.
