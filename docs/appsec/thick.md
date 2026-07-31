# Thick-Client Module (desktop binary)

**AppSec pillar — target-driven.** Assesses a thick-client target (a desktop
binary: `.exe`/`.dll`/`.jar`/native). There is no single OWASP standard for
desktop apps, so checks are **CWE-mapped** (the `owasp` field is blank) but still
carry an ATT&CK technique and a `safe|intrusive` risk tag.

Targets come from `assess --thick app.exe`. Static review (strings, decompile,
config/secret scan) is enumeration; anything that touches a running client or the
update channel stays staged for the operator. Tooling: strings, dnSpy/ILSpy/jadx,
Ghidra, procmon, accesschk, mitmproxy, frida (see `docs/appsec/arsenal.md`).
Placeholders: `{app} {host}`.

**Boundary:** methodology + staging only. The engine emits these steps; the
operator runs them with their own tooling.

```yaml
module: thick
title: Thick Client (Desktop Binary)
scope: target
matches: [exe, dll, jar]
summary: "Thick client {host} (desktop binary review)."
techniques_extra: []
checks:
  - {name: Triage strings / imports, attack: T1592.002, owasp: "", cwe: CWE-200, risk: safe,
     command: "strings -n 8 {app}   # + review imports/sections (Detect It Easy, PE-bear)",
     purpose: "Fingerprint the binary, language/runtime and obvious secrets."}
  - {name: Decompile, attack: T1592.002, owasp: "", cwe: CWE-656, risk: safe,
     command: "# .NET: dnSpy/ILSpy {app} | Java: jadx {app} | native: Ghidra {app}",
     purpose: "Recover source/IL for logic and secret review."}
  - {name: Hardcoded secrets / config, attack: T1552.001, owasp: "", cwe: CWE-798, risk: safe,
     command: "# trufflehog filesystem . ; search binary + config for creds/keys/connection-strings",
     purpose: "Recover embedded credentials, keys and connection strings."}
  - {name: Insecure local storage, attack: T1005, owasp: "", cwe: CWE-312, risk: safe,
     command: "# inspect files + registry (HKCU/HKLM) for cleartext secrets; procmon to trace access",
     purpose: "Test for sensitive data stored in the clear locally."}
  - {name: IPC / named pipes / RPC, attack: T1559, owasp: "", cwe: CWE-419, risk: safe,
     command: "# enumerate named pipes / COM / RPC / local sockets; test authz on the IPC endpoints",
     purpose: "Test local IPC surface and its authorization."}
  - {name: DLL search-order hijack, attack: T1574.001, owasp: "", cwe: CWE-427, risk: safe,
     command: "# procmon for 'NAME NOT FOUND' on DLL loads -> plant a proxy DLL on the search path",
     purpose: "Test for DLL/library search-order hijacking."}
  - {name: Privilege & service config, attack: T1574.010, owasp: "", cwe: CWE-276, risk: safe,
     command: "# accesschk: service permissions, unquoted service paths, writable install dir",
     purpose: "Test for local privilege-escalation via weak config."}
  - {name: Update mechanism integrity, attack: T1195, owasp: "", cwe: CWE-494, risk: intrusive,
     command: "# authorized only: MITM the update channel - is it signed + TLS-pinned?",
     purpose: "Test update integrity (code-signing + transport)."}
  - {name: Traffic interception, attack: T1557, owasp: "", cwe: CWE-319, risk: safe,
     command: "# proxy the client through mitmproxy/Burp; review protocol, TLS validation, secrets on the wire",
     purpose: "Test client-server transport and trust."}
  - {name: Backend authorization (thick-client trust), attack: T1078, owasp: "", cwe: CWE-602, risk: safe,
     command: "# replay/modify client->server calls via the proxy; test server-side authz (thick clients often over-trust the client)",
     purpose: "Test whether security decisions are enforced server-side."}
  - {name: Runtime secrets, attack: T1003, owasp: "", cwe: CWE-316, risk: safe,
     command: "# dump process memory for tokens/keys; frida to hook the running client (authorized)",
     purpose: "Recover secrets held in memory at runtime."}
```
