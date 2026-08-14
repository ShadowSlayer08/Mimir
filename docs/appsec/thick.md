# Thick-Client Module (desktop binary)

**AppSec pillar — target-driven.** Assesses a thick-client target across platforms:
Windows (`.exe`/`.dll`/`.msi`), Linux (ELF/`.so`) and macOS (`.app`/`.dmg`/`.pkg`,
Mach-O). There is no single OWASP standard for desktop apps, so checks are
**CWE-mapped** (the `owasp` field is blank) but still carry an ATT&CK technique and a
`safe|intrusive` risk tag. Platform-specific checks are gated with
`when: windows|linux|macos`; cross-platform ones are `always`.

Targets come from `assess --thick app.exe|app.dmg|app.elf` (platform inferred from
extension). Tooling: strings, dnSpy/ILSpy/jadx, Ghidra, Hopper, otool/class-dump,
procmon, accesschk, mitmproxy, frida (see `docs/appsec/arsenal.md`).
Placeholders: `{app} {host} {platform}`.

**Boundary:** methodology + staging only. The engine emits these steps; the operator
runs them with their own tooling.

```yaml
module: thick
title: Thick Client (Desktop Binary)
scope: target
matches: [exe, dll, jar, elf, dmg, app, macos, linux, windows]
summary: "Thick client {host} (desktop binary review)."
techniques_extra: []
checks:
  - {name: Triage strings / imports, attack: T1592.002, owasp: "", cwe: CWE-200, risk: safe, when: always,
     command: "strings -n 8 {app}   # + review imports/sections (Detect It Easy, PE-bear)",
     purpose: "Fingerprint the binary, language/runtime and obvious secrets."}
  - {name: Decompile, attack: T1592.002, owasp: "", cwe: CWE-656, risk: safe, when: always,
     command: "# .NET: dnSpy/ILSpy {app} | Java: jadx {app} | native: Ghidra {app}",
     purpose: "Recover source/IL for logic and secret review."}
  - {name: Hardcoded secrets / config, attack: T1552.001, owasp: "", cwe: CWE-798, risk: safe, when: always,
     command: "# trufflehog filesystem . ; search binary + config for creds/keys/connection-strings",
     purpose: "Recover embedded credentials, keys and connection strings."}
  - {name: Insecure local storage, attack: T1005, owasp: "", cwe: CWE-312, risk: safe, when: always,
     command: "# inspect files, registry (HKCU/HKLM on Windows) and app config for cleartext secrets; procmon/strace",
     purpose: "Test for sensitive data stored in the clear locally."}
  - {name: Traffic interception, attack: T1557, owasp: "", cwe: CWE-319, risk: safe, when: always,
     command: "# proxy the client through mitmproxy/Burp; review protocol, TLS validation, secrets on the wire",
     purpose: "Test client-server transport and trust."}
  - {name: Backend authorization (thick-client trust), attack: T1078, owasp: "", cwe: CWE-602, risk: safe, when: always,
     command: "# replay/modify client->server calls via the proxy; test server-side authz (thick clients often over-trust the client)",
     purpose: "Test whether security decisions are enforced server-side."}
  - {name: Update mechanism integrity, attack: T1195, owasp: "", cwe: CWE-494, risk: intrusive, when: always,
     command: "# authorized only: MITM the update channel - is it signed + TLS-pinned?",
     purpose: "Test update integrity (code-signing + transport)."}
  - {name: Runtime secrets, attack: T1003, owasp: "", cwe: CWE-316, risk: safe, when: always,
     command: "# dump process memory for tokens/keys; frida to hook the running client (authorized)",
     purpose: "Recover secrets held in memory at runtime."}
  - {name: IPC / named pipes / RPC, attack: T1559, owasp: "", cwe: CWE-419, risk: safe, when: windows,
     command: "# enumerate named pipes / COM / RPC / local sockets; test authz on the IPC endpoints",
     purpose: "Test the local IPC surface and its authorization."}
  - {name: DLL search-order hijack, attack: T1574.001, owasp: "", cwe: CWE-427, risk: safe, when: windows,
     command: "# procmon for 'NAME NOT FOUND' on DLL loads -> plant a proxy DLL on the search path",
     purpose: "Test for DLL search-order hijacking."}
  - {name: Privilege & service config, attack: T1574.010, owasp: "", cwe: CWE-276, risk: safe, when: windows,
     command: "# accesschk: service permissions, unquoted service paths, writable install dir",
     purpose: "Test for local privilege-escalation via weak config."}
  - {name: macOS signing & notarization, attack: T1553.001, owasp: "", cwe: CWE-347, risk: safe, when: macos,
     command: "codesign -dv --verbose=4 {app}; spctl -a -vv {app}   # signature, notarization, Gatekeeper",
     purpose: "Assess code-signing, notarization and Gatekeeper."}
  - {name: macOS entitlements & TCC, attack: T1548, owasp: "", cwe: CWE-250, risk: safe, when: macos,
     command: "codesign -d --entitlements :- {app}   # entitlements, hardened runtime, TCC/privacy scope",
     purpose: "Review entitlements, hardened runtime and TCC exposure."}
  - {name: Mach-O analysis, attack: T1592.002, owasp: "", cwe: CWE-656, risk: safe, when: macos,
     command: "otool -L {app}; class-dump {app}   # + Hopper/Ghidra: dylibs, ObjC/Swift symbols",
     purpose: "Decompile the Mach-O binary and map dylibs."}
  - {name: Dylib hijack / injection, attack: T1574.004, owasp: "", cwe: CWE-427, risk: safe, when: macos,
     command: "# check @rpath/@loader_path dylib load order for hijack; DYLD_INSERT_LIBRARIES",
     purpose: "Test for dylib hijacking / injection."}
  - {name: macOS Keychain / local secrets, attack: T1555.001, owasp: "", cwe: CWE-522, risk: safe, when: macos,
     command: "# inspect Keychain items, plist/preferences and app-support files for cleartext secrets",
     purpose: "Test for secrets in the Keychain and local files."}
  - {name: ELF analysis & hardening, attack: T1592.002, owasp: "", cwe: CWE-656, risk: safe, when: linux,
     command: "file {app}; checksec --file={app}   # + Ghidra: RELRO/NX/PIE/canary, imports",
     purpose: "Decompile the ELF and check binary hardening."}
  - {name: SUID / capabilities / RPATH, attack: T1548.001, owasp: "", cwe: CWE-732, risk: safe, when: linux,
     command: "# check SUID/SGID, file capabilities (getcap), RPATH/RUNPATH for library hijack",
     purpose: "Test for local privilege-escalation via ELF permissions."}
  - {name: Linux local IPC, attack: T1559, owasp: "", cwe: CWE-419, risk: safe, when: linux,
     command: "# enumerate D-Bus / unix sockets; test authz on the local IPC endpoints",
     purpose: "Test the local IPC surface on Linux."}
```
