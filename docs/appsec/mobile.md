# Mobile App Module (OWASP MASVS/MASTG)

**AppSec pillar — target-driven.** Assesses a mobile-app target (an APK/IPA file)
with the OWASP **MASVS** as the backbone (verified per **MASTG**). Each check
carries its ATT&CK technique plus a MASVS reference and a CWE, and a
`safe|intrusive` risk tag (intrusive dynamic instrumentation — frida/objection —
is hidden in VAPT mode).

Targets come from `assess --mobile app.apk|app.ipa`. Static analysis (unpack,
decompile, secret-scan) is enumeration; **dynamic** analysis on a test device
stays staged for the operator. Tooling: apktool, jadx, MobSF/mobsfscan, frida,
objection, trufflehog (see `docs/appsec/arsenal.md`). Placeholders: `{app} {host}
{platform}`.

**Boundary:** methodology + staging only. The engine emits these steps; the
operator runs them with their own tooling on an authorized test device.

```yaml
module: mobile
title: Mobile App (OWASP MASVS)
scope: target
matches: [apk, ipa]
summary: "Mobile app {host} (OWASP MASVS methodology)."
techniques_extra: []
checks:
  - {name: Unpack / decompile, attack: T1592.002, owasp: "MASVS-CODE-1", cwe: CWE-656, risk: safe,
     command: "# android: apktool d {app} -o out/ && jadx -d src/ {app}   |  ios: unzip {app}",
     purpose: "Unpack the app and decompile to source for review."}
  - {name: Static MASVS scan, attack: T1595.002, owasp: "MASVS-CODE-2", cwe: CWE-1395, risk: safe,
     command: "# MobSF: upload {app} for static analysis  (or: mobsfscan out/)",
     purpose: "Run an automated MASVS static analysis pass."}
  - {name: Hardcoded secrets, attack: T1552.001, owasp: "MASVS-STORAGE-2", cwe: CWE-798, risk: safe,
     command: "# trufflehog filesystem out/ ; grep decompiled src for keys/tokens/URLs",
     purpose: "Recover API keys, tokens and endpoints baked into the app."}
  - {name: Manifest / exported components, attack: T1592.002, owasp: "MASVS-PLATFORM-1", cwe: CWE-926, risk: safe,
     command: "# review AndroidManifest.xml: exported activities/services/receivers/providers, permissions, debuggable, allowBackup (Info.plist / entitlements on iOS)",
     purpose: "Enumerate the app's attack surface and dangerous flags."}
  - {name: Insecure data storage, attack: T1005, owasp: "MASVS-STORAGE-1", cwe: CWE-312, risk: safe,
     command: "# inspect shared_prefs / sqlite / files / Keychain for cleartext PII or credentials",
     purpose: "Test for sensitive data stored in the clear."}
  - {name: Cryptography, attack: T1600, owasp: "MASVS-CRYPTO-1", cwe: CWE-327, risk: safe,
     command: "# review crypto use: hardcoded keys, ECB, weak/deprecated algorithms, static IVs",
     purpose: "Test for weak or misused cryptography."}
  - {name: Network security / TLS pinning, attack: T1557, owasp: "MASVS-NETWORK-1", cwe: CWE-295, risk: safe,
     command: "# check cleartext traffic (usesCleartextTraffic/ATS), cert & hostname validation, pinning",
     purpose: "Test transport security and certificate validation."}
  - {name: Authentication & session, attack: T1078, owasp: "MASVS-AUTH-1", cwe: CWE-287, risk: safe,
     command: "# review auth flows, token storage, and local/biometric-auth bypass",
     purpose: "Test authentication and session handling."}
  - {name: Platform interaction / IPC, attack: T1190, owasp: "MASVS-PLATFORM-2", cwe: CWE-927, risk: safe,
     command: "# test exported components, deep links, and WebView (JS bridge / file access)",
     purpose: "Test IPC, deep links and WebView exposure."}
  - {name: Anti-tamper / RASP, attack: T1622, owasp: "MASVS-RESILIENCE-1", cwe: CWE-693, risk: safe,
     command: "# assess root/jailbreak detection, debugger/emulator checks, obfuscation",
     purpose: "Review resilience controls (informational for most engagements)."}
  - {name: Dynamic instrumentation, attack: T1055, owasp: "MASVS-RESILIENCE-2", cwe: CWE-489, risk: intrusive,
     command: "# authorized only: frida/objection to hook runtime, bypass pinning/root, dump secrets",
     purpose: "Run-time analysis: hook, bypass controls, dump secrets (on a test device)."}
  - {name: Backend API surface, attack: T1590, owasp: "MASVS-NETWORK-2", cwe: CWE-200, risk: safe,
     command: "# extract the API endpoints/keys the app uses, then assess them with:  assess --api <url>",
     purpose: "Pivot to the app's backend API (feeds the api module)."}
```
