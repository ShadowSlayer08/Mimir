# RDP Module

Remote Desktop Protocol assessment methodology. One assessment per RDP port
(default 3389). Covers NLA enforcement, encryption level / certificate, BlueKeep
(CVE-2019-0708) **detection only**, and authorized credential testing. RDP is a
prime lateral-movement landing point (`T1021.001`); `{auth_cmd}` is the
operator's authenticated connect reference.

```yaml
module: rdp
title: RDP
scope: port
matches: [ms-wbt-server, rdp]
summary: "RDP exposed on {port} ({prod} {ver})."
finding_keywords: [rdp, ms-wbt-server, bluekeep, cve-2019-0708, nla, ms12-020]
finding_categories: [Remote Access, "Vuln scan"]
connect:
  ms-wbt-server: "xfreerdp /v:{ip}:{port} /u:<user> /p:<pass> /cert:ignore +clipboard"
  rdp: "xfreerdp /v:{ip}:{port} /u:<user> /p:<pass> /cert:ignore +clipboard"
techniques_extra: [T1021.001]
attack_surface:
  - when: "always"
    note: "RDP reachable — valid credentials grant interactive access and a lateral-movement foothold (T1021.001)."
  - when: "has_cve"
    note: "Reported version has known CVEs (e.g. BlueKeep CVE-2019-0708 / MS12-020) — confirm via scanner before any operator action."
checks:
  - {name: Service / version fingerprint, attack: T1592.004, command: "nmap -p{port} -sV --script rdp-ntlm-info {ip}",
     purpose: "Confirm RDP, product/build, and leak hostname/domain/OS via the NTLM challenge."}
  - {name: Encryption & NLA enforcement, attack: T1592.004, command: "nmap -p{port} --script rdp-enum-encryption {ip}",
     purpose: "Enumerate supported security layers (RDP/TLS/CredSSP) and whether NLA is required."}
  - {name: NLA check (impacket), attack: T1595.002, command: "rdp_check.py <domain>/<user>:<pass>@{ip}",
     purpose: "Test whether Network Level Authentication is enforced and validate a credential at the protocol layer."}
  - {name: Certificate review, attack: T1592.004, command: "openssl s_client -connect {ip}:{port} -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates",
     purpose: "Inspect the RDP TLS certificate for self-signed / expired / weak-key issues enabling MITM."}
  - {name: BlueKeep detection (scanner only), attack: T1595.002, command: "rdpscan {ip}:{port}",
     purpose: "Detect CVE-2019-0708 (BlueKeep). nmap ships no official NSE for it; rdpscan is detection-only (alt: msf auxiliary/scanner/rdp/cve_2019_0708_bluekeep). Do NOT run the exploit."}
  - {name: MS12-020 detection, attack: T1595.002, command: "nmap -p{port} -sV --script rdp-vuln-ms12-020 {ip}",
     purpose: "Check for the MS12-020 RDP pre-auth DoS/UAF vulnerability (detection only)."}
  - {name: Credential test (crowbar), attack: T1110.001, command: "crowbar -b rdp -s {ip}/32 -p {port} -U users.txt -C passwords.txt",
     purpose: "Authorized password testing against RDP (mind account lockout policy)."}
  - {name: Credential spray (hydra), attack: T1110.003, command: "hydra -L users.txt -P passwords.txt -t 1 -f rdp://{ip}:{port}",
     purpose: "Single-threaded authorized spray; one attempt at a time to respect lockout."}
  - {name: Authenticated connect, attack: T1021.001, command: "{auth_cmd}",
     purpose: "Establish an authorized interactive session with validated credentials."}
```
