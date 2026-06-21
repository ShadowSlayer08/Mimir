# Abuse Info

Per-technique exploitation insight — the BloodHound-style "how would an operator
abuse this edge" guidance attached to every staged attack-path step. Keyed by
MITRE ATT&CK id (sub-techniques fall back to their base technique).

Each entry is **guidance for a human operator**: what the step gives you
(`impact`), how it's typically abused with the operator's own tooling (`how`),
and the detection/safety caveats (`opsec`). The engine surfaces this; it runs
nothing and ships no payloads.

```yaml
abuse_info:
  T1190:
    name: Exploit Public-Facing Application
    impact: "A confirmed exploitable exposure yields an initial foothold / RCE on the host."
    how: "Validate the condition detection-only first (vuln NSE / scanner), then run YOUR exploit for that exact CVE/version in scope."
    opsec: "Exploitation can crash the service — confirm a maintenance window and that the target is in scope."
  T1210:
    name: Exploitation of Remote Services
    impact: "A vulnerable network service (e.g. SMB MS17-010) gives unauthenticated code execution, often as SYSTEM/root."
    how: "Confirm VULNERABLE state, then run the matching exploit from your framework against the validated target."
    opsec: "Memory-corruption exploits (EternalBlue) can BSOD hosts — treat production with extreme care."
  T1078:
    name: Valid Accounts
    impact: "Reused or recovered credentials grant authenticated access with no exploit needed."
    how: "Spray validated creds across reachable services (netexec smb/winrm/ssh ...); look for local-admin reuse across hosts."
    opsec: "Spraying risks lockout — read the password policy first (T1201) and throttle attempts."
  T1068:
    name: Exploitation for Privilege Escalation
    impact: "A local flaw escalates a foothold to SYSTEM/root."
    how: "Enumerate first (linpeas/winPEAS, sudo -l, SUID, unquoted-service-paths), then run the specific privesc you confirmed."
    opsec: "Kernel exploits can panic the host; prefer misconfig-based escalation where available."
  T1003:
    name: OS Credential Dumping
    impact: "Local credential material (hashes/tickets) for lateral movement and escalation."
    how: "From SYSTEM/root, dump SAM/LSASS/lsa secrets (your post-ex tooling) or /etc/shadow; crack offline or pass-the-hash."
    opsec: "LSASS access is heavily monitored by EDR — expect detection; coordinate with the client."
  T1003.006:
    name: DCSync
    impact: "Replication rights (GetChanges/GetChangesAll) let you pull ANY account's hash, including krbtgt → golden ticket / full domain."
    how: "secretsdump.py -just-dc <domain>/<user>:<pass>@<dc>  (target krbtgt + privileged accounts)."
    opsec: "DCSync from a non-DC is a strong detection signal; dumping krbtgt is high-impact — get explicit sign-off."
  T1482:
    name: Domain Trust Discovery
    impact: "Maps trusts and privilege paths to high-value targets (Domain Admins, krbtgt)."
    how: "bloodhound-python -c All; in BloodHound run 'Shortest paths to Domain Admins' and review each edge's abuse info."
    opsec: "Collection is noisy (LDAP/SMB to every host) — pace it; consider targeted collection methods."
  T1558.003:
    name: Kerberoasting
    impact: "Service accounts with SPNs let you request TGS tickets that crack offline to the service-account password."
    how: "GetUserSPNs.py <domain>/<user>:<pass> -request -outputfile spns.txt ; hashcat -m 13100 spns.txt wordlist."
    opsec: "Bulk SPN requests trigger event 4769 — request specific high-value SPNs rather than all."
  T1558.004:
    name: AS-REP Roasting
    impact: "Accounts without Kerberos pre-auth let you grab a crackable AS-REP without any credentials."
    how: "GetNPUsers.py <domain>/ -usersfile users.txt -no-pass -format hashcat ; crack with hashcat -m 18200."
    opsec: "Low-noise discovery, but cracking is offline — value depends on password strength."
  T1021:
    name: Remote Services
    impact: "Valid credentials give an authenticated foothold on the remote host."
    how: "Authenticate to the service with validated creds (netexec / the native client); reuse across hosts."
    opsec: "Remote logons are logged — choose the quietest exec method the service allows."
  T1021.001:
    name: "Remote Services: RDP"
    impact: "Valid creds give an interactive desktop and a foothold on the target."
    how: "xfreerdp /v:<ip> /u:<user> /p:<pass> ; or pass-the-hash where Restricted Admin is enabled."
    opsec: "Interactive logons are logged (4624 type 10); leaves session artifacts."
  T1021.002:
    name: "Remote Services: SMB/Admin Shares"
    impact: "Valid creds + local admin on the target give remote code execution over SMB."
    how: "netexec smb <ip> -u <user> -p <pass> -x 'whoami' ; or wmiexec/atexec/smbexec for a shell."
    opsec: "psexec-style service creation is noisy — prefer wmiexec/atexec; watch for EDR on 445."
  T1021.004:
    name: "Remote Services: SSH"
    impact: "Valid creds or a recovered key give a shell on the target."
    how: "ssh -i <key> <user>@<ip> ; reuse recovered keys/passphrases across hosts."
    opsec: "Logged in auth.log; key reuse across hosts is a common, quiet pivot."
  T1021.006:
    name: "Remote Services: WinRM"
    impact: "Valid creds give remote PowerShell execution."
    how: "evil-winrm -i <ip> -u <user> -p <pass> ; or netexec winrm for validation/spray."
    opsec: "PowerShell remoting is logged (4103/4104 if ScriptBlock logging is on)."
  T1552:
    name: Unsecured Credentials
    impact: "Exposed credential material (configs, hashes, keys, BMC RAKP) for direct access or cracking."
    how: "Harvest from the exposed source, then reuse/crack and test against reachable services (T1078)."
    opsec: "Treat recovered creds as in-scope-only; do not pivot outside the engagement."
  T1040:
    name: Network Sniffing
    impact: "Cleartext protocols on-path leak credentials and session data."
    how: "With an authorized on-path position, capture (tcpdump) and extract creds from cleartext sessions."
    opsec: "Requires a network position; passive — low detection risk."
  T1557:
    name: Adversary-in-the-Middle
    impact: "Coercion/relay (e.g. NTLM) can capture or relay authentication to reachable services."
    how: "responder + ntlmrelayx against hosts without SMB signing (validate signing first)."
    opsec: "Poisoning is intrusive and broad — scope tightly and time-box it."
  T1135:
    name: Network Share Discovery
    impact: "Readable/writable shares (SMB/NFS/AFP/rsync) expose data and sometimes write-to-exec paths."
    how: "Enumerate and mount in scope; inventory for credentials, configs and writable locations."
    opsec: "Read-only enumeration is quiet; writing to shares is not — log any change."
  T1213:
    name: Data from Information Repositories
    impact: "Network-reachable datastores (DBs, wikis, repos) hold high-value data and secrets."
    how: "Authenticate (or anon), then inventory databases/indices/keys for impact assessment."
    opsec: "Read in scope only; do not exfiltrate real data without written authorization."
  T1602:
    name: Network Device Config Dump
    impact: "Device configs (via SNMP/TFTP/SMI) leak credentials, SNMP communities and topology."
    how: "Pull the config over the exposed channel; extract secrets and reuse them (T1078)."
    opsec: "Config retrieval is largely passive; the leaked creds are the real impact."
```
