# WinRM Module

WinRM / WSMan methodology (5985 plaintext, 5986 TLS). A valid credential over
WinRM yields remote PowerShell execution — a prime lateral-movement target.

```yaml
module: winrm
title: WinRM
scope: port
matches: [winrm, wsman]
tls_ports: [5986]
summary: "WinRM/WSMan service ({prod})."
finding_keywords: [winrm, wsman, powershell remoting]
techniques_extra: [T1021.006]
attack_surface:
  - { when: "always", note: "WinRM enables remote PowerShell — a reused/valid credential yields code execution; restrict and monitor." }
  - { when: "tls", note: "WinRM over HTTPS (5986) — review the TLS certificate." }
checks:
  - { name: Service detection, attack: T1046, command: "nmap -p{port} -sV --script http-ntlm-info --script-args http-ntlm-info.root=/wsman {ip}", purpose: "Confirm WinRM (Microsoft HTTPAPI on 5985/5986) and leak hostname/domain via the NTLM type-2 message on /wsman." }
  - { name: Auth methods, attack: T1592.004, command: "curl -sk {scheme}://{ip}:{port}/wsman -X POST", purpose: "Identify supported authentication (Negotiate/Kerberos/Basic)." }
  - { name: Credential validation, attack: T1110.003, command: "crackmapexec winrm {ip} -u users.txt -p passwords.txt", purpose: "Authorized validation of credentials over WinRM (mind lockout)." }
  - { name: Authenticated shell, attack: T1021.006, command: "evil-winrm -i {ip} -u <user> -p <pass>", purpose: "Validate remote PowerShell access with tested credentials (authorized)." }
  - { name: Command exec check, attack: T1059.001, command: "crackmapexec winrm {ip} -u <user> -p <pass> -x 'whoami'", purpose: "Confirm command execution and the resulting privilege level." }
```
