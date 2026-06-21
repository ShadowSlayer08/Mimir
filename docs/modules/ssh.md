# SSH Module

OpenSSH/Dropbear methodology. One assessment per SSH port: enumerate version,
algorithms and auth methods, then test for weak/reused credentials and keys.

```yaml
module: ssh
title: SSH
scope: port
matches: [ssh]
summary: "SSH service ({prod})."
finding_keywords: [ssh, openssh, dropbear]
attack_surface:
  - { when: "has_cve", note: "SSH daemon version has known CVEs (see findings)." }
  - { when: "always", note: "Authentication endpoint — enumerate auth methods and test for weak/reused credentials and keys (mind lockout)." }
techniques_extra: [T1021.004]
checks:
  - { name: Version & algorithms, attack: T1046, command: "nmap -p{port} -sV --script ssh2-enum-algos,ssh-hostkey {ip}", purpose: "Identify version, KEX/cipher/MAC algorithms and host keys; flag legacy/weak crypto." }
  - { name: Auth methods, attack: T1592.004, command: "ssh -o PreferredAuthentications=none -o BatchMode=yes {ip} -p {port}", purpose: "List accepted authentication methods (password vs key vs keyboard-interactive)." }
  - { name: Host key harvest, attack: T1590, command: "ssh-keyscan -p {port} {ip}", purpose: "Record host keys to detect shared/known keys across hosts." }
  - { name: Config audit, attack: T1552.004, command: "ssh-audit {ip}:{port}", purpose: "Audit for weak host keys, deprecated algorithms and insecure configuration." }
  - { name: User enumeration, attack: T1087, command: "nmap -p{port} --script ssh-auth-methods --script-args 'ssh.user=root' {ip}", purpose: "Probe username validity (e.g. CVE-2018-15473 timing) before any spraying." }
  - { name: Credential test, attack: T1110.003, command: "hydra -L users.txt -P passwords.txt ssh://{ip}:{port} -t 4 -f", purpose: "Authorized password spraying for weak/default credentials (throttle; mind lockout)." }
  - { name: Key-based access, attack: T1021.004, command: "ssh -i <recovered_key> -p {port} <user>@{ip}", purpose: "Validate access with any recovered private keys (authorized)." }
```
