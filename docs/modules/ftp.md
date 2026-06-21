# FTP Module

FTP methodology. One assessment per FTP port: test anonymous access, banner/CVEs,
bounce, writable paths, and (for ftps) TLS posture.

```yaml
module: ftp
title: FTP
scope: port
matches: [ftp, ftps, ftp-data]
tls_ports: [990]
summary: "FTP service ({prod})."
finding_keywords: [ftp, anonymous, vsftpd, proftpd, filezilla]
techniques_extra: [T1078]
attack_surface:
  - { when: "not tls", note: "FTP is cleartext — credentials and data are exposed on-path; prefer SFTP/FTPS." }
  - { when: "has_cve", note: "FTP daemon version has known CVEs (see findings)." }
checks:
  - { name: Anonymous login, attack: T1078, command: "nmap -p{port} --script ftp-anon {ip}", purpose: "Test for anonymous FTP access and list readable content." }
  - { name: Banner & version, attack: T1592.002, command: "nmap -p{port} -sV --script ftp-syst {ip}", purpose: "Identify the FTP daemon and OS for CVE cross-referencing." }
  - { name: FTP bounce, attack: T1090, command: "nmap -p{port} --script ftp-bounce {ip}", purpose: "Detect FTP bounce (PORT) proxying that could reach internal hosts." }
  - { name: Manual enumeration, attack: T1083, command: "ftp {ip} {port}", purpose: "List directories, check writable paths and upload restrictions (authorized)." }
  - { name: Credential test, attack: T1110.003, command: "hydra -L users.txt -P passwords.txt ftp://{ip}:{port} -f", purpose: "Authorized testing for weak/default credentials (mind lockout)." }
  - { name: TLS posture, attack: T1595, when: tls, command: "sslscan {ip}:{port}", purpose: "For FTPS, enumerate TLS protocols/ciphers/certificate." }
```
