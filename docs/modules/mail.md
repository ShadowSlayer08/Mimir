# Mail Module

SMTP / IMAP / POP3 methodology. One assessment per mail port. `{disp}` resolves
the protocol name from `labels`. Covers relay, user enumeration, STARTTLS and
authorized credential testing.

```yaml
module: mail
title: Mail (SMTP/IMAP/POP3)
scope: port
matches: [smtp, smtps, submission, imap, imaps, pop3, pop3s]
tls_ports: [465, 993, 995]
summary: "{disp} service ({prod})."
finding_keywords: [smtp, imap, pop3, open relay, starttls]
labels:
  smtp: SMTP
  smtps: SMTPS
  submission: SMTP Submission
  imap: IMAP
  imaps: IMAPS
  pop3: POP3
  pop3s: POP3S
techniques_extra: [T1114]
attack_surface:
  - { when: "not tls", note: "Cleartext mail protocol — enforce STARTTLS/implicit TLS to protect credentials." }
  - { when: "has_cve", note: "Mail daemon version has known CVEs (see findings)." }
checks:
  - { name: Banner & commands, attack: T1592.002, command: "nmap -p{port} -sV --script smtp-commands,banner {ip}", purpose: "Identify the MTA/MDA, supported verbs and STARTTLS advertisement." }
  - { name: Open relay test, attack: T1590, command: "nmap -p{port} --script smtp-open-relay {ip}", purpose: "Detect whether the server relays mail for arbitrary senders." }
  - { name: User enumeration, attack: T1087.003, command: "smtp-user-enum -M VRFY -U users.txt -t {ip} -p {port}", purpose: "Enumerate valid mailboxes via VRFY/EXPN/RCPT." }
  - { name: STARTTLS posture, attack: T1595, command: "openssl s_client -starttls smtp -connect {ip}:{port}", purpose: "Verify STARTTLS support and inspect the certificate." }
  - { name: TLS posture, attack: T1595, when: tls, command: "sslscan {ip}:{port}", purpose: "For implicit-TLS ports (465/993/995), enumerate protocols/ciphers/cert." }
  - { name: Credential test, attack: T1110.003, command: "hydra -L users.txt -P passwords.txt -s {port} {ip} <smtp|imap|pop3>   # add -S for implicit-TLS (465/993/995)", purpose: "Authorized testing for weak mailbox credentials with the matching hydra module (mind lockout)." }
  - { name: Mailbox access, attack: T1114, command: "# after auth: enumerate folders/messages in scope (IMAP/POP3 client)", purpose: "Gauge data exposure once authenticated." }
```
