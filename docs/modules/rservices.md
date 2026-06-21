# Berkeley r-services Module

rexec (512), rsh/shell (514) and rlogin/login (513) methodology. These use
cleartext and `.rhosts` / `hosts.equiv` host-trust authentication.

```yaml
module: rservices
title: Berkeley r-services
scope: port
matches: [rlogin, rsh, exec, shell, login, klogin, kshell]
summary: "Berkeley r-service ({frag}) — cleartext, host-trust auth."
finding_keywords: [rlogin, rsh, rexec, r-service, rhosts]
techniques_extra: [T1021]
attack_surface:
  - { when: "always", note: "r-services use cleartext and .rhosts/hosts.equiv host-trust — disable in favour of SSH." }
checks:
  - { name: Service enumeration, attack: T1046, command: "nmap -p{port} -sV {ip}", purpose: "Confirm rexec(512)/rsh(514)/rlogin(513) and read banners." }
  - { name: Trusted-host access, attack: T1078, command: "rlogin {ip} -l root", purpose: "Test passwordless access via host-trust relationships (authorized)." }
  - { name: Remote command (rsh), attack: T1021, command: "rsh {ip} -l <user> id", purpose: "Validate trust-based remote command execution." }
  - { name: rexec auth, attack: T1110, command: "# rexec with tested credentials, in scope", purpose: "Test credential acceptance on the rexec service." }
  - { name: On-path capture, attack: T1040, command: "# authorized capture: tcpdump -i <iface> host {ip}", purpose: "Show cleartext credential exposure on the wire." }
```
