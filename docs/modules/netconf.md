# NETCONF Module

NETCONF (TCP 830) methodology — SSH-subsystem network-device management. A valid
credential yields full device configuration read/write.

```yaml
module: netconf
title: NETCONF
scope: port
matches: [netconf]
summary: "NETCONF management service ({prod})."
finding_keywords: [netconf, yang]
techniques_extra: [T1078]
attack_surface:
  - { when: "always", note: "NETCONF exposes full device config (get-config/edit-config) to an authenticated client — restrict to the management plane." }
checks:
  - { name: Service detection, attack: T1046, command: "nmap -p830 -sV --script ssh2-enum-algos {ip}", purpose: "Confirm NETCONF-over-SSH and the host-key/algorithms." }
  - { name: Hello / capabilities, attack: T1592.004, command: "ssh -p 830 -s {ip} netconf", purpose: "Read the NETCONF <hello> and advertised YANG capabilities/vendor." }
  - { name: Credential test, attack: T1110.003, command: "hydra -L users.txt -P passwords.txt ssh://{ip}:830 -f", purpose: "Authorized testing for weak management credentials (mind lockout)." }
  - { name: Config read, attack: T1602.002, command: "# authenticated: <get-config><source><running/></source></get-config>", purpose: "Retrieve the running config once authenticated (configs leak credentials)." }
```
