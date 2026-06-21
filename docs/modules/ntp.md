# NTP Module

NTP methodology (123/udp). Legacy NTP (monlist) leaks recent client IPs and
enables large DDoS amplification.

```yaml
module: ntp
title: NTP
scope: port
matches: [ntp]
summary: "NTP service ({prod})."
finding_keywords: [ntp, monlist]
techniques_extra: [T1590]
attack_surface:
  - { when: "always", note: "Legacy NTP (monlist) leaks recent client IPs and enables large DDoS amplification — patch/disable mode 7." }
checks:
  - { name: Version & sysinfo, attack: T1592.002, command: "ntpq -c rv {ip}", purpose: "Read NTP version, OS and system variables." }
  - { name: monlist, attack: T1590, command: "ntpdc -n -c monlist {ip}", purpose: "Test monlist (CVE-2013-5211): client-IP disclosure and amplification." }
  - { name: NSE info, attack: T1046, command: "nmap -sU -p{port} --script ntp-info,ntp-monlist {ip}", purpose: "Enumerate NTP info and amplification vectors." }
  - { name: Peer enumeration, attack: T1590, command: "ntpq -p {ip}", purpose: "List configured peers/upstreams (topology disclosure)." }
```
