# Open Proxy Module

Proxy methodology (SOCKS 1080 and friends). An open/unauthenticated proxy
enables anonymisation and pivoting into internal networks.

```yaml
module: proxy
title: Open Proxy
scope: port
matches: [socks, socks5, socks4]
summary: "Proxy service ({frag})."
finding_keywords: [socks, proxy]
unauth_services: [socks, socks5, socks4]
techniques_extra: [T1090]
attack_surface:
  - { when: "unauth", note: "An open/unauthenticated proxy enables anonymisation and pivoting into internal networks — require authentication and ACLs." }
checks:
  - { name: Open relay test, attack: T1090, command: "curl -sx socks5://{ip}:{port} http://example.com", purpose: "Test whether the proxy relays to external hosts unauthenticated." }
  - { name: Internal pivot, attack: T1572, command: "curl -sx socks5://{ip}:{port} http://<internal-ip>/", purpose: "Check reachability of internal hosts through the proxy (authorized)." }
  - { name: Auth requirement, attack: T1592, command: "nmap -p{port} --script socks-auth-info,socks-open-proxy {ip}", purpose: "Determine the SOCKS version and whether authentication is enforced." }
  - { name: Proxy fingerprint, attack: T1592.002, command: "nmap -p{port} -sV {ip}", purpose: "Identify the proxy software and version." }
```
