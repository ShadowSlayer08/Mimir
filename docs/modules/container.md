# Container / Orchestration Module

Container and orchestration assessment methodology. One assessment per matching
open port. Covers the Docker Engine API (2375/2376), the Kubernetes API server
(6443/8443), the kubelet read/exec API (10250) and etcd (2379). The central risk
is **unauthenticated API access**: a reachable Docker socket, an anonymous-RBAC
Kubernetes API, an open kubelet `/run` endpoint, or an unauth etcd keyspace each
yields host or full-cluster takeover. `{disp}` resolves from the `labels` map and
`{auth_cmd}` from the `connect` map; services in `unauth_services` are flagged as
frequently exposed without authentication.

```yaml
module: container
title: Container / Orchestration
scope: port
matches: [docker, kubernetes, kubelet, etcd]
summary: "{disp} API reachable {ver} — unauth access risks host/cluster takeover."
tls_ports: [2376, 6443, 8443, 10250, 2379]
finding_keywords: [docker, kubernetes, kubelet, etcd, container, kube-apiserver, anonymous]
finding_categories: [Container]
labels:
  docker: Docker Engine API
  kubernetes: Kubernetes API server
  kubelet: kubelet API
  etcd: etcd
connect:
  docker: "docker -H {scheme}://{ip}:{port} info"
  kubernetes: "kubectl --server={scheme}://{ip}:{port} --insecure-skip-tls-verify get pods -A"
  kubelet: "kubeletctl -s {ip} pods"
  etcd: "etcdctl --endpoints={scheme}://{ip}:{port} get / --prefix --keys-only"
unauth_services: [docker, kubernetes, kubelet, etcd]
techniques_extra: [T1610, T1613, T1552.007]
attack_surface:
  - when: "unauth"
    note: "{disp} is frequently exposed without authentication — test anonymous/unauth access before anything else."
  - when: "not tls"
    note: "Plaintext API ({scheme}) — Docker 2375 / etcd 2379 with no TLS means no mutual auth; full control if reachable."
  - when: "tls"
    note: "TLS endpoint — anonymous RBAC or missing client-cert verification can still grant access; review cert/auth findings."
  - when: "has_cve"
    note: "Platform version has known CVEs (see findings)."
checks:
  - {name: Connectivity / unauth test, attack: T1613, command: "{auth_cmd}",
     purpose: "Confirm reachability and whether the API answers without credentials."}
  - {name: Fingerprint version,        attack: T1592, command: "nmap -p{port} -sV --script vulners {ip}",
     purpose: "Confirm platform/version and cross-reference CVEs."}
  - {name: Docker API enumeration,     attack: T1613, when: unauth, command: "curl -sk {scheme}://{ip}:{port}/version; curl -sk {scheme}://{ip}:{port}/containers/json",
     purpose: "Read engine version and list running containers via the unauth Docker socket."}
  - {name: K8s anonymous API access,   attack: T1613, command: "curl -sk {scheme}://{ip}:{port}/api/v1/namespaces; kubectl --server={scheme}://{ip}:{port} --insecure-skip-tls-verify auth can-i --list",
     purpose: "Test anonymous binding and enumerate what the anonymous/unauth identity is permitted to do."}
  - {name: kubelet pod/exec surface,   attack: T1613, when: unauth, command: "kubeletctl -s {ip} scan rce; kubeletctl -s {ip} pods",
     purpose: "Enumerate pods reachable through the kubelet read/exec API on 10250."}
  - {name: etcd secret extraction,     attack: T1552.007, command: "etcdctl --endpoints={scheme}://{ip}:{port} get /registry/secrets --prefix --keys-only",
     purpose: "Dump cluster keyspace; etcd stores Kubernetes Secrets and service-account tokens in the clear."}
  - {name: Service-account token loot, attack: T1552.007, command: "# from an enumerated pod: read /var/run/secrets/kubernetes.io/serviceaccount/token (in authorized scope)",
     purpose: "Recover mounted service-account tokens to assess privilege escalation in-cluster."}
  - {name: Client-cert / auth test,    attack: T1110, command: "nmap -p{port} --script ssl-cert {ip}; curl -sk {scheme}://{ip}:{port}/healthz -i",
     purpose: "Inspect TLS client-auth requirement and probe for missing authn (authorized; mind lockout)."}
```
