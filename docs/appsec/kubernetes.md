# Kubernetes Module (ATT&CK Containers)

**AppSec pillar — target-driven.** Assesses a Kubernetes target (cluster endpoint /
kubeconfig / context) against the MITRE **ATT&CK Containers** matrix. Checks are
ATT&CK + CWE-mapped with a `safe|intrusive` risk tag: external recon, RBAC/secret/CIS
review are safe; container escape and attacker-pod scheduling are intrusive
(VAPT-hidden).

Targets come from `assess --k8s <cluster|kubeconfig|context>`. Tooling: kube-hunter,
kube-bench, kubeaudit, kubeletctl, kubectl, rbac-tool, kubectl-who-can, trivy,
peirates, botb, cosign.

**Boundary:** methodology + staging only — the operator runs these with their own
cluster credentials, in scope. **Cross-layer:** a pod pivots to node cloud metadata
(IMDS, T1552.005), tying into the cloud module.

```yaml
module: k8s
title: Kubernetes (ATT&CK Containers)
scope: target
matches: [k8s, kubernetes, kube]
summary: "Kubernetes cluster assessment (ATT&CK Containers)."
techniques_extra: []
checks:
  - {name: External cluster recon, attack: T1595, owasp: "", cwe: CWE-200, risk: safe, when: always,
     command: "kube-hunter --remote {cluster}   # or: nmap -p6443,10250,10255,2379,8001 {cluster}",
     purpose: "Find exposed API server, kubelet, etcd and dashboard."}
  - {name: Kubelet anonymous access, attack: T1613, owasp: "", cwe: CWE-306, risk: safe, when: always,
     command: "kubeletctl -s {cluster} pods   # anonymous kubelet 10250/10255 enumeration",
     purpose: "Enumerate pods/containers via an exposed kubelet."}
  - {name: API server anonymous access, attack: T1078, owasp: "", cwe: CWE-287, risk: safe, when: always,
     command: "kubectl --insecure-skip-tls-verify -s https://{cluster}:6443 get pods -A   # test anon / system-unauth",
     purpose: "Test unauthenticated Kubernetes API access."}
  - {name: CIS benchmark, attack: T1526, owasp: "", cwe: CWE-1188, risk: safe, when: always,
     command: "kube-bench run   # node + master CIS hardening",
     purpose: "Assess cluster hardening against CIS."}
  - {name: RBAC / privilege audit, attack: T1069, owasp: "", cwe: CWE-269, risk: safe, when: always,
     command: "kubectl auth can-i --list; rbac-tool analysis; kubectl-who-can create pods",
     purpose: "Map over-permissive roles and privilege paths."}
  - {name: Cluster secrets & SA tokens, attack: T1552.007, owasp: "", cwe: CWE-522, risk: safe, when: always,
     command: "kubectl get secrets -A -o yaml   # + check SA-token automount, configmaps/env for creds",
     purpose: "Recover Kubernetes secrets and service-account tokens."}
  - {name: Workload misconfiguration, attack: T1610, owasp: "", cwe: CWE-16, risk: safe, when: always,
     command: "kubeaudit all; trivy k8s cluster   # privileged / hostPID / hostPath / hostNetwork pods",
     purpose: "Find privileged and breakout-prone workloads."}
  - {name: Pod to node escape, attack: T1611, owasp: "", cwe: CWE-269, risk: intrusive, when: always,
     command: "# authorized: from a privileged pod - botb / nsenter host mount / abuse hostPath",
     purpose: "Test container-to-host escape."}
  - {name: Attacker pod scheduling, attack: T1610, owasp: "", cwe: CWE-284, risk: intrusive, when: always,
     command: "# authorized: kubectl run with hostPID/privileged to reach the node (peirates automates)",
     purpose: "Test ability to schedule a breakout pod."}
  - {name: Image provenance & CVEs, attack: T1525, owasp: "", cwe: CWE-494, risk: safe, when: always,
     command: "trivy image <image>   # verify signing (cosign); check for implanted/backdoored images",
     purpose: "Assess image provenance and vulnerabilities."}
  - {name: etcd exposure, attack: T1552, owasp: "", cwe: CWE-306, risk: safe, when: always,
     command: "# test etcd 2379 for unauthenticated read (etcdctl get / --prefix) -> all secrets",
     purpose: "Test etcd for unauthenticated access."}
  - {name: Cloud metadata from pod, attack: T1552.005, owasp: "", cwe: CWE-918, risk: intrusive, when: always,
     command: "# from a pod: curl http://169.254.169.254/ for node IAM credentials (IMDS)",
     purpose: "Pivot to cloud credentials via node metadata."}
```
