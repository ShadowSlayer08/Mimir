#!/usr/bin/env python3
"""modules.kubernetes — Kubernetes cluster methodology (target-driven).

Authorized / lab / CTF use only.

Assesses a KUBERNETES target (a cluster endpoint / kubeconfig / context) using the
MITRE **ATT&CK Containers** matrix. Checks are ATT&CK + CWE-mapped with a
`safe|intrusive` risk tag: external recon, RBAC/secret/CIS review are safe; container
escape and attacker-pod scheduling are intrusive (VAPT-hidden). Methodology + STAGING
only; the engine runs nothing.

Tooling: kube-hunter, kube-bench, kubeaudit, kubeletctl, kubectl, rbac-tool,
kubectl-who-can, trivy, peirates, botb, cosign.

Checks load from docs/appsec/kubernetes.md (`module: k8s`) when present, else built-in.
Placeholders: {cluster} {context}.
"""
from __future__ import annotations

import string

from .base import Check, ModuleResult, worst

_A = "always"
# (name, attack, owasp, cwe, risk, when, command, purpose)
BUILTIN_CHECKS = [
    ("External cluster recon", "T1595", "", "CWE-200", "safe", _A,
     "kube-hunter --remote {cluster}   # or: nmap -p6443,10250,10255,2379,8001 {cluster}",
     "Find exposed API server, kubelet, etcd and dashboard."),
    ("Kubelet anonymous access", "T1613", "", "CWE-306", "safe", _A,
     "kubeletctl -s {cluster} pods   # anonymous kubelet 10250/10255 enumeration",
     "Enumerate pods/containers via an exposed kubelet."),
    ("API server anonymous access", "T1078", "", "CWE-287", "safe", _A,
     "kubectl --insecure-skip-tls-verify -s https://{cluster}:6443 get pods -A   # test anon / system:unauth",
     "Test unauthenticated Kubernetes API access."),
    ("CIS benchmark", "T1526", "", "CWE-1188", "safe", _A,
     "kube-bench run   # node + master CIS hardening",
     "Assess cluster hardening against CIS."),
    ("RBAC / privilege audit", "T1069", "", "CWE-269", "safe", _A,
     "kubectl auth can-i --list; rbac-tool analysis; kubectl-who-can create pods",
     "Map over-permissive roles and privilege paths."),
    ("Cluster secrets & SA tokens", "T1552.007", "", "CWE-522", "safe", _A,
     "kubectl get secrets -A -o yaml   # + check SA-token automount, configmaps/env for creds",
     "Recover Kubernetes secrets and service-account tokens."),
    ("Workload misconfiguration", "T1610", "", "CWE-16", "safe", _A,
     "kubeaudit all; trivy k8s cluster   # privileged / hostPID / hostPath / hostNetwork pods",
     "Find privileged and breakout-prone workloads."),
    ("Pod to node escape", "T1611", "", "CWE-269", "intrusive", _A,
     "# authorized: from a privileged pod - botb / nsenter host mount / abuse hostPath",
     "Test container-to-host escape."),
    ("Attacker pod scheduling", "T1610", "", "CWE-284", "intrusive", _A,
     "# authorized: kubectl run with hostPID/privileged to reach the node (peirates automates)",
     "Test ability to schedule a breakout pod."),
    ("Image provenance & CVEs", "T1525", "", "CWE-494", "safe", _A,
     "trivy image <image>   # verify signing (cosign); check for implanted/backdoored images",
     "Assess image provenance and vulnerabilities."),
    ("etcd exposure", "T1552", "", "CWE-306", "safe", _A,
     "# test etcd 2379 for unauthenticated read (etcdctl get / --prefix) -> all secrets",
     "Test etcd for unauthenticated access."),
    ("Cloud metadata from pod", "T1552.005", "", "CWE-918", "intrusive", _A,
     "# from a pod: curl http://169.254.169.254/ for node IAM credentials (IMDS)",
     "Pivot to cloud credentials via node metadata."),
]


class _SafeDict(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(s, ctx):
    return string.Formatter().vformat(s or "", (), _SafeDict(ctx))


class KubernetesModule:
    name = "k8s"
    title = "Kubernetes (ATT&CK Containers)"

    def __init__(self, docs_dir=None):
        try:
            from knowledge_loader import load_knowledge
            self._mdef = load_knowledge(docs_dir).modules.get("k8s")
        except Exception:                                              # pragma: no cover
            self._mdef = None

    def _checks(self):
        if self._mdef and self._mdef.get("checks"):
            return self._mdef["checks"]
        return [{"name": n, "attack": a, "owasp": o, "cwe": w, "risk": rk,
                 "when": wh, "command": cmd, "purpose": pp}
                for (n, a, o, w, rk, wh, cmd, pp) in BUILTIN_CHECKS]

    def assess_target(self, target, findings):
        ctx = {"cluster": target.get("host") or target.get("ref") or "<cluster>",
               "context": target.get("context") or "<context>", "label": target.get("label", "")}
        try:
            from config import PATHS as _PATHS
            ctx.update(_PATHS)
        except Exception:                 # pragma: no cover
            pass

        checks, techs = [], set()
        for c in self._checks():
            checks.append(Check(c["name"], _fmt(c["command"], ctx), c.get("purpose", ""),
                                c.get("attack", ""), c.get("owasp", ""), c.get("cwe", ""),
                                c.get("risk", "")).to_dict())
            if c.get("attack"):
                techs.add(c["attack"])

        surface = ["Kubernetes control + data plane - exposed API/kubelet/etcd, weak RBAC, "
                   "over-privileged pods and SA tokens drive cluster takeover and node escape."]
        return [ModuleResult(
            self.name, self.title, target.get("ref", "k8s"), "cluster",
            "Kubernetes cluster assessment (ATT&CK Containers).",
            worst([]), techniques=sorted(techs), attack_surface=surface,
            checks=checks, findings=[])]
