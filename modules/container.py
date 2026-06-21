#!/usr/bin/env python3
"""modules.container — container/orchestration methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class ContainerModule(SpecModule):
    name = "container"
    title = "Container / Orchestration"
    NAMES = ("docker", "kubernetes", "kubelet", "etcd")
    TLS_PORTS = (2376, 6443, 8443, 10250)
    UNAUTH = ("docker", "kubelet", "etcd")
    SUMMARY = "{disp} API reachable — unauth access risks host/cluster takeover."
    KEYWORDS = ("docker", "kubernetes", "kubelet", "etcd", "kube")
    EXTRA_TECH = ("T1610", "T1613")
    LABELS = {"docker": "Docker Engine API", "kubernetes": "Kubernetes API server",
              "kubelet": "kubelet API", "etcd": "etcd"}
    SURFACE = (
        ("always", "Exposed container/orchestrator APIs can yield host or cluster takeover — require mTLS/RBAC and never expose publicly."),
        ("unauth", "Unauthenticated Docker/kubelet/etcd APIs allow container creation, secret theft and node compromise."),
    )
    CHECKS = (
        ("Docker API", "T1613", "docker -H tcp://{ip}:{port} info", "Test the unauthenticated Docker Engine API and enumerate the host."),
        ("Docker containers", "T1610", "curl -sk {scheme}://{ip}:{port}/containers/json", "List running containers (surface mount/secret exposure)."),
        ("K8s API anon", "T1613", "kubectl --server={scheme}://{ip}:{port} --insecure-skip-tls-verify get pods -A", "Test anonymous API access and RBAC misconfiguration."),
        ("Kubelet enum", "T1613", "curl -sk https://{ip}:{port}/pods", "Enumerate pods via the kubelet API on 10250."),
        ("etcd dump", "T1552.007", "etcdctl --endpoints={ip}:{port} get / --prefix --keys-only", "Test unauthenticated etcd and surface stored secrets/keys."),
    )
