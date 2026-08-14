#!/usr/bin/env python3
"""modules.hypervisor — virtualization / hypervisor methodology (target-driven).

Authorized / lab / CTF use only.

Assesses a HYPERVISOR target (VMware ESXi / vCenter / vSphere, Proxmox, Xen,
Hyper-V, Nutanix) — the virtualization management plane, an increasingly targeted
ransomware and lateral-movement surface. Checks are ATT&CK + CWE-mapped with a
`safe|intrusive` risk tag: version/CVE and exposure review are safe; credential and
escape testing are intrusive (VAPT-hidden). Methodology + STAGING only.

Tooling: nmap (esxi/vsphere NSE), scanners for OpenSLP/CIM, govc, PowerCLI, and the
operator's own exploit tooling for the mapped CVEs.

Checks load from docs/appsec/hypervisor.md (`module: hypervisor`) when present, else
built-in. Providers: --hypervisor esxi|vcenter|proxmox|xen|hyperv[:host].
Placeholders: {provider} {host}.
"""
from __future__ import annotations

import string

from .base import Check, ModuleResult, worst

_A = "always"
# (name, attack, owasp, cwe, risk, when, command, purpose)
BUILTIN_CHECKS = [
    ("Management interface recon", "T1595", "", "CWE-200", "safe", _A,
     "nmap -sV -p80,443,427,902,5480,5989,8006 {host}   # mgmt UI/API, SLP, CIM",
     "Fingerprint the hypervisor and version."),
    ("Management-plane CVEs", "T1190", "", "CWE-1035", "safe", _A,
     "# map version to CVEs: ESXi OpenSLP CVE-2021-21974; vCenter CVE-2021-22005 / CVE-2023-34048",
     "Flag exploitable management-plane CVEs."),
    ("Default / weak credentials", "T1078.001", "", "CWE-1392", "intrusive", _A,
     "# authorized, lockout-aware: test default/weak admin creds on the mgmt UI/API",
     "Test management authentication."),
    ("ESXi SLP / CIM exposure", "T1046", "", "CWE-306", "safe", "esxi",
     "# check OpenSLP (427) and CIM (5989) exposure; SSH/shell enablement on ESXi hosts",
     "Find exposed ESXi management services."),
    ("vCenter SSO / SAML", "T1550", "", "CWE-287", "safe", "vcenter",
     "# assess vCenter SSO and SAML token handling (CVE-2022-31656 class), admin role sprawl",
     "Test the vCenter identity surface."),
    ("Proxmox API / realm", "T1078", "", "CWE-287", "safe", "proxmox",
     "# assess the Proxmox 8006 API, PAM/PVE realms and root@pam exposure",
     "Test Proxmox authentication and API."),
    ("Guest to host escape surface", "T1611", "", "CWE-269", "safe", _A,
     "# inventory VM-tools versions for escape CVEs; review VM isolation config",
     "Assess VM-escape exposure."),
    ("Datastore / VMDK access", "T1005", "", "CWE-552", "safe", _A,
     "# test datastore / VMDK access (offline secret extraction from VM disks)",
     "Test datastore access controls."),
    ("Snapshot / backup exposure", "T1005", "", "CWE-284", "safe", _A,
     "# check for exposed snapshots/backups - VM images can carry domain secrets (NTDS)",
     "Find sensitive VM images."),
    ("Ransomware resilience", "T1490", "", "CWE-693", "safe", _A,
     "# review hypervisor ransomware exposure: SSH enabled, flat network, isolated mgmt plane",
     "Assess hypervisor-ransomware exposure."),
]

_PROV = {"esxi": "esxi", "vsphere": "esxi", "vmware": "esxi",
         "vcenter": "vcenter", "proxmox": "proxmox", "pve": "proxmox",
         "xen": "xen", "xenserver": "xen", "hyperv": "hyperv", "hyper-v": "hyperv",
         "nutanix": "nutanix"}


class _SafeDict(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(s, ctx):
    return string.Formatter().vformat(s or "", (), _SafeDict(ctx))


class HypervisorModule:
    name = "hypervisor"
    title = "Hypervisor / Virtualization"

    def __init__(self, docs_dir=None):
        try:
            from knowledge_loader import load_knowledge
            self._mdef = load_knowledge(docs_dir).modules.get("hypervisor")
        except Exception:                                              # pragma: no cover
            self._mdef = None

    def _checks(self):
        if self._mdef and self._mdef.get("checks"):
            return self._mdef["checks"]
        return [{"name": n, "attack": a, "owasp": o, "cwe": w, "risk": rk,
                 "when": wh, "command": cmd, "purpose": pp}
                for (n, a, o, w, rk, wh, cmd, pp) in BUILTIN_CHECKS]

    def assess_target(self, target, findings):
        raw = (target.get("provider") or "esxi").lower()
        prov = _PROV.get(raw, "esxi")
        ctx = {"provider": raw, "host": target.get("host") or target.get("ref") or "<host>",
               "label": target.get("label", "")}
        try:
            from config import PATHS as _PATHS
            ctx.update(_PATHS)
        except Exception:                 # pragma: no cover
            pass

        flags = {"always": True, "esxi": prov == "esxi", "vcenter": prov == "vcenter",
                 "proxmox": prov == "proxmox"}
        checks, techs = [], set()
        for c in self._checks():
            when = c.get("when", "always") or "always"
            if not flags.get(when, when == "always"):
                continue
            checks.append(Check(c["name"], _fmt(c["command"], ctx), c.get("purpose", ""),
                                c.get("attack", ""), c.get("owasp", ""), c.get("cwe", ""),
                                c.get("risk", "")).to_dict())
            if c.get("attack"):
                techs.add(c["attack"])

        surface = [f"Hypervisor management plane ({raw}) - CVEs, weak mgmt creds and datastore "
                   "access give host-wide compromise and are a prime ransomware target."]
        return [ModuleResult(
            self.name, self.title, target.get("ref", raw), raw,
            f"Hypervisor posture ({raw}).",
            worst([]), techniques=sorted(techs), attack_surface=surface,
            checks=checks, findings=[])]
