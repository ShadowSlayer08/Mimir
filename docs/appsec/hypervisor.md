# Hypervisor / Virtualization Module

**AppSec pillar — target-driven.** Assesses a hypervisor target (VMware ESXi /
vCenter / vSphere, Proxmox, Xen, Hyper-V, Nutanix) — the virtualization management
plane, an increasingly targeted ransomware and lateral-movement surface. Checks are
ATT&CK + CWE-mapped with a `safe|intrusive` risk tag: version/CVE and exposure review
are safe; credential and escape testing are intrusive (VAPT-hidden).

Targets come from `assess --hypervisor esxi|vcenter|proxmox|xen|hyperv[:host]`.
Provider-scoped checks use `when: esxi|vcenter|proxmox`. Tooling: nmap NSE
(esxi/vsphere), OpenSLP/CIM probes, govc, PowerCLI, and the operator's own exploit
tooling for the mapped CVEs.

**Boundary:** methodology + staging only. **Cross-layer:** a captured VMDK/snapshot
is a domain-secret source (NTDS), tying into the Active Directory module.

```yaml
module: hypervisor
title: Hypervisor / Virtualization
scope: target
matches: [esxi, vcenter, vsphere, proxmox, xen, hyperv, nutanix]
summary: "Hypervisor posture."
techniques_extra: []
checks:
  - {name: Management interface recon, attack: T1595, owasp: "", cwe: CWE-200, risk: safe, when: always,
     command: "nmap -sV -p80,443,427,902,5480,5989,8006 {host}   # mgmt UI/API, SLP, CIM",
     purpose: "Fingerprint the hypervisor and version."}
  - {name: Management-plane CVEs, attack: T1190, owasp: "", cwe: CWE-1035, risk: safe, when: always,
     command: "# map version to CVEs: ESXi OpenSLP CVE-2021-21974; vCenter CVE-2021-22005 / CVE-2023-34048",
     purpose: "Flag exploitable management-plane CVEs."}
  - {name: Default / weak credentials, attack: T1078.001, owasp: "", cwe: CWE-1392, risk: intrusive, when: always,
     command: "# authorized, lockout-aware: test default/weak admin creds on the mgmt UI/API",
     purpose: "Test management authentication."}
  - {name: ESXi SLP / CIM exposure, attack: T1046, owasp: "", cwe: CWE-306, risk: safe, when: esxi,
     command: "# check OpenSLP (427) and CIM (5989) exposure; SSH/shell enablement on ESXi hosts",
     purpose: "Find exposed ESXi management services."}
  - {name: vCenter SSO / SAML, attack: T1550, owasp: "", cwe: CWE-287, risk: safe, when: vcenter,
     command: "# assess vCenter SSO and SAML token handling (CVE-2022-31656 class), admin role sprawl",
     purpose: "Test the vCenter identity surface."}
  - {name: Proxmox API / realm, attack: T1078, owasp: "", cwe: CWE-287, risk: safe, when: proxmox,
     command: "# assess the Proxmox 8006 API, PAM/PVE realms and root@pam exposure",
     purpose: "Test Proxmox authentication and API."}
  - {name: Guest to host escape surface, attack: T1611, owasp: "", cwe: CWE-269, risk: safe, when: always,
     command: "# inventory VM-tools versions for escape CVEs; review VM isolation config",
     purpose: "Assess VM-escape exposure."}
  - {name: Datastore / VMDK access, attack: T1005, owasp: "", cwe: CWE-552, risk: safe, when: always,
     command: "# test datastore / VMDK access (offline secret extraction from VM disks)",
     purpose: "Test datastore access controls."}
  - {name: Snapshot / backup exposure, attack: T1005, owasp: "", cwe: CWE-284, risk: safe, when: always,
     command: "# check for exposed snapshots/backups - VM images can carry domain secrets (NTDS)",
     purpose: "Find sensitive VM images."}
  - {name: Ransomware resilience, attack: T1490, owasp: "", cwe: CWE-693, risk: safe, when: always,
     command: "# review hypervisor ransomware exposure: SSH enabled, flat network, isolated mgmt plane",
     purpose: "Assess hypervisor-ransomware exposure."}
```
