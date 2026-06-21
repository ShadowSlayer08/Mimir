# iSCSI Module

iSCSI target (TCP 3260) methodology — block storage / SAN. Targets without CHAP
allow any initiator to enumerate and mount LUNs.

```yaml
module: iscsi
title: iSCSI Target
scope: port
matches: [iscsi, iscsi-target]
summary: "iSCSI target service ({prod})."
finding_keywords: [iscsi, lun, target, initiator]
unauth_services: [iscsi, iscsi-target]
techniques_extra: [T1135]
attack_surface:
  - { when: "always", note: "iSCSI targets without CHAP let any initiator enumerate and mount LUNs — block-level access to NAS/SAN data." }
checks:
  - { name: Target enumeration, attack: T1135, command: "nmap -p3260 --script iscsi-info {ip}", purpose: "Enumerate iSCSI targets (IQNs) and whether authentication is required." }
  - { name: Discovery (iscsiadm), attack: T1046, command: "iscsiadm -m discovery -t sendtargets -p {ip}:{port}", purpose: "List advertised targets via SendTargets discovery." }
  - { name: Unauth mount, attack: T1078, command: "iscsiadm -m node -T <iqn> -p {ip} --login", purpose: "Attempt to attach a target without CHAP (authorized) and inventory the LUN." }
  - { name: CHAP brute, attack: T1110, command: "nmap -p3260 --script iscsi-brute {ip}", purpose: "Authorized testing of CHAP credentials where required." }
```
