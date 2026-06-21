#!/usr/bin/env python3
"""modules.iscsi — iSCSI target (3260) methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class IscsiModule(SpecModule):
    name = "iscsi"
    title = "iSCSI Target"
    NAMES = ("iscsi", "iscsi-target")
    UNAUTH = ("iscsi", "iscsi-target")
    SUMMARY = "iSCSI target service ({prod})."
    KEYWORDS = ("iscsi", "lun", "target", "initiator")
    EXTRA_TECH = ("T1135",)
    SURFACE = (
        ("always", "iSCSI targets without CHAP let any initiator enumerate and mount LUNs — block-level access to NAS/SAN data."),
    )
    CHECKS = (
        ("Target enumeration", "T1135", "nmap -p3260 --script iscsi-info {ip}", "Enumerate iSCSI targets (IQNs) and whether auth is required."),
        ("Discovery (iscsiadm)", "T1046", "iscsiadm -m discovery -t sendtargets -p {ip}:{port}", "List advertised targets via SendTargets discovery."),
        ("Unauth mount", "T1078", "iscsiadm -m node -T <iqn> -p {ip} --login", "Attempt to attach a target without CHAP (authorized) and inventory the LUN."),
        ("CHAP brute", "T1110", "nmap -p3260 --script iscsi-brute {ip}", "Authorized testing of CHAP credentials where required."),
    )
