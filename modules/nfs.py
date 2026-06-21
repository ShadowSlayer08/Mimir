#!/usr/bin/env python3
"""modules.nfs — NFS / RPC assessment methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class NFSModule(SpecModule):
    name = "nfs"
    title = "NFS / RPC"
    NAMES = ("nfs", "rpcbind", "mountd", "nlockmgr")
    UNAUTH = ("nfs", "rpcbind")
    SUMMARY = "{prod} (NFS/RPC) reachable."
    KEYWORDS = ("nfs", "rpcbind", "mountd", "showmount", "no_root_squash")
    EXTRA_TECH = ("T1135",)
    SURFACE = (
        ("always", "NFS exports may be world-readable/writable; no_root_squash enables privileged file access."),
        ("unauth", "rpcbind/NFS frequently allow unauthenticated enumeration and mounts — test export permissions."),
    )
    CHECKS = (
        ("RPC programs", "T1046", "rpcinfo -p {ip}", "List registered RPC programs and their ports."),
        ("List exports", "T1135", "showmount -e {ip}", "Enumerate exported NFS shares and allowed clients."),
        ("Export scripting", "T1135", "nmap -p{port} --script nfs-showmount,nfs-ls,nfs-statfs {ip}", "Enumerate exports, list files and check free space via NSE."),
        ("Mount & inspect", "T1039", "mount -t nfs {ip}:/<export> /mnt/nfs -o nolock", "Mount an export and inventory readable/writable data (authorized)."),
        ("root_squash test", "T1078", "# as root, write a file to the mount; root-owned => no_root_squash", "Determine whether privileged writes are possible (privesc surface)."),
    )
