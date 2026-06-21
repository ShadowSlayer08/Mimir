# NFS / RPC Module

NFS and RPC (rpcbind/mountd) methodology. One assessment per matching port:
enumerate RPC programs, list exports, and test export permissions.

```yaml
module: nfs
title: NFS / RPC
scope: port
matches: [nfs, rpcbind, mountd, nlockmgr]
summary: "{prod} (NFS/RPC) reachable."
finding_keywords: [nfs, rpcbind, mountd, showmount, no_root_squash]
unauth_services: [nfs, rpcbind]
techniques_extra: [T1135]
attack_surface:
  - { when: "always", note: "NFS exports may be world-readable/writable; no_root_squash enables privileged file access." }
  - { when: "unauth", note: "rpcbind/NFS frequently allow unauthenticated enumeration and mounts — test export permissions." }
checks:
  - { name: RPC programs, attack: T1046, command: "rpcinfo -p {ip}", purpose: "List registered RPC programs and their ports." }
  - { name: List exports, attack: T1135, command: "showmount -e {ip}", purpose: "Enumerate exported NFS shares and allowed clients." }
  - { name: Export scripting, attack: T1135, command: "nmap -p{port} --script nfs-showmount,nfs-ls,nfs-statfs {ip}", purpose: "Enumerate exports, list files and check free space via NSE." }
  - { name: Mount & inspect, attack: T1039, command: "mount -t nfs {ip}:/<export> /mnt/nfs -o nolock", purpose: "Mount an export and inventory readable/writable data (authorized)." }
  - { name: root_squash test, attack: T1078, command: "# as root, write a file to the mount; if owned by root, no_root_squash is set", purpose: "Determine whether privileged writes are possible (privesc surface)." }
```
