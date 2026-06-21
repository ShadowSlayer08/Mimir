#!/usr/bin/env python3
"""modules.database — database service assessment methodology."""
from __future__ import annotations

from .base import Module, ModuleResult, Check, host_label, worst

# service fragment -> (display, connectivity/auth-test command, often-unauthenticated?)
DBS = {
    "mysql":         ("MySQL/MariaDB", "mysql -h {ip} -P {port} -u root", False),
    "ms-sql-s":      ("MSSQL", "impacket-mssqlclient <user>:<pass>@{ip}", False),
    "postgresql":    ("PostgreSQL", "psql -h {ip} -p {port} -U postgres", False),
    "mongodb":       ("MongoDB", "mongosh --host {ip} --port {port}", True),
    "mongod":        ("MongoDB", "mongosh --host {ip} --port {port}", True),
    "redis":         ("Redis", "redis-cli -h {ip} -p {port} info", True),
    "memcache":      ("Memcached", "memcstat --servers={ip}:{port}", True),
    "memcached":     ("Memcached", "memcstat --servers={ip}:{port}", True),
    "elasticsearch": ("Elasticsearch", "curl -s http://{ip}:{port}/_cat/indices", True),
    "couchdb":       ("CouchDB", "curl -s http://{ip}:{port}/_all_dbs", True),
    "oracle":        ("Oracle TNS", "odat all -s {ip} -p {port}", False),
    "cassandra":     ("Cassandra", "cqlsh {ip} {port}", False),
}


class DatabaseModule(Module):
    name = "database"
    title = "Database"

    def assess(self, host, findings):
        label, ip = host_label(host), host.get("ip") or host_label(host)
        results = []
        for p in host.get("ports", []):
            name = (p["service"].get("name") or "").lower()
            match = next(((frag, *DBS[frag]) for frag in DBS if frag in name), None)
            if not match:
                continue
            frag, disp, cmd, unauth = match
            port = p["port"]
            ff = self.findings_for_port(findings, port)
            ver = p["service"].get("version", "")
            surface = []
            if unauth:
                surface.append(f"{disp} is frequently deployed without authentication — test for anonymous access first.")
            if any(f["category"] == "CVE (vulners)" for f in ff):
                surface.append("Engine version has known CVEs (see findings).")

            checks = [
                Check("Connectivity / auth test", cmd.format(ip=ip, port=port),
                      "Test reachability and whether (anonymous) auth succeeds.",
                      "T1190" if unauth else "T1078"),
                Check("Version & CVEs", f"nmap -p{port} -sV --script vulners {ip}",
                      "Confirm exact version and cross-reference CVEs.", "T1592"),
                Check("Credential test",
                      f"hydra -L users.txt -P passwords.txt {ip} <mysql|postgres|mssql>   # NoSQL engines: use the engine client + a wordlist",
                      "Test for weak/default credentials with the matching hydra module (authorized; mind lockout).", "T1110"),
                Check("Data enumeration", "# after auth: list databases / keys / indices in scope",
                      "Inventory exposed data to gauge impact.", "T1213"),
            ]
            results.append(ModuleResult(
                self.name, self.title, f"{label}:{port}", frag,
                f"{disp} reachable{(' ' + ver) if ver else ''}.", worst(ff),
                techniques=self.techs(checks),
                attack_surface=surface, checks=[c.to_dict() for c in checks], findings=ff))
        return results
