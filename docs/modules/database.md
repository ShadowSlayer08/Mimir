# Database Module

Database assessment methodology. One assessment per database port. `{auth_cmd}`
is resolved per-engine from the `connect` map; engines in `unauth_services` are
flagged as often-unauthenticated.

```yaml
module: database
title: Database
scope: port
matches: [mysql, ms-sql-s, postgresql, mongodb, mongod, redis, memcache, memcached, elasticsearch, couchdb, oracle, cassandra]
summary: "{disp} reachable {ver}."
labels:
  mysql: MySQL/MariaDB
  ms-sql-s: MSSQL
  postgresql: PostgreSQL
  mongodb: MongoDB
  mongod: MongoDB
  redis: Redis
  memcache: Memcached
  memcached: Memcached
  elasticsearch: Elasticsearch
  couchdb: CouchDB
  oracle: Oracle TNS
  cassandra: Cassandra
connect:
  mysql: "mysql -h {ip} -P {port} -u root"
  ms-sql-s: "impacket-mssqlclient <user>:<pass>@{ip}"
  postgresql: "psql -h {ip} -p {port} -U postgres"
  mongodb: "mongosh --host {ip} --port {port}"
  mongod: "mongosh --host {ip} --port {port}"
  redis: "redis-cli -h {ip} -p {port} info"
  memcache: "memcstat --servers={ip}:{port}"
  memcached: "memcstat --servers={ip}:{port}"
  elasticsearch: "curl -s http://{ip}:{port}/_cat/indices"
  couchdb: "curl -s http://{ip}:{port}/_all_dbs"
  oracle: "odat all -s {ip} -p {port}"
  cassandra: "cqlsh {ip} {port}"
unauth_services: [mongodb, mongod, redis, memcache, memcached, elasticsearch, couchdb]
attack_surface:
  - when: "unauth"
    note: "{disp} is frequently deployed without authentication — test for anonymous access first."
  - when: "has_cve"
    note: "Engine version has known CVEs (see findings)."
checks:
  - {name: Connectivity / auth test, attack: T1078, command: "{auth_cmd}",
     purpose: "Test reachability and whether (anonymous) auth succeeds."}
  - {name: Version & CVEs,    attack: T1592, command: "nmap -p{port} -sV --script vulners {ip}",
     purpose: "Confirm exact version and cross-reference CVEs."}
  - {name: Credential test,   attack: T1110, command: "hydra -L users.txt -P passwords.txt {ip} <mysql|postgres|mssql>   # NoSQL engines: use the engine client + a wordlist",
     purpose: "Test for weak/default credentials with the matching hydra module (authorized; mind lockout)."}
  - {name: Data enumeration,  attack: T1213, command: "# after auth: list databases / keys / indices in scope",
     purpose: "Inventory exposed data to gauge impact."}
```
