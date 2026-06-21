# Kill-Chain Model

A 5-stage operator model that maps the engine's pipeline onto the Lockheed-Martin
Cyber Kill Chain and MITRE ATT&CK tactics. Each stage is **methodology + ATT&CK
mapping + staging** — the engine plans and stages; a human operator executes each
step manually, in authorized scope, with their own tooling.

**Boundary (see `docs/instructions.md`):** the engine never generates payloads,
runs exploits, installs implants, or operates C2. For the action phases it maps
the techniques and stages the steps for the operator; it does not perform them.

```yaml
kill_chain:
  stages:
    - id: 1
      name: Reconnaissance
      phases: [Reconnaissance]
      tactics: ["TA0043 Reconnaissance", "TA0007 Discovery"]
      objective: "Map the attack surface — live hosts, open TCP/UDP ports, service versions, OS, ownership."
      methodology:
        - {name: Host & port discovery, attack: T1595, command: "assess.py <target>  (Stage 1: -p- -Pn -A, +UDP service ports)"}
        - {name: Service/version enum, attack: T1592.002, command: "nmap -sV; per-service NSE (Stage 1b)"}
        - {name: DNS / OSINT, attack: T1590, command: "dig AXFR @<ns>; dnsenum; whois; subfinder; amass"}
      boundary: ""
    - id: 2
      name: Weaponization & Vulnerability Analysis
      phases: [Weaponization]
      tactics: ["TA0042 Resource Development"]
      objective: "Correlate findings to exploitable conditions and the tooling each would require — PLANNING ONLY."
      methodology:
        - {name: CVE correlation, attack: T1588.006, command: "vulners -> findings (Stage 2); composite risk score"}
        - {name: Exploit availability, attack: T1588.005, command: "searchsploit '<product> <version>'; review the public-exploit flag"}
        - {name: Tooling plan, attack: T1588.002, command: "note which operator tooling a path would need (the engine supplies none)"}
      boundary: "The engine maps which exploits/tooling a step would need. It does NOT build, arm, or obtain payloads — the operator supplies their own tooling."
    - id: 3
      name: Delivery & Exploitation
      phases: [Delivery, Exploitation]
      tactics: ["TA0001 Initial Access", "TA0002 Execution"]
      objective: "Stage the initial-access steps from confirmed exposures; validate scope; the OPERATOR executes manually."
      methodology:
        - {name: Exploit public-facing app, attack: T1190, command: "staged per attack path; confirm scope; operator executes with own tooling"}
        - {name: Exploit remote service, attack: T1210, command: "staged; run detection-only verification first (e.g. nmap vuln NSE)"}
        - {name: Valid accounts, attack: T1078, command: "authorized credential testing (crackmapexec / hydra), mind lockout"}
      boundary: "The engine stages exploitable conditions and the ATT&CK step. It launches nothing — no payloads, no exploit execution, no shells."
    - id: 4
      name: Post-Exploitation
      phases: [Installation]
      tactics: ["TA0004 Privilege Escalation", "TA0006 Credential Access", "TA0008 Lateral Movement", "TA0007 Discovery", "TA0003 Persistence"]
      objective: "Methodology for after a foothold: enumerate privesc, harvest credentials (per RoE), map the domain, move laterally."
      methodology:
        - {name: Privesc enum (Linux), attack: T1068, command: "linpeas.sh; sudo -l; find / -perm -4000 -type f 2>/dev/null"}
        - {name: Privesc enum (Windows), attack: T1068, command: "winPEAS.exe; whoami /priv; Seatbelt.exe -group=all"}
        - {name: Credential access, attack: T1003, command: "per engagement RoE, with your post-ex tooling (LSASS/SAM/NTDS) — log every action"}
        - {name: AD attack-path discovery, attack: T1482, command: "bloodhound-python -c All -d <domain> -u <u> -p <p> -dc <dc>"}
        - {name: Lateral movement, attack: T1021, command: "crackmapexec / evil-winrm with validated credentials (authorized)"}
        - {name: Persistence, attack: T1543, command: "establish per engagement RoE with your own tooling; document & clean up"}
      boundary: "Enumeration, authorized credential-testing and discovery are operator references. The engine does not dump credentials, install implants, or persist — it maps the techniques and stages them."
    - id: 5
      name: Command & Control / Actions on Objectives
      phases: ["Command and Control", "Actions on Objectives"]
      tactics: ["TA0011 Command and Control", "TA0009 Collection", "TA0010 Exfiltration", "TA0040 Impact"]
      objective: "Plan and document objective actions — likely C2/egress, collection targets, exfil routes, impact — then report."
      methodology:
        - {name: C2 / egress mapping, attack: T1071, command: "identify likely C2 channels & egress for planning/detection; operator runs their own C2 in scope"}
        - {name: Collection targets, attack: T1213, command: "rank high-value data stores from the inventory (Stage 2 findings)"}
        - {name: Exfiltration assessment, attack: T1041, command: "assess egress paths; demonstrate per RoE only; never move real data without written authorization"}
        - {name: Reporting & tracking, attack: T1213, command: "assess.py --report/--runbook/--navigator; --ledger to track the engagement"}
      boundary: "The engine never operates C2 or exfiltrates data. It maps objective-phase techniques for planning, in-scope demonstration, and reporting only."
```
