# Workflow

Stage view — what happens to data as an assessment runs, and which component
owns each stage.

| # | Stage | What happens | Owner |
| - | --- | --- | --- |
| 1 | Discovery | Run nmap (`-sV -O --script vulners,vuln,default -oX`) against in-scope targets | operator / nmap |
| 2 | Classification | Parse hosts, ports, services, OS; normalise into findings | `nmap_analyzer` |
| 3 | Enumeration | Route each service to its module(s); render ATT&CK-mapped methodology | `modules/` + `docs/` |
| 4 | Correlation | Derive capabilities from findings; chain them | `attack_path_engine` |
| 5 | Attack Paths | Build scored rce / lateral / domain paths | `attack_path_engine` |
| 6 | Reporting | Export + review (executive / technical) | exporters + console |

## Loop, not a line
Steps 1–6 are not strictly one-shot. New assets (an AD dump, recovered creds,
pivots) should re-enter at Classification. The execution queue in the console
tracks operator-driven steps whose results feed the next iteration.

## Example
```
nmap -sV -O --script "vulners,vuln,default" -oX scan.xml 10.10.10.0/24
python3 nmap_analyzer.py scan.xml --no-gui --json report.json
python3 -m modules scan.xml                 # enumeration methodology
python3 attack_path_engine.py scan.xml      # attack paths
python3 pentest_console.py scan.xml         # GUI: review + stage
```
