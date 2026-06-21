"""Attack-path generation: from a real scan, and from ingested credential evidence."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nmap_analyzer import load_scan, analyze, build_report  # noqa: E402
from attack_path_engine import generate_paths  # noqa: E402
from evidence import _blank_host  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO, "tests", "fixtures", "full_scan.xml")


def test_paths_from_fixture_carry_attack_ids():
    hosts, meta, _ = load_scan(FIXTURE)
    report = build_report(hosts, meta, analyze(hosts))
    paths = generate_paths(report)
    assert paths, "expected at least one attack path from full_scan.xml"
    for p in paths:
        for step in p["steps"]:
            assert step["technique_id"].startswith("T"), step


def _host(label, ip, *svcs):
    h = _blank_host()
    h["ip"] = ip
    h["hostnames"] = [label]
    for i, name in enumerate(svcs):
        h["ports"].append({"port": 1000 + i, "protocol": "tcp", "state": "open", "reason": "",
                           "service": {"name": name, "product": "", "version": "", "extrainfo": "",
                                       "tunnel": "", "ostype": "", "cpe": []},
                           "scripts": {}, "ssl_enum": None, "least_strength": None, "cert": None})
    return h


def test_evidence_credentials_drive_lateral_path():
    # Recovered credential evidence on h1 + a reachable SSH service on h2
    # should produce a credential-reuse -> lateral path.
    hosts = [_host("h1", "10.0.0.1", "http"), _host("h2", "10.0.0.2", "ssh")]
    findings = [{"host": "h1", "port": 0, "category": "Evidence", "severity": "high",
                 "title": "Credential hashes in loot.txt", "cve": [], "detail": "", "fix": ""}]
    report = {"hosts": hosts, "findings": findings}
    paths = generate_paths(report)
    assert any(p["kind"] == "lateral" for p in paths), "expected a lateral path from evidence creds"
