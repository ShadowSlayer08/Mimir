"""Engagement JSON contract (assess.build_engagement_json + --emit-json).

The contract is the stable bridge to external frontends (the Flutter desktop
viewer, a future web UI). It is a pure projection of already-computed engine
output — no scanning, no execution.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmap_analyzer import load_scan, analyze, build_report  # noqa: E402
from modules import dispatch  # noqa: E402
from attack_path_engine import generate_paths  # noqa: E402
from assess import build_engagement_json  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "full_scan.xml")


def _engagement():
    hosts, meta, _ = load_scan(FIXTURE)
    report = build_report(hosts, meta, analyze(hosts))
    mods = dispatch(report)
    paths = generate_paths(report)
    scan_meta = {"mode": "vapt", "from_xml": FIXTURE, "from_dir": None, "target": "fixture"}
    return build_engagement_json(report, mods, paths, scan_meta)


def test_contract_top_level_keys():
    eng = _engagement()
    assert set(eng) >= {"schema", "meta", "hosts", "findings", "attack_paths", "killchain"}
    assert eng["schema"] == "redengine.engagement"
    m = eng["meta"]
    assert m["offline"] is True and m["mode"] == "vapt"
    assert "STAGING ONLY" in m["boundary"]            # boundary stamped into every export
    assert "severity_counts" in m and "totals" in m


def test_hosts_and_findings_projected():
    eng = _engagement()
    assert eng["hosts"], "expected at least one host in the fixture"
    h = eng["hosts"][0]
    for k in ("ip", "label", "os", "device_class", "grade",
              "open_ports", "finding_count", "ports"):
        assert k in h


def test_steps_carry_command_and_killchain_present():
    eng = _engagement()
    assert "stages" in eng["killchain"]
    assert len(eng["killchain"]["stages"]) == 5        # 5-stage kill-chain model
    for ap in eng["attack_paths"]:
        assert {"id", "name", "severity", "score", "steps"} <= set(ap)
        for s in ap["steps"]:
            # every step is copy-ready and ATT&CK-tagged for the frontend
            assert "command" in s and "technique_id" in s and "abuse" in s


def test_emit_json_is_serializable():
    eng = _engagement()
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(eng, fh, indent=2)
        reloaded = json.load(open(path, encoding="utf-8"))
        assert reloaded["schema"] == "redengine.engagement"
    finally:
        os.unlink(path)
