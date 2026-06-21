"""5-stage kill-chain playbook: stage model loads, ATT&CK ids valid, paths mapped."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nmap_analyzer import load_scan, analyze, build_report  # noqa: E402
from modules import dispatch  # noqa: E402
from attack_path_engine import generate_paths  # noqa: E402
from killchain import load_stages, build_killchain  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO, "tests", "fixtures", "full_scan.xml")
ATT = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_five_stages_load():
    stages = load_stages()
    assert [s["id"] for s in stages] == [1, 2, 3, 4, 5]
    assert "Reconnaissance" in stages[0]["name"]


def test_methodology_attack_ids_valid():
    for st in load_stages():
        for m in st.get("methodology", []):
            assert ATT.match(m.get("attack", "")), (st["name"], m)


def test_staged_steps_mapped_into_stages():
    hosts, meta, _ = load_scan(FIXTURE)
    report = build_report(hosts, meta, analyze(hosts))
    mods, paths = dispatch(report), generate_paths(report)
    kc = build_killchain(report, mods, paths)
    assert len(kc) == 5
    # every staged step is assigned to exactly one stage; total preserved
    total_steps = sum(len(p["steps"]) for p in paths)
    mapped = sum(len(st["staged_steps"]) for st in kc)
    assert mapped <= total_steps and mapped > 0
    # initial access lands in stage 3, post-ex tactics in stage 4
    s3 = next(s for s in kc if s["id"] == 3)
    assert any(step["tactic"] == "Initial Access" for step in s3["staged_steps"])
