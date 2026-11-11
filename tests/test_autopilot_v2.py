"""autopilot v2 (observe-decide-run loop) + parsers package.

Covers:
  * parsers.nmap on default text + grepable output
  * parsers.nuclei on JSONL
  * parsers.generic regex extraction (hosts, URLs, CVEs)
  * parsers.dispatch routing by command prefix + fallback
  * autopilot_loop._merge_hosts / _merge_services / _merge_findings dedup
  * autopilot_loop.run_loop iteration cap + early-exit on dry iteration
  * autopilot_loop.run_loop writes the engagement back when a path is given
  * autopilot_loop CLI refuses without --yes-i-am-authorized
"""
import json
import os
import sys
import tempfile

# Force the LLM client offline by pointing Ollama at a dead port. The
# autopilot v2 loop re-ranks via copilot/qualia, which otherwise can block
# for minutes against a real local daemon under its default timeout. Setting
# this before the first import keeps the deterministic fallback path in
# every re-rank — exactly what we want to assert the loop mechanics against.
os.environ["OLLAMA_HOST"] = "http://127.0.0.1:1"
os.environ["MIMIR_LLM_TIMEOUT"] = "0.5"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import autopilot          # noqa: E402
import autopilot_loop     # noqa: E402
import parsers            # noqa: E402
from parsers.base import ParseResult   # noqa: E402


def _tmp(suffix=""):
    fd, p = tempfile.mkstemp(suffix=suffix, prefix="apv2-test-")
    os.close(fd)
    return p


def _cleanup(*paths):
    for p in paths:
        for suffix in ("", "-wal", "-shm", "-journal"):
            x = p + suffix
            if os.path.exists(x):
                try:
                    os.unlink(x)
                except OSError:
                    pass


# --------------------------------------------------------------------------- #
# parsers.nmap
# --------------------------------------------------------------------------- #
_NMAP_TEXT = """\
Starting Nmap 7.94 ( https://nmap.org ) at 2026-11-08 12:00 UTC
Nmap scan report for web01.corp.lab (10.0.0.5)
Host is up (0.0010s latency).
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9
80/tcp   open  http       nginx 1.24.0
443/tcp  open  https      nginx 1.24.0

Nmap scan report for 10.0.0.6
Host is up (0.0011s latency).
PORT     STATE SERVICE
445/tcp  open  microsoft-ds
Nmap done: 2 IP addresses (2 hosts up) scanned in 2.14 seconds
"""

_NMAP_GREP = """\
# Nmap 7.94 scan started
Host: 10.0.0.42 ()	Status: Up
Host: 10.0.0.42 ()	Ports: 22/open/tcp//ssh///, 8080/open/tcp//http-proxy///	Ignored State: filtered (998)
"""


def test_parser_nmap_text_extracts_hosts_and_services():
    r = parsers.dispatch("nmap -sV -p 22,80,443 10.0.0.5", _NMAP_TEXT)
    assert "10.0.0.5" in r.new_hosts or "web01.corp.lab" in r.new_hosts
    assert "10.0.0.6" in r.new_hosts
    ports = {(s["host"], s["port"]) for s in r.new_services}
    assert ("10.0.0.5", 22) in ports or ("web01.corp.lab", 22) in ports
    assert any(s["port"] == 80 for s in r.new_services)
    assert any(s["port"] == 445 for s in r.new_services)


def test_parser_nmap_grepable_extracts_ports():
    r = parsers.dispatch("nmap -oG - 10.0.0.42", _NMAP_GREP)
    assert "10.0.0.42" in r.new_hosts
    ports = {s["port"] for s in r.new_services}
    assert 22 in ports and 8080 in ports


def test_parser_nmap_empty_output_is_empty_result():
    r = parsers.dispatch("nmap -sn 10.0.0.99", "")
    assert r.is_empty()


# --------------------------------------------------------------------------- #
# parsers.nuclei
# --------------------------------------------------------------------------- #
def test_parser_nuclei_jsonl_emits_findings():
    stdout = "\n".join([
        json.dumps({
            "template-id": "CVE-2024-0001",
            "info": {"name": "Example critical RCE",
                     "severity": "critical",
                     "classification": {"cve-id": ["CVE-2024-0001"],
                                        "cwe-id": ["CWE-78"]}},
            "host": "https://web.lab:443/", "matched-at": "https://web.lab:443/api"}),
        json.dumps({
            "template-id": "generic-http-detection",
            "info": {"name": "Tech detected", "severity": "info"},
            "host": "http://web2.lab/"}),
        "not-json-line",
        "",
    ])
    r = parsers.dispatch("nuclei -jsonl -t cves/", stdout)
    sevs = [f["severity"] for f in r.new_findings]
    assert sevs == ["critical", "info"]
    cves = [f["cve"] for f in r.new_findings]
    assert "CVE-2024-0001" in cves


def test_parser_nuclei_empty_output_is_empty_result():
    r = parsers.dispatch("nuclei -jsonl", "")
    assert r.is_empty()


# --------------------------------------------------------------------------- #
# parsers.generic
# --------------------------------------------------------------------------- #
def test_parser_generic_extracts_cves_and_hosts():
    text = ("curl: fetched https://assets.example.com/a.js "
            "and saw CVE-2023-12345 plus CVE-2024-67890 on 10.1.2.3")
    r = parsers.dispatch("curl -s https://assets.example.com/a.js", text)
    assert "10.1.2.3" in r.new_hosts
    assert "assets.example.com" in r.new_hosts
    cves = {f["cve"] for f in r.new_findings}
    assert cves == {"CVE-2023-12345", "CVE-2024-67890"}


def test_parser_generic_ignores_loopback_and_broadcast():
    text = "ping 127.0.0.1\nping 0.0.0.0\nping 255.255.255.255\nhit 10.5.5.5"
    r = parsers.dispatch("ping 10.5.5.5", text)
    assert "10.5.5.5" in r.new_hosts
    for junk in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):
        assert junk not in r.new_hosts, junk


def test_parser_dispatch_fallback_is_generic():
    r = parsers.dispatch("totally-unknown-tool --flag", "CVE-2025-00001 on x.lab")
    assert r.source_tool == "generic"
    assert any(f["cve"] == "CVE-2025-00001" for f in r.new_findings)


# --------------------------------------------------------------------------- #
# Merge helpers — idempotent + dedup'd
# --------------------------------------------------------------------------- #
def test_merge_hosts_dedups_case_insensitive():
    eng = {"hosts": [{"address": "10.0.0.5"}]}
    added = autopilot_loop._merge_hosts(eng, ["10.0.0.5", "10.0.0.6", "Web.Example"])
    assert added == 2
    assert len(eng["hosts"]) == 3
    # Second call adds none.
    assert autopilot_loop._merge_hosts(eng, ["10.0.0.6", "web.example"]) == 0


def test_merge_services_creates_host_stub_when_missing():
    eng = {"hosts": []}
    host_added, port_added = autopilot_loop._merge_services(
        eng, [{"host": "10.0.0.9", "port": 22, "proto": "tcp",
               "service": "ssh"}])
    assert host_added == 1 and port_added == 1
    assert eng["hosts"][0]["ports"][0]["port"] == 22


def test_merge_services_dedups_port_per_host():
    eng = {"hosts": [{"address": "10.0.0.9",
                      "ports": [{"port": 22, "protocol": "tcp"}]}]}
    _, port_added = autopilot_loop._merge_services(
        eng, [{"host": "10.0.0.9", "port": 22, "proto": "tcp", "service": "ssh"},
              {"host": "10.0.0.9", "port": 80, "proto": "tcp", "service": "http"}])
    assert port_added == 1
    ports = {p["port"] for p in eng["hosts"][0]["ports"]}
    assert ports == {22, 80}


def test_merge_findings_dedups_by_host_title_cve():
    eng = {"findings": [{"host": "h1", "title": "X", "cve": "CVE-1"}]}
    added = autopilot_loop._merge_findings(
        eng, [{"host": "h1", "title": "X", "cve": "CVE-1"},
              {"host": "h1", "title": "Y", "cve": "CVE-1"}])
    assert added == 1
    assert len(eng["findings"]) == 2


# --------------------------------------------------------------------------- #
# Loop — dry-run convergence, iteration cap, engagement writeback
# --------------------------------------------------------------------------- #
def _mkstep(**over):
    base = {"technique_id": "T1046", "host": "10.0.0.5",
            "command": "echo probe", "risk": "safe", "order": 1}
    base.update(over)
    return base


def _mkeng(steps, kind="recon"):
    return {
        "schema": "mimir-engagement",
        "hosts": [], "findings": [],
        "attack_paths": [{"id": "P-1", "kind": kind, "steps": steps}],
        "modules": [],
    }


def test_loop_dry_run_converges_without_execution():
    eng = _mkeng([_mkstep(command="echo a")])
    summary = autopilot_loop.run_loop(
        eng, max_iterations=3,
        autopilot_kwargs={"dry_run": True, "noise_ceiling": 5})
    # Dry iteration: nothing executed -> early exit after first.
    assert summary["iterations"] == 1
    assert summary["autopilot_runs"][0]["started"] == 0
    assert summary["merged_hosts"] == 0
    assert summary["merged_findings"] == 0


def test_loop_merges_parsed_output_into_engagement():
    # Use a real safe command whose output the nmap parser can't claim and the
    # generic parser WILL extract from. `echo` the sentinel text verbatim.
    sentinel = ("Scanning done. New host 10.1.1.1 "
                "responded; CVE-2025-99999 observed on target.lab.")
    cmd = 'echo "%s"' % sentinel.replace('"', '\\"')
    eng = _mkeng([_mkstep(command=cmd)])
    summary = autopilot_loop.run_loop(
        eng, max_iterations=1,
        autopilot_kwargs={"noise_ceiling": 5})
    assert summary["autopilot_runs"][0]["started"] == 1
    assert summary["merged_findings"] >= 1
    cves = {f.get("cve") for f in eng["findings"]}
    assert "CVE-2025-99999" in cves


def test_loop_writes_engagement_back_to_disk():
    eng_path = _tmp(".json")
    cmd = 'echo "SEEN CVE-2024-11111 on probe.lab"'
    eng = _mkeng([_mkstep(command=cmd)])
    with open(eng_path, "w", encoding="utf-8") as fh:
        json.dump(eng, fh)
    try:
        autopilot_loop.run_loop(
            eng, max_iterations=1,
            autopilot_kwargs={"noise_ceiling": 5},
            engagement_path=eng_path)
        with open(eng_path, encoding="utf-8") as fh:
            disk = json.load(fh)
        assert any(f.get("cve") == "CVE-2024-11111" for f in disk["findings"])
    finally:
        _cleanup(eng_path)


def test_loop_iteration_cap_is_respected():
    # 3 real executions per iteration; cap at 2 iterations. Second iteration
    # has nothing left to learn, so convergence may trigger — we assert the
    # ceiling, not the exact count.
    cmd = 'echo "noop"'
    eng = _mkeng([_mkstep(command=cmd, order=1),
                  _mkstep(command=cmd, order=2)])
    summary = autopilot_loop.run_loop(
        eng, max_iterations=2,
        autopilot_kwargs={"noise_ceiling": 5})
    assert summary["iterations"] <= 2


def test_loop_jsonl_log_writes_per_iteration_records():
    log = _tmp(".jsonl")
    try:
        eng = _mkeng([_mkstep(command='echo "ok"')])
        autopilot_loop.run_loop(
            eng, max_iterations=1,
            autopilot_kwargs={"noise_ceiling": 5},
            loop_log_path=log)
        with open(log, encoding="utf-8") as fh:
            lines = [json.loads(ln) for ln in fh if ln.strip()]
        iters = [l for l in lines if "iteration" in l]
        assert len(iters) == 1
        assert any("summary" in l for l in lines)
    finally:
        _cleanup(log)


def test_loop_cli_refuses_without_authorization_flag():
    eng_path = _tmp(".json")
    try:
        with open(eng_path, "w", encoding="utf-8") as fh:
            json.dump(_mkeng([_mkstep(command='echo "x"')]), fh)
        rc = autopilot_loop.main([eng_path, "--max-iterations", "1"])
        assert rc == 2
    finally:
        _cleanup(eng_path)


# --------------------------------------------------------------------------- #
# Integration: autopilot.py --loop N dispatches to the v2 driver
# --------------------------------------------------------------------------- #
def test_autopilot_cli_loop_flag_dispatches_to_v2():
    eng_path = _tmp(".json")
    try:
        with open(eng_path, "w", encoding="utf-8") as fh:
            json.dump(_mkeng([_mkstep(command='echo "v2"')]), fh)
        rc = autopilot.main([eng_path, "--yes-i-am-authorized",
                             "--dry-run", "--loop", "1"])
        assert rc == 0
    finally:
        _cleanup(eng_path)
