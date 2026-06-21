"""Tests for assess.py — the single-CLI pipeline runner.

Covers the Stage-0 scope gate (in / out of scope, hostname + CIDR matching) and
a full --from-xml run that must yield non-empty findings, modules and attack
paths. Runs under pytest; also runnable standalone (`python3 tests/test_assess.py`)
for environments without pytest installed.
"""
import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import assess  # noqa: E402

FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "full_scan.xml")


def _scope_file(*lines):
    fd, path = tempfile.mkstemp(prefix="scope_", suffix=".txt")
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


# --------------------------------------------------------------------------- #
# Stage 0 — scope gate (unit)
# --------------------------------------------------------------------------- #
def test_scope_cidr_membership():
    path = _scope_file("10.10.10.0/24", "# a comment", "")
    nets, names = assess.load_scope(path)
    os.unlink(path)
    assert assess.target_in_scope(["10.10.10.5"], nets, names) is True
    assert assess.target_in_scope(["10.10.10.20"], nets, names) is True
    # out of scope
    assert assess.target_in_scope(["192.168.0.5"], nets, names) is False
    assert assess.target_in_scope(["10.10.11.1"], nets, names) is False


def test_scope_cidr_subnet_containment():
    path = _scope_file("10.10.10.0/24")
    nets, names = assess.load_scope(path)
    os.unlink(path)
    # a CIDR target fully inside scope is in scope; a wider one is not
    assert assess.target_in_scope(["10.10.10.0/25"], nets, names) is True
    assert assess.target_in_scope(["10.0.0.0/8"], nets, names) is False


def test_scope_hostname_exact_match():
    path = _scope_file("dc01.corp.lab", "10.10.10.0/24")
    nets, names = assess.load_scope(path)
    os.unlink(path)
    assert assess.target_in_scope(["dc01.corp.lab"], nets, names) is True
    # case-insensitive
    assert assess.target_in_scope(["DC01.corp.lab"], nets, names) is True
    # a different hostname (not an IP) is out of scope
    assert assess.target_in_scope(["evil.example.com"], nets, names) is False


def test_scope_multi_identifier_any_match():
    """A host is in scope if ANY of its identifiers matches."""
    path = _scope_file("dc01.corp.lab")
    nets, names = assess.load_scope(path)
    os.unlink(path)
    # ip not in scope, but hostname is -> in scope
    assert assess.target_in_scope(["10.10.10.5", "dc01.corp.lab"], nets, names) is True
    # neither matches -> out
    assert assess.target_in_scope(["10.10.10.5", "web.corp.lab"], nets, names) is False


# --------------------------------------------------------------------------- #
# Stage 0 — scope gate (end-to-end exit codes)
# --------------------------------------------------------------------------- #
def _run_assess(*args):
    # assess.py emits UTF-8 (box-drawing, '→', '·'); decode as UTF-8 explicitly
    # so the harness doesn't choke on a non-UTF-8 platform locale (e.g. Windows
    # cp1252).
    return subprocess.run([sys.executable, os.path.join(REPO_ROOT, "assess.py"), *args],
                          cwd=REPO_ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def test_e2e_in_scope_runs_all_stages():
    path = _scope_file("10.10.10.0/24")
    try:
        r = _run_assess("--from-xml", FIXTURE, "--scope", path, "--yes")
    finally:
        os.unlink(path)
    assert r.returncode == 0, r.stderr
    out = r.stdout
    for stage in ("Stage 0", "Stage 1", "Stage 2", "Stage 3", "Stage 4"):
        assert stage in out, f"missing {stage} in output"
    # staging banner present, no auto-exploitation
    assert "does NOT launch exploits" in out


def test_e2e_out_of_scope_refused_nonzero():
    path = _scope_file("192.168.0.0/24")
    try:
        r = _run_assess("--from-xml", FIXTURE, "--scope", path, "--yes")
    finally:
        os.unlink(path)
    assert r.returncode != 0
    assert "REFUSED" in r.stdout
    # must not proceed to analysis
    assert "Stage 2" not in r.stdout


# --------------------------------------------------------------------------- #
# Full --from-xml pipeline produces non-empty results
# --------------------------------------------------------------------------- #
def test_from_xml_pipeline_nonempty():
    path = _scope_file("10.10.10.0/24")
    fd, json_out = tempfile.mkstemp(prefix="assess_", suffix=".json")
    os.close(fd)
    try:
        r = _run_assess("--from-xml", FIXTURE, "--scope", path, "--yes",
                        "--json", json_out)
        assert r.returncode == 0, r.stderr
        data = json.load(open(json_out))
    finally:
        os.unlink(path)
        os.unlink(json_out)
    assert set(["generated", "scan", "report", "modules", "attack_paths"]).issubset(data)
    # JSON report must drop the bulky raw hosts (matches export_json contract)
    assert "hosts" not in data["report"]
    assert len(data["report"]["findings"]) > 0
    assert len(data["modules"]) > 0
    assert len(data["attack_paths"]) > 0
    # every attack-path step carries an ATT&CK technique id (constitution rule)
    for p in data["attack_paths"]:
        for step in p["steps"]:
            assert step["technique_id"].startswith("T")


# --------------------------------------------------------------------------- #
# Standalone runner (for environments without pytest)
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    fns = sorted((n, f) for n, f in globals().items()
                 if n.startswith("test_") and callable(f))
    failures = 0
    for name, fn in fns:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL  {name}: {exc!r}")
    print(f"\n{len(fns) - failures}/{len(fns)} passed")
    sys.exit(1 if failures else 0)
