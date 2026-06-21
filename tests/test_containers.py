"""Containerized runner generation (Podman/Docker commands + K8s Jobs)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import containers as ct  # noqa: E402


def test_config_loads():
    cfg = ct.load_config()
    assert cfg["default_image"] and isinstance(cfg["images"], dict)
    assert "nmap" in cfg["images"]


def test_dedicated_image_passes_args():
    line = ct.containerize("nmap -p- -sV 10.0.0.1", runtime="podman")
    assert line.startswith("podman run --rm")
    assert ct.load_config()["images"]["nmap"] in line
    assert "-p- -sV 10.0.0.1" in line
    assert " nmap nmap " not in line     # tool name not duplicated


def test_toolbox_image_uses_shell():
    line = ct.containerize("whatweb http://10.0.0.1", runtime="podman")
    assert "sh -lc" in line and "whatweb http://10.0.0.1" in line


def test_non_runnable_steps_skipped():
    assert ct.containerize("# after auth: enumerate shares") is None
    assert ct.containerize("<get-config/>") is None


def test_k8s_job_shape():
    cfg = ct.load_config()
    job = ct.k8s_job({"command": "nuclei -u http://x", "attack": "T1595"}, {"module": "web"}, cfg, 0)
    assert job["kind"] == "Job" and job["metadata"]["name"].startswith("pe-web-")
    assert job["spec"]["template"]["spec"]["containers"][0]["image"] == cfg["images"]["nuclei"]


def test_runnable_checks_excludes_intrusive_and_comments():
    mods = [{"module": "web", "checks": [
        {"name": "Fingerprint", "attack": "T1592.002", "command": "whatweb http://h"},
        {"name": "Brute", "attack": "T1110.003", "command": "hydra -L u -P p http://h"},
        {"name": "Note", "attack": "T1213", "command": "# after auth: enumerate"},
    ]}]
    runnable = ct.runnable_checks(mods)
    names = [c["name"] for c in runnable]
    assert "Fingerprint" in names           # enumeration kept
    assert "Brute" not in names             # intrusive (T1110/hydra) excluded
    assert "Note" not in names              # comment/placeholder excluded


def test_run_enumeration_requires_runtime():
    try:
        ct.run_enumeration([], runtime="definitely-no-such-runtime-xyz")
        assert False, "expected RuntimeError when runtime is absent"
    except RuntimeError:
        pass


def test_writers_produce_files():
    mods = [{"title": "Web", "module": "web", "target": "h:80",
             "checks": [{"name": "Fingerprint", "attack": "T1592.002", "command": "whatweb http://h"},
                        {"name": "Templates", "attack": "T1595", "command": "nuclei -u http://h"}]}]
    d = tempfile.mkdtemp(prefix="ct_")
    try:
        sh = os.path.join(d, "runners.sh"); ct.write_runner_script(mods, sh, "podman")
        body = open(sh, encoding="utf-8").read()
        assert "podman run" in body and "no exploit payloads" in body
        yml = os.path.join(d, "jobs.yaml"); n = ct.write_k8s_jobs(mods, yml)
        assert n == 2 and "kind: Job" in open(yml, encoding="utf-8").read()
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
