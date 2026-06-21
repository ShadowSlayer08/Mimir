"""Evidence ingestion: gnmap parse, inventory merge, indicator scan, ingest_dir."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evidence import (parse_gnmap, merge_inventories, scan_text_indicators,  # noqa: E402
                      ingest_dir, _blank_host)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO, "tests", "fixtures", "broad_scan.xml")


def _host(ip, *svc_ports):
    h = _blank_host()
    h["ip"] = ip
    for port, name in svc_ports:
        h["ports"].append({"port": port, "protocol": "tcp", "state": "open", "reason": "",
                           "service": {"name": name, "product": "", "version": "", "extrainfo": "",
                                       "tunnel": "", "ostype": "", "cpe": []},
                           "scripts": {}, "ssl_enum": None, "least_strength": None, "cert": None})
    return h


def test_parse_gnmap():
    g = "Host: 10.0.0.1 (web)\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///\tIgnored State: closed"
    hosts = parse_gnmap(g)
    assert len(hosts) == 1 and hosts[0]["ip"] == "10.0.0.1"
    assert {p["port"] for p in hosts[0]["ports"]} == {22, 80}


def test_merge_inventories_dedup():
    a = [_host("10.0.0.1", (22, "ssh"))]
    b = [_host("10.0.0.1", (80, "http")), _host("10.0.0.2", (445, "microsoft-ds"))]
    merged = merge_inventories([a, b])
    assert len(merged) == 2
    h1 = next(h for h in merged if h["ip"] == "10.0.0.1")
    assert {p["port"] for p in h1["ports"]} == {22, 80}      # union of both scans


def test_scan_text_indicators():
    text = ("CVE-2017-0144 — host looks VULNERABLE\n"
            "found creds admin:Password123\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n")
    titles = " | ".join(f["title"] for f in scan_text_indicators(text, "loot.txt"))
    assert "CVE" in titles and "Private key" in titles
    assert "VULNERABLE" in titles or "Credential" in titles


def test_ingest_dir(tmpdir=None):
    d = tempfile.mkdtemp(prefix="ev_")
    try:
        with open(os.path.join(d, "recon.xml"), "w", encoding="utf-8") as fh:
            fh.write(open(FIXTURE, encoding="utf-8").read())
        with open(os.path.join(d, "loot.txt"), "w", encoding="utf-8") as fh:
            fh.write("svc:S3cret!  CVE-2021-1234 password found\n")
        hosts, meta, evidence, manifest = ingest_dir(d)
        assert len(hosts) >= 1
        assert len(evidence) >= 1
        assert any(k == "nmap-xml" for _, k, _ in manifest)
        assert any(k == "evidence" for _, k, _ in manifest)
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
