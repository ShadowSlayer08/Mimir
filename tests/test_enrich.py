"""Live-intel enrichment (enrich.py) + per-asset risk config (assess._load_assets).

No network: the feed parsers are tested against local fixtures, and the offline
path is verified to degrade to empty (engine falls back to its offline behavior).
"""
import gzip
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import enrich  # noqa: E402
from assess import _load_assets  # noqa: E402


def test_parse_kev():
    fd, p = tempfile.mkstemp(suffix=".json"); os.close(fd)
    try:
        with open(p, "w", encoding="utf-8") as fh:
            json.dump({"vulnerabilities": [{"cveID": "CVE-2021-1234"},
                                           {"cveID": "cve-2017-0144"},
                                           {"notacve": "x"}]}, fh)
        kev = enrich.parse_kev(p)
        assert "CVE-2021-1234" in kev and "CVE-2017-0144" in kev   # upper-cased
        assert len(kev) == 2                                       # non-CVE entry dropped
    finally:
        os.unlink(p)


def test_parse_epss():
    fd, p = tempfile.mkstemp(suffix=".csv.gz"); os.close(fd)
    try:
        with gzip.open(p, "wt", encoding="utf-8") as fh:
            fh.write("#model_version:v2025,score_date:2026-06-21\n")
            fh.write("cve,epss,percentile\n")
            fh.write("CVE-2021-1234,0.97531,0.999\n")
            fh.write("CVE-2020-0001,0.00100,0.10\n")
            fh.write(",0.5,0.99\n")                                 # malformed: empty CVE id
        m = enrich.parse_epss(p)
        assert abs(m["CVE-2021-1234"] - 0.97531) < 1e-6
        assert m["CVE-2020-0001"] == 0.001
        assert "" not in m                                          # empty-CVE row skipped
        assert "CVE" not in m                                       # header/comment skipped
    finally:
        os.unlink(p)


def test_enrich_offline_no_cache_is_empty():
    d = tempfile.mkdtemp(prefix="enrich_")
    orig = enrich.app_path
    enrich.app_path = lambda name: os.path.join(d, name)   # empty cache dir
    try:
        kev, epss = enrich.enrich(offline=True)            # offline + no cache -> empty, no raise
        assert kev == set() and epss == {}
    finally:
        enrich.app_path = orig
        shutil.rmtree(d, ignore_errors=True)


def test_load_assets_levels_and_floats():
    fd, p = tempfile.mkstemp(suffix=".yaml"); os.close(fd)
    try:
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("dc01:\n  exposure: internet\n  business: critical\n"
                     "ws01:\n  exposure: 0.3\n  business: low\n")
        cfg = _load_assets(p)
        assert cfg["dc01"]["exposure"] == 1.0 and cfg["dc01"]["business"] == 1.0   # level names
        assert cfg["ws01"]["exposure"] == 0.3 and cfg["ws01"]["business"] == 0.2   # float + level
    finally:
        os.unlink(p)
