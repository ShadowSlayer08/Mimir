"""Read-only web API over the engagement contract (webapi.route / load_engagement)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import webapi  # noqa: E402

PAY = {"schema": "redengine.engagement",
       "meta": {"mode": "vapt", "totals": {"hosts": 1, "findings": 2},
                "severity_counts": {"high": 1}},
       "hosts": [{"label": "h", "grade": "C"}],
       "findings": [{"host": "h", "severity": "high", "title": "t", "owasp": [], "cwe": []}],
       "attack_paths": [{"id": "AP-001", "name": "x", "steps": []}],
       "killchain": {"stages": []}}


def test_route_health_and_engagement():
    s, ct, body = webapi.route(PAY, "/health")
    assert s == 200 and json.loads(body)["status"] == "ok"
    s, ct, body = webapi.route(PAY, "/api/engagement")
    assert s == 200 and json.loads(body)["schema"] == "redengine.engagement"


def test_route_slices_and_unknown():
    for name, expect in [("hosts", list), ("findings", list), ("attack_paths", list),
                         ("meta", dict), ("killchain", dict)]:
        s, ct, body = webapi.route(PAY, "/api/" + name)
        assert s == 200 and isinstance(json.loads(body), expect)
    assert webapi.route(PAY, "/api/bogus")[0] == 404


def test_route_spa_passthrough():
    assert webapi.route(PAY, "/") is None          # non-API path -> SPA served by the handler


def test_load_engagement_validates():
    fd, p = tempfile.mkstemp(suffix=".json"); os.close(fd)
    try:
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(PAY, fh)
        assert webapi.load_engagement(p)["schema"] == "redengine.engagement"
        with open(p, "w", encoding="utf-8") as fh:
            json.dump({"nope": 1}, fh)
        try:
            webapi.load_engagement(p)
            assert False, "expected ValueError on non-engagement JSON"
        except ValueError:
            pass
    finally:
        os.unlink(p)
