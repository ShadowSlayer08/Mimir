"""AppSec pillar: application targets + the OWASP-WSTG web module (target-driven)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apptargets import web_targets_from_report, parse_web, app_targets  # noqa: E402
from modules import dispatch, dispatch_apps  # noqa: E402
from modules.web_app import WebAppModule  # noqa: E402


def _report():
    return {
        "hosts": [
            {"ip": "10.0.0.5", "hostnames": ["dc01.lab"], "ipv6": "", "os": [],
             "ports": [
                 {"port": 443, "protocol": "tcp",
                  "service": {"name": "https", "product": "nginx", "version": "1.20", "tunnel": "ssl"}},
                 {"port": 8080, "protocol": "tcp",
                  "service": {"name": "http-alt", "product": "", "version": "", "tunnel": ""}},
             ]},
        ],
        "findings": [
            {"host": "dc01.lab", "port": 443, "category": "CVE (vulners)", "severity": "high",
             "title": "nginx 1.20: known CVEs", "cve": ["CVE-2021-1"]},
        ],
    }


def test_auto_promote_http_services():
    t = web_targets_from_report(_report())
    refs = {x["ref"] for x in t}
    assert "https://dc01.lab" in refs          # 443 -> https, default port dropped
    assert "http://dc01.lab:8080" in refs      # http-alt -> http with explicit port
    assert all(x["kind"] == "web" for x in t)


def test_parse_web_normalises():
    t = parse_web(["example.com", "https://h2:8443/app, http://h3"])
    refs = [x["ref"] for x in t]
    assert "http://example.com" in refs        # bare host -> http
    assert any(x["scheme"] == "https" and x["port"] == 8443 for x in t)
    assert len(t) == 3                          # comma + whitespace split


def test_web_module_checks_carry_owasp_cwe_attack():
    tgt = {"kind": "web", "ref": "https://dc01.lab", "label": "dc01.lab", "host": "dc01.lab",
           "ip": "10.0.0.5", "port": 443, "scheme": "https", "tls": True}
    res = WebAppModule().assess_target(tgt, _report()["findings"])[0].to_dict()
    assert res["module"] == "web_app"
    chk = {c["name"]: c for c in res["checks"]}
    assert chk["Fingerprint"]["owasp"].startswith("WSTG")
    assert chk["Fingerprint"]["cwe"].startswith("CWE")
    assert all(c["attack"] for c in res["checks"])         # every check ATT&CK-tagged
    assert res["severity"] == "high"                       # inherits the related CVE finding


def test_intrusive_web_checks_hidden_in_vapt():
    rep = _report()
    apps = app_targets(rep)
    full = dispatch_apps(apps, rep, mode="redteam")
    vapt = dispatch_apps(apps, rep, mode="vapt")

    def names(results):
        return {c["name"] for r in results for c in r["checks"]}
    assert {"SQL injection", "Command injection"} <= names(full)   # shown in red team
    assert not ({"SQL injection", "Command injection"} & names(vapt))  # hidden in VAPT (intrusive)
    assert "Fingerprint" in names(vapt)                    # safe checks still shown
    assert "XSS" in names(vapt)                            # dalfox XSS check is safe/staged


def test_dispatch_merges_app_results():
    rep = _report()
    mods = dispatch(rep, mode="redteam", app_targets=app_targets(rep))
    assert any(m["module"] == "web_app" for m in mods)     # app results merged with host modules


def test_parse_web_ipv6():
    t = parse_web(["http://[::1]:8080", "https://[2001:db8::1]"])
    assert any(x["host"] == "::1" and x["port"] == 8080 for x in t)        # bracketed IPv6 + port
    assert any(x["host"] == "2001:db8::1" and x["port"] == 443 for x in t)


def test_app_targets_dedup_default_port():
    rep = {"hosts": [{"ip": "10.0.0.9", "hostnames": ["h"], "ipv6": "",
                      "ports": [{"port": 443, "service": {"name": "https", "tunnel": "ssl"}}]}]}
    # auto-promoted https://h and operator https://h:443 are the SAME target -> deduped
    t = [x for x in app_targets(rep, web=["https://h:443"]) if x["host"] == "h"]
    assert len(t) == 1


def test_web_host_originates_t1190_path():
    from attack_path_engine import generate_paths
    rep = {"findings": [], "hosts": [
        {"ip": "10.0.0.9", "hostnames": ["shop.lab"], "ipv6": "",
         "ports": [{"port": 443, "service": {"name": "https", "tunnel": "ssl"}}]}]}
    paths = generate_paths(rep)
    # a web host with no other findings still originates an Initial-Access (T1190) entry
    assert any(p["kind"] == "webapp" and p["steps"][0]["technique_id"] == "T1190" for p in paths)


def test_api_target_and_module():
    from apptargets import parse_api
    from modules.api import APIModule
    t = parse_api(["https://api.lab/v1"])[0]
    assert t["kind"] == "api" and t["scheme"] == "https"
    res = APIModule().assess_target(t, [])[0].to_dict()
    assert res["module"] == "api"
    names = {c["name"] for c in res["checks"]}
    assert "BOLA (object-level authz)" in names            # OWASP API1:2023
    assert all(c["attack"] for c in res["checks"])
    assert any(c["owasp"].startswith("API") for c in res["checks"])   # API-Top-10 refs


def test_api_intrusive_hidden_in_vapt():
    from modules import dispatch_apps
    from apptargets import parse_api
    rep = {"hosts": [], "findings": []}
    apps = parse_api(["https://api.lab"])
    full = {c["name"] for r in dispatch_apps(apps, rep, mode="redteam") for c in r["checks"]}
    vapt = {c["name"] for r in dispatch_apps(apps, rep, mode="vapt") for c in r["checks"]}
    assert "Injection" in full and "Injection" not in vapt            # intrusive hidden in VAPT
    assert "BOLA (object-level authz)" in vapt                        # safe shown


def test_dispatch_routes_web_and_api():
    rep = _report()
    mods = dispatch(rep, mode="redteam", app_targets=app_targets(rep, api=["https://api.lab"]))
    kinds = {m["module"] for m in mods}
    assert "web_app" in kinds and "api" in kinds           # both AppSec modules dispatched


def test_mobile_and_thick_targets_and_modules():
    from apptargets import parse_mobile, parse_thick
    from modules.mobile import MobileModule
    from modules.thick_client import ThickClientModule
    m = parse_mobile(["/tmp/app.apk"])[0]
    assert m["kind"] == "mobile" and m["platform"] == "android" and m["host"] == "app.apk"
    assert parse_mobile(["Payload.ipa"])[0]["platform"] == "ios"    # extension -> platform
    mr = MobileModule().assess_target(m, [])[0].to_dict()
    assert mr["module"] == "mobile" and any(c["owasp"].startswith("MASVS") for c in mr["checks"])
    t = parse_thick(["C:/apps/client.exe"])[0]
    assert t["kind"] == "thick" and t["host"] == "client.exe"
    tr = ThickClientModule().assess_target(t, [])[0].to_dict()
    assert tr["module"] == "thick" and all(c["attack"] for c in tr["checks"])   # CWE-mapped, ATT&CK-tagged


def test_mobile_thick_intrusive_muting_and_dispatch():
    from modules import dispatch_apps
    rep = {"hosts": [], "findings": []}
    apps = app_targets(rep, mobile=["/tmp/a.apk"], thick=["/tmp/c.exe"])
    assert {"mobile", "thick"} <= {r["module"] for r in dispatch_apps(apps, rep, mode="redteam")}
    vnames = {c["name"] for r in dispatch_apps(apps, rep, mode="vapt") for c in r["checks"]}
    rnames = {c["name"] for r in dispatch_apps(apps, rep, mode="redteam") for c in r["checks"]}
    assert "Dynamic instrumentation" in rnames and "Dynamic instrumentation" not in vnames  # frida intrusive


def test_cloud_targets_and_provider_scoping():
    from apptargets import parse_cloud
    from modules.cloud import CloudModule
    t = parse_cloud(["aws:123456789012", "azure", "notacloud"])
    assert {x["provider"] for x in t} == {"aws", "azure"}          # unknown provider dropped
    aws = CloudModule().assess_target(
        {"kind": "cloud", "provider": "aws", "ref": "aws", "account": "1"}, [])[0].to_dict()
    names = {c["name"] for c in aws["checks"]}
    assert "AWS posture scan" in names                            # aws-scoped shown
    assert "GCP posture scan" not in names                        # gcp-scoped hidden for aws
    assert "Public cloud asset discovery" in names                # cross-provider (always)
    assert all(c["attack"] for c in aws["checks"])                # ATT&CK-Cloud tagged


def test_cloud_intrusive_hidden_and_dispatch():
    from modules import dispatch_apps
    rep = {"hosts": [], "findings": []}
    apps = app_targets(rep, cloud=["aws"])
    assert any(r["module"] == "cloud" for r in dispatch_apps(apps, rep, mode="redteam"))
    vn = {c["name"] for r in dispatch_apps(apps, rep, mode="vapt") for c in r["checks"]}
    assert "Credential / role abuse" not in vn                    # intrusive hidden in VAPT
