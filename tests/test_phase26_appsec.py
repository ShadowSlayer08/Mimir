"""Phase 26 — AppSec surface in Autopilot v2.

Covers:
  * parsers.httpx: JSONL -> new_urls + new_hosts
  * parsers.subfinder: subdomain-per-line -> new_subdomains + new_hosts
  * parsers.feroxbuster: feroxbuster text + ffuf JSON + gobuster text
  * parsers dispatch routes "httpx", "subfinder", "feroxbuster" correctly
  * ParseResult new_urls/new_subdomains propagate through is_empty +
    total_items + to_dict
  * autopilot_loop._synth_app_targets builds {"kind":"web","host","ref"}
    rows from URLs AND from bare subdomains
  * autopilot_loop._merge_urls / _merge_subdomains are idempotent
  * autopilot_loop._restage_from_discoveries with new_urls calls
    modules.dispatch_apps and appends AppSec checks to AUTOPILOT-V2-SYNTH
"""
import os
import sys

os.environ["OLLAMA_HOST"] = "http://127.0.0.1:1"
os.environ["MIMIR_LLM_TIMEOUT"] = "0.5"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import autopilot_loop                           # noqa: E402
import parsers                                   # noqa: E402
from parsers.base import ParseResult             # noqa: E402


# --------------------------------------------------------------------------- #
# parsers.httpx
# --------------------------------------------------------------------------- #
_HTTPX_JSONL = """\
{"url":"https://api.lab/","host":"api.lab","status_code":200,"title":"API","tech":["nginx","react"],"webserver":"nginx/1.24"}
{"url":"https://admin.lab/dashboard","host":"admin.lab","status_code":403,"title":"","tech":["Django"]}
not json
"""


def test_httpx_parser_extracts_urls_and_hosts():
    r = parsers.dispatch("httpx -silent -json", _HTTPX_JSONL)
    assert r.source_tool == "httpx"
    assert len(r.new_urls) == 2
    assert {u["url"] for u in r.new_urls} == {"https://api.lab/", "https://admin.lab/dashboard"}
    assert "api.lab" in r.new_hosts
    assert "admin.lab" in r.new_hosts
    assert any(u["tech"] for u in r.new_urls)


def test_httpx_parser_empty_is_empty():
    r = parsers.dispatch("httpx -silent", "")
    assert r.is_empty()


# --------------------------------------------------------------------------- #
# parsers.subfinder
# --------------------------------------------------------------------------- #
_SUBFINDER = """\
www.example.com
api.example.com
admin.example.com
# comment line
https://cdn.example.com
127.0.0.1
"""


def test_subfinder_parser_extracts_subdomains_and_hosts():
    r = parsers.dispatch("subfinder -d example.com", _SUBFINDER)
    assert r.source_tool == "subfinder"
    subs = set(r.new_subdomains)
    assert {"www.example.com", "api.example.com",
            "admin.example.com", "cdn.example.com"} <= subs
    # Numeric IPs don't look like hostnames and should be filtered.
    assert "127.0.0.1" not in subs
    # Each subdomain is also a new_host.
    for s in subs:
        assert s in r.new_hosts


def test_subfinder_parser_filters_invalid_lines():
    r = parsers.dispatch("subfinder", "badline\n\nalso badline\n")
    assert r.is_empty()


# --------------------------------------------------------------------------- #
# parsers.feroxbuster — multiple shapes
# --------------------------------------------------------------------------- #
_FEROX_TEXT = """\
200       GET      12l    34w   56c https://api.lab/users
404       GET       0l     0w    0c https://api.lab/missing
301       GET       5l    12w  120c https://api.lab/login
"""


_FFUF_JSON = """{"results":[{"url":"https://api.lab/v1/items","status":200},{"url":"https://api.lab/v1/admin","status":403}]}"""


def test_feroxbuster_text_parser_extracts_urls():
    r = parsers.dispatch("feroxbuster -u https://api.lab", _FEROX_TEXT)
    urls = {u["url"] for u in r.new_urls}
    assert "https://api.lab/users" in urls
    assert "https://api.lab/login" in urls
    assert "https://api.lab/missing" in urls
    for u in r.new_urls:
        assert isinstance(u["status"], int)


def test_ffuf_json_parser_extracts_urls():
    r = parsers.dispatch("ffuf -u https://api.lab/FUZZ", _FFUF_JSON)
    urls = {u["url"] for u in r.new_urls}
    assert urls == {"https://api.lab/v1/items", "https://api.lab/v1/admin"}


def test_gobuster_text_parser_with_base_url():
    # gobuster emits just paths; the parser lifts the base from an earlier
    # URL. Seed one via feroxbuster, then follow with gobuster.
    stdout = _FEROX_TEXT + "\n/secret                (Status: 200) [Size: 42]\n"
    r = parsers.dispatch("gobuster dir -u https://api.lab", stdout)
    urls = {u["url"] for u in r.new_urls}
    assert any(u.endswith("/secret") for u in urls)


# --------------------------------------------------------------------------- #
# ParseResult plumbing for the new fields
# --------------------------------------------------------------------------- #
def test_parseresult_counts_urls_and_subdomains():
    pr = ParseResult(source_tool="t")
    pr.new_urls.append({"url": "https://x/"})
    pr.new_subdomains.append("sub.x.lab")
    assert not pr.is_empty()
    assert pr.total_items() == 2
    d = pr.to_dict()
    assert d["new_urls"] and d["new_subdomains"]


# --------------------------------------------------------------------------- #
# autopilot_loop AppSec plumbing
# --------------------------------------------------------------------------- #
def test_merge_urls_dedups():
    eng = {}
    autopilot_loop._merge_urls(eng, [{"url": "https://a/"}, {"url": "https://b/"}])
    added = autopilot_loop._merge_urls(eng, [{"url": "https://a/"},
                                             {"url": "https://c/"}])
    assert added == 1
    assert len(eng["appsec_urls"]) == 3


def test_merge_subdomains_dedups_case_insensitive():
    eng = {}
    autopilot_loop._merge_subdomains(eng, ["Sub.Example.Com"])
    added = autopilot_loop._merge_subdomains(eng, ["sub.example.com", "api.example.com"])
    assert added == 1
    assert len(eng["appsec_subdomains"]) == 2


def test_synth_app_targets_from_urls_and_subdomains():
    targets = autopilot_loop._synth_app_targets(
        [{"url": "https://api.lab/v1"}],
        ["admin.lab"])
    kinds = {t["kind"] for t in targets}
    assert kinds == {"web"}
    hosts = {t["host"] for t in targets}
    assert hosts == {"api.lab", "admin.lab"}
    # Subdomains get both http + https targets.
    refs = {t["ref"] for t in targets if t["host"] == "admin.lab"}
    assert "http://admin.lab/" in refs and "https://admin.lab/" in refs


def test_restage_from_discoveries_handles_new_urls_only():
    # No new services, just URLs — AppSec dispatcher must still get called.
    eng = {"hosts": [], "findings": [], "attack_paths": []}
    new_urls = [{"url": "https://api.lab/", "status": 200}]
    added, modules_called = autopilot_loop._restage_from_discoveries(
        eng, [], mode="vapt", noise_ceiling=10,
        accept_risk=("safe", "intrusive"),
        new_urls=new_urls)
    # Even if the KB is sparse, dispatch_apps should return at least one
    # web_app module instance; added may be 0 if every check is intrusive
    # beyond the ceiling, but modules_called > 0 proves wiring is live.
    assert modules_called > 0
    if added > 0:
        synth = eng["attack_paths"][0]
        assert synth["id"] == "AUTOPILOT-V2-SYNTH"
        # Any lifted step should cite a web_app-ish module.
        mods = {s["module"] for s in synth["steps"]}
        assert any(m in mods for m in ("web", "web_app", "web_recon"))


def test_restage_from_discoveries_handles_subdomains_only():
    eng = {"hosts": [], "findings": [], "attack_paths": []}
    added, modules_called = autopilot_loop._restage_from_discoveries(
        eng, [], mode="vapt", noise_ceiling=10,
        accept_risk=("safe", "intrusive"),
        new_subdomains=["admin.lab"])
    assert modules_called > 0


def test_restage_from_discoveries_empty_everything():
    eng = {"hosts": [], "findings": [], "attack_paths": []}
    added, modules_called = autopilot_loop._restage_from_discoveries(
        eng, [], mode="vapt", new_urls=[], new_subdomains=[])
    assert added == 0 and modules_called == 0
