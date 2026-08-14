"""New testing domains: wireless/RF, Kubernetes, source/supply-chain, SaaS identity,
hypervisor, and macOS/Linux thick-client platform gating.

Locks: operator parsing, dispatch, ATT&CK/risk validity, and `when`-gating.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apptargets import (app_targets, parse_wireless, parse_k8s, parse_source,  # noqa: E402
                        parse_identity, parse_hypervisor, parse_thick)
from modules import dispatch_apps  # noqa: E402

_ATTACK = re.compile(r"^T\d{4}(\.\d{3})?$")


def _run(target):
    res = dispatch_apps([target], {"findings": []})
    assert res and res[0].get("checks"), "dispatch produced no checks for " + repr(target.get("kind"))
    return res[0]


def _names(result):
    return {c["name"] for c in result["checks"]}


def _assert_valid(result):
    for c in result["checks"]:
        assert _ATTACK.match(c["attack"]), "bad ATT&CK id: " + repr(c["attack"])
        assert c.get("risk", "safe") in ("safe", "intrusive"), "bad risk: " + repr(c.get("risk"))
        assert ":" not in c["name"], "check name must not contain a colon: " + c["name"]


# --- parsing -------------------------------------------------------------- #
def test_parse_wireless_band_vs_ssid():
    assert parse_wireless(["ble"])[0]["band"] == "ble"
    t = parse_wireless(["CorpWiFi"])[0]
    assert t["kind"] == "wireless" and t.get("ssid") == "CorpWiFi" and "band" not in t


def test_parse_identity_and_hypervisor_providers():
    i = parse_identity(["entra:contoso.onmicrosoft.com"])[0]
    assert i["provider"] == "entra" and i["tenant"] == "contoso.onmicrosoft.com"
    h = parse_hypervisor(["esxi:10.0.0.8"])[0]
    assert h["provider"] == "esxi" and h["host"] == "10.0.0.8"


def test_parse_source_and_k8s():
    assert parse_source(["./repo"])[0]["kind"] == "source"
    assert parse_k8s(["https://c:6443"])[0]["kind"] == "k8s"


def test_thick_platform_from_extension():
    assert parse_thick(["a.dmg"])[0]["platform"] == "macos"
    assert parse_thick(["a.elf"])[0]["platform"] == "linux"
    assert parse_thick(["a.exe"])[0]["platform"] == "windows"


def test_app_targets_dedup_new_kinds():
    ts = app_targets({"hosts": [], "findings": []}, wireless=["wifi", "wifi"], k8s=["c1"])
    kinds = [t["kind"] for t in ts]
    assert kinds.count("wireless") == 1 and kinds.count("k8s") == 1     # deduped


# --- dispatch + validity -------------------------------------------------- #
def test_all_new_domains_dispatch_valid():
    for t in ({"kind": "wireless", "ref": "wifi", "host": "wifi", "band": "wifi"},
              {"kind": "k8s", "ref": "c", "host": "c"},
              {"kind": "source", "ref": "./r", "host": "r"},
              {"kind": "identity", "ref": "entra", "provider": "entra", "host": "e"},
              {"kind": "hypervisor", "ref": "esxi", "provider": "esxi", "host": "h"}):
        _assert_valid(_run(t))


# --- when-gating ---------------------------------------------------------- #
def test_wireless_band_gating():
    ble = _names(_run({"kind": "wireless", "ref": "ble", "band": "ble", "host": "ble"}))
    assert "BLE enumeration" in ble
    assert "WPS exposure" not in ble                       # wifi-only check hidden for BLE


def test_thick_platform_gating():
    mac = _names(_run({"kind": "thick", "ref": "a.dmg", "host": "a", "platform": "macos"}))
    win = _names(_run({"kind": "thick", "ref": "a.exe", "host": "a", "platform": "windows"}))
    assert "Mach-O analysis" in mac and "DLL search-order hijack" not in mac
    assert "DLL search-order hijack" in win and "Mach-O analysis" not in win


def test_identity_provider_gating():
    okta = _names(_run({"kind": "identity", "ref": "okta", "provider": "okta", "host": "o"}))
    assert "Okta configuration & policy" in okta
    assert "Entra / M365 recon (authed)" not in okta
