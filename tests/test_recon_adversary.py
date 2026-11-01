"""recon_chain + adversary — Phase 17 lifts.

Lock the three contracts that matter:
  1. recon_chain emits a 5-phase sequence with valid ATT&CK ids + noise scores.
  2. adversary profiles exist for the shipped actor list and each profile's
     path has valid ATT&CK ids in order.
  3. apply_overlay() boosts matching actions, is non-destructive on non-matches.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import adversary
import recon_chain

_ATTACK = re.compile(r"^T\d{4}(\.\d{3})?$")


# ---- recon_chain --------------------------------------------------------- #
def test_recon_chain_has_all_five_phases():
    c = recon_chain.build("acme.example")
    phase_ids = [p["id"] for p in c["phases"]]
    assert phase_ids == ["passive", "active", "hosts", "web", "vuln"]
    assert c["domain"] == "acme.example"


def test_recon_chain_steps_valid():
    c = recon_chain.build("acme.example")
    total = 0
    for ph in c["phases"]:
        for s in ph["steps"]:
            assert _ATTACK.match(s["attack"]), s["attack"]
            assert s["risk"] in ("safe", "intrusive")
            assert 0 <= s["noise"] <= 10
            assert "{domain}" not in s["command"]       # the placeholder got filled
            total += 1
    assert total >= 20                                   # we ship >= 20 steps across phases


def test_recon_chain_single_phase_filter():
    c = recon_chain.build("acme.example", phases=["passive"])
    assert len(c["phases"]) == 1 and c["phases"][0]["id"] == "passive"
    assert all(s["risk"] == "safe" for s in c["phases"][0]["steps"])


def test_recon_chain_projection_to_paths():
    c = recon_chain.build("acme.example")
    paths = recon_chain.to_findings(c)
    assert paths and all(p["kind"] == "recon" for p in paths)
    assert all(p["id"].startswith("RECON-") for p in paths)
    # Every step has an attack id matching the Mimir shape.
    for p in paths:
        for s in p["steps"]:
            assert _ATTACK.match(s["technique_id"])


# ---- adversary ---------------------------------------------------------- #
def test_adversary_profiles_ship_the_core_set():
    ids = {p["id"] for p in adversary.list_profiles()}
    expected = {"apt29", "apt28", "fin7", "volt_typhoon", "lazarus",
                "conti", "initial_access", "post_exploitation"}
    assert expected.issubset(ids), expected - ids


def test_every_profile_has_valid_attack_ids():
    for p in adversary.list_profiles():
        prof = adversary.get(p["id"])
        for tech_id, _name in prof["ttps"]:
            assert _ATTACK.match(tech_id), f"{p['id']}: {tech_id}"


def test_adversary_profile_as_path():
    p = adversary.profile_as_path("apt29")
    assert p and p["kind"] == "adversary"
    assert p["id"].startswith("ADV-")
    assert len(p["steps"]) >= 8
    assert all(_ATTACK.match(s["technique_id"]) for s in p["steps"])


def test_adversary_overlay_up_weights_matching_only():
    actions = [
        {"attack": "T1003.001", "score": 50, "title": "lsass dump"},        # in apt29
        {"attack": "T1595.002", "score": 60, "title": "nmap scan"},         # not in apt29
        {"attack": "T1528",     "score": 40, "title": "token theft"},       # in apt29
    ]
    out = adversary.apply_overlay(actions, "apt29", bonus=15)
    assert len(out) == 3
    scores = {a["title"]: a["score"] for a in out}
    assert scores["lsass dump"] == 50                   # T1003.001 NOT in apt29 — unchanged
    # scores for matching
    for a in out:
        if (a.get("trace") or {}).get("profile_match"):
            assert a["trace"]["profile_bonus"] == 15
    # non-matching actions MUST NOT have a trace addition
    nonmatch = next(a for a in out if a["title"] == "nmap scan")
    assert "profile_match" not in (nonmatch.get("trace") or {})


def test_adversary_overlay_unknown_profile_is_noop():
    actions = [{"attack": "T1190", "score": 50}]
    out = adversary.apply_overlay(actions, "no-such-profile")
    assert out == actions
