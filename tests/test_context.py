"""Context-aware commands — fill discovered/operator facts, never secrets."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from context import infer, infer_domain, fill, apply  # noqa: E402


def test_infer_domain_from_hostnames():
    rep = {"hosts": [{"hostnames": ["dc01.corp.lab"], "ports": []},
                     {"hostnames": ["web.corp.lab"], "ports": []}]}
    assert infer_domain(rep) == "corp.lab"


def test_infer_context():
    rep = {"hosts": [{"hostnames": ["dc01.corp.lab"], "ip": "10.0.0.5",
                      "ports": [{"service": {"name": "kerberos"}}]}]}
    ctx = infer(rep)
    assert ctx["domain"] == "corp.lab" and ctx["company"] == "corp" and ctx["dc"] == "dc01.corp.lab"


def test_fill_non_secret_only():
    # user + domain filled; <pass> preserved (secrets never baked in)
    out = fill("hydra -l <user> -p <pass> <domain>", {"user": "svc", "domain": "corp.lab"})
    assert out == "hydra -l svc -p <pass> corp.lab"


def test_overrides_win_and_secrets_rejected():
    ctx = infer({"hosts": []}, {"domain": "acme.io", "user": "admin", "password": "nope", "apikey": "x"})
    assert ctx["domain"] == "acme.io" and ctx["user"] == "admin"
    assert "password" not in ctx and "apikey" not in ctx        # secret-ish keys rejected


def test_apply_mutates_commands_and_guidance():
    mods = [{"checks": [{"command": "nxc smb <dc> -u <user>"}]}]
    paths = [{"steps": [{"command": "secretsdump <domain>", "guidance": "as <user>"}]}]
    apply(mods, paths, {"dc": "dc01", "user": "svc", "domain": "corp.lab"})
    assert mods[0]["checks"][0]["command"] == "nxc smb dc01 -u svc"
    assert paths[0]["steps"][0]["command"] == "secretsdump corp.lab"
    assert paths[0]["steps"][0]["guidance"] == "as svc"
