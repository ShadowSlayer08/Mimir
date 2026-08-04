"""AD relationship graph: BloodHound ingest -> staged privilege-escalation paths."""
import json
import os
import shutil
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ad_graph import ADGraph, ingest  # noqa: E402

D = "S-1-5-21-1-1-1"


def _dataset(tmp):
    # Domain Users --GenericAll--> SVC --MemberOf--> Domain Admins  (classic any-user->DA)
    groups = {"meta": {"type": "groups", "version": 5}, "data": [
        {"ObjectIdentifier": f"{D}-512", "Properties": {"name": "DOMAIN ADMINS@LAB", "highvalue": True},
         "Members": [{"ObjectIdentifier": f"{D}-1106", "ObjectType": "User"}], "Aces": []},
        {"ObjectIdentifier": f"{D}-513", "Properties": {"name": "DOMAIN USERS@LAB"},
         "Members": [{"ObjectIdentifier": f"{D}-1105", "ObjectType": "User"}], "Aces": []}]}
    users = {"meta": {"type": "users", "version": 5}, "data": [
        {"ObjectIdentifier": f"{D}-1105", "Properties": {"name": "LOWPRIV@LAB"}, "Aces": []},
        {"ObjectIdentifier": f"{D}-1106", "Properties": {"name": "SVC@LAB"},
         "Aces": [{"PrincipalSID": f"{D}-513", "RightName": "GenericAll", "PrincipalType": "Group"}]}]}
    for nm, doc in [("groups.json", groups), ("users.json", users)]:
        with open(os.path.join(tmp, nm), "w", encoding="utf-8") as fh:
            json.dump(doc, fh)


def test_graph_ingest_and_edges():
    tmp = tempfile.mkdtemp(prefix="bh_")
    try:
        _dataset(tmp)
        g = ADGraph().load_bloodhound(tmp)
        assert len(g.nodes) == 4
        assert f"{D}-512" in g.high                            # DA is high-value (RID + flag)
        assert (f"{D}-1106", "GenericAll") in g.edges[f"{D}-513"]   # DU has GenericAll on SVC
        assert (f"{D}-512", "MemberOf") in g.edges[f"{D}-1106"]     # SVC member of DA
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_derive_path_to_domain_admin():
    tmp = tempfile.mkdtemp(prefix="bh_")
    try:
        _dataset(tmp)
        g, paths = ingest(tmp)                                 # default owned = Domain Users
        assert f"{D}-513" in g.owned
        assert paths, "expected a privilege path to Domain Admins"
        p = paths[0]
        assert p["kind"] == "domain" and p["severity"] == "critical"
        assert "DOMAIN ADMINS@LAB" in p["name"]
        assert "T1098" in [s["technique_id"] for s in p["steps"]]   # GenericAll abuse
        assert all(s["abuse"]["how"] for s in p["steps"])           # every edge has guidance
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_owned_override_and_zip():
    tmp = tempfile.mkdtemp(prefix="bh_")
    try:
        _dataset(tmp)
        zp = os.path.join(tmp, "bh.zip")
        with zipfile.ZipFile(zp, "w") as z:
            z.write(os.path.join(tmp, "groups.json"), "groups.json")
            z.write(os.path.join(tmp, "users.json"), "users.json")
        g, paths = ingest(zp, owned=["SVC@LAB"])               # start from SVC directly
        assert f"{D}-1106" in g.owned and len(g.nodes) == 4    # zip ingested
        assert paths and paths[0]["steps"][0]["basis"].startswith("SVC@LAB")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
