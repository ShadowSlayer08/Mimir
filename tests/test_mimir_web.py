"""mimir_web — DB schema + auth + session cookies + CSRF + role-at-least.

Locks the operator-workflow web app's core contracts (no HTTP server test here —
the DB + auth layers are the risky bits).
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mimir_web import auth as _auth
from mimir_web import db as _db


def _tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db", prefix="mimir-web-")
    os.close(fd); os.unlink(path)
    return path


# ---- DB + auth round-trip -------------------------------------------------
def test_bootstrap_admin_and_login():
    p = _tmp_db()
    con = None
    try:
        con = _db.connect(p)
        created, uid = _db.bootstrap_admin(con, "ops@example", "correct-horse-battery-staple")
        assert created and uid == 1
        # Second bootstrap is a no-op (we don't want a privilege-escalation path).
        created2, uid2 = _db.bootstrap_admin(con, "attacker@example", "another-pass-12345")
        assert created2 is False
        user = _db.get_user_by_email(con, "ops@example")
        assert user and user["role"] == "admin"
        assert _db.verify_password("correct-horse-battery-staple",
                                   user["pw_hash"], user["pw_salt"])
        assert not _db.verify_password("wrong-passphrase",
                                       user["pw_hash"], user["pw_salt"])
    finally:
        if con is not None:
            con.close()
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                if os.path.exists(p + suffix):
                    os.unlink(p + suffix)
            except OSError:
                pass


def test_role_hierarchy():
    assert _db.role_at_least({"role": "admin"}, "admin")
    assert _db.role_at_least({"role": "admin"}, "operator")
    assert _db.role_at_least({"role": "lead"}, "operator")
    assert not _db.role_at_least({"role": "operator"}, "lead")
    assert not _db.role_at_least({"role": "viewer"}, "operator")
    assert not _db.role_at_least(None, "viewer")


def test_session_sign_and_verify():
    p = _tmp_db()
    con = None
    try:
        con = _db.connect(p)
        _db.bootstrap_admin(con, "op@ex", "passphrase-twelve-chars")
        sid = _auth.new_session(con, 1)
        user = _auth.verify_session(con, sid)
        assert user and user["email"] == "op@ex"
        # Tampered session is rejected.
        assert _auth.verify_session(con, sid + "x") is None
        assert _auth.verify_session(con, "garbage") is None
    finally:
        if con is not None:
            con.close()
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                if os.path.exists(p + suffix):
                    os.unlink(p + suffix)
            except OSError:
                pass


def test_csrf_double_submit():
    sid = "test-session-xyz"
    csrf = _auth.expected_csrf(sid)
    assert _auth.verify_csrf(sid, csrf)
    assert not _auth.verify_csrf(sid, "wrong-token")
    assert not _auth.verify_csrf("", csrf)


# ---- engagement + jobs + audit --------------------------------------------
def test_engagement_crud_and_audit():
    p = _tmp_db()
    con = None
    try:
        con = _db.connect(p)
        _db.bootstrap_admin(con, "op@ex", "passphrase-twelve-chars")
        eid = _db.create_engagement(
            con, 1, name="Acme Q4",
            scope={"in_scope": ["10.0.0.0/24"]},
            roe_text="no DoS")
        assert eid == 1
        eng = _db.get_engagement(con, eid)
        assert eng["name"] == "Acme Q4" and eng["status"] == "draft"
        _db.update_engagement(con, 1, eid, status="active")
        assert _db.get_engagement(con, eid)["status"] == "active"
        audit_rows = _db.recent_audit(con, engagement_id=eid)
        actions = {r["action"] for r in audit_rows}
        assert {"engagement_create", "engagement_update"} <= actions
    finally:
        if con is not None:
            con.close()
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                if os.path.exists(p + suffix):
                    os.unlink(p + suffix)
            except OSError:
                pass


def test_jobs_lifecycle():
    p = _tmp_db()
    con = None
    try:
        con = _db.connect(p)
        _db.bootstrap_admin(con, "op@ex", "passphrase-twelve-chars")
        eid = _db.create_engagement(con, 1, name="E1", scope={})
        jid = _db.create_job(con, 1, eid, "scan", {"mode": "vapt"})
        _db.set_job_state(con, jid, "running", pid=1234)
        _db.set_job_state(con, jid, "done", exit_code=0)
        jobs = _db.list_jobs(con, engagement_id=eid)
        assert len(jobs) == 1
        assert jobs[0]["state"] == "done" and jobs[0]["exit_code"] == 0
    finally:
        if con is not None:
            con.close()
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                if os.path.exists(p + suffix):
                    os.unlink(p + suffix)
            except OSError:
                pass


# ---- Crucible bridge contract --------------------------------------------
def test_crucible_bridge_offline_safe():
    """With no CRUCIBLE_URL/key, the bridge reports unreachable and returns None."""
    import crucible_bridge as cb
    saved_url = os.environ.pop("CRUCIBLE_URL", None)
    saved_key = os.environ.pop("CRUCIBLE_API_KEY", None)
    saved_mu  = os.environ.pop("MIMIR_CRUCIBLE_URL", None)
    saved_mk  = os.environ.pop("MIMIR_CRUCIBLE_API_KEY", None)
    try:
        assert cb.available() is False
        assert cb.forward_ai_target({"ref": "https://x"}) is None
        assert cb.collect_findings("job-123") == []
        s = cb.status()
        assert s["url_configured"] is False and s["key_configured"] is False
        # Signature verification fails without a key.
        assert cb.verify_inbound_signature("POST", "/x", b"body", "deadbeef") is False
    finally:
        for k, v in (("CRUCIBLE_URL", saved_url), ("CRUCIBLE_API_KEY", saved_key),
                     ("MIMIR_CRUCIBLE_URL", saved_mu), ("MIMIR_CRUCIBLE_API_KEY", saved_mk)):
            if v is not None:
                os.environ[k] = v


def test_crucible_signature_roundtrip():
    """A signature produced with the same key must verify."""
    import crucible_bridge as cb
    saved = os.environ.get("CRUCIBLE_API_KEY")
    os.environ["CRUCIBLE_API_KEY"] = "test-shared-secret-12345"
    try:
        sig = cb._sign("POST", "/bridge/crucible/finding", b'{"x":1}')
        assert cb.verify_inbound_signature("POST", "/bridge/crucible/finding", b'{"x":1}', sig)
        assert not cb.verify_inbound_signature("POST", "/bridge/crucible/finding", b'{"x":2}', sig)
    finally:
        if saved is None:
            os.environ.pop("CRUCIBLE_API_KEY", None)
        else:
            os.environ["CRUCIBLE_API_KEY"] = saved
