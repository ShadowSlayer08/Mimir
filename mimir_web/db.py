#!/usr/bin/env python3
"""mimir_web.db — SQLite schema + helpers for the operator-workflow web app.

Authorized / lab / CTF / VAPT / red-team use only.

Four tables:
  users         — operators + roles (admin / lead / operator / viewer)
  engagements   — per-engagement metadata, scope, ROE, status
  jobs          — background scan jobs tracked by state (queued/running/done/err)
  audit         — append-only log of every state-changing action (RBAC audit trail)

The on-disk file is the operator's workstation DB (`~/.mimir/mimir.db` by
default). All credentials are hashed with scrypt (stdlib hashlib). Session
tokens are HMAC-signed cookies with a server-side rotating key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone

# Role hierarchy — numeric so "at-least" checks are easy.
ROLES = {"viewer": 10, "operator": 20, "lead": 30, "admin": 40}


_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT UNIQUE NOT NULL,
    pw_hash     TEXT NOT NULL,                            -- scrypt base64
    pw_salt     TEXT NOT NULL,                            -- 16 bytes base64
    role        TEXT NOT NULL DEFAULT 'operator',
    totp_secret TEXT,                                     -- optional
    created_at  TEXT NOT NULL,
    disabled    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS engagements(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    client      TEXT,
    jurisdiction TEXT,
    status      TEXT NOT NULL DEFAULT 'draft',            -- draft/active/closed
    noise_profile TEXT NOT NULL DEFAULT 'normal',         -- stealth/normal/aggressive
    scope_json  TEXT,                                     -- {in_scope,out_of_scope,windows,...}
    roe_text    TEXT,                                     -- the original ROE prose
    roe_parsed_json TEXT,                                 -- roe_parse output
    engagement_json TEXT,                                 -- the current assess --emit-json contents
    ledger_db   TEXT,                                     -- per-engagement ledger path
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,                            -- scan / appsec / adgraph / report / etc.
    state       TEXT NOT NULL DEFAULT 'queued',           -- queued/running/done/error
    args_json   TEXT,                                     -- opaque, kind-specific
    pid         INTEGER,
    log_path    TEXT,
    started_at  TEXT,
    ended_at    TEXT,
    exit_code   INTEGER,
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    user_id     INTEGER REFERENCES users(id),
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
    action      TEXT NOT NULL,
    detail      TEXT
);

CREATE TABLE IF NOT EXISTS kv(
    k TEXT PRIMARY KEY, v TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS engagements_status ON engagements(status);
CREATE INDEX IF NOT EXISTS jobs_eng          ON jobs(engagement_id);
CREATE INDEX IF NOT EXISTS audit_eng         ON audit(engagement_id);
"""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_db_path():
    base = os.environ.get("MIMIR_WEB_DB",
                          os.environ.get("VANTAGE_WEB_DB"))
    if base:
        return base
    home = os.path.expanduser("~")
    d = os.path.join(home, ".mimir")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "mimir.db")


# --------------------------------------------------------------------------- #
# Password hashing — stdlib scrypt. Parameters per OWASP 2024 (CPU/memory cost).
_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_LEN = 32
_SALT_BYTES = 16
# scrypt maxmem default in Python's OpenSSL binding is ~32 MB; our N/r/p
# combination lands right on that line and intermittently fails. Bump to 64 MB
# which still fits trivially on an operator workstation.
_SCRYPT_MAXMEM = 64 * 1024 * 1024


def hash_password(password):
    salt = secrets.token_bytes(_SALT_BYTES)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                         n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
                         dklen=_SCRYPT_LEN, maxmem=_SCRYPT_MAXMEM)
    import base64
    return base64.b64encode(key).decode("ascii"), base64.b64encode(salt).decode("ascii")


def verify_password(password, pw_hash_b64, salt_b64):
    import base64
    try:
        salt = base64.b64decode(salt_b64)
        want = base64.b64decode(pw_hash_b64)
    except Exception:
        return False
    try:
        key = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                             n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
                             dklen=_SCRYPT_LEN, maxmem=_SCRYPT_MAXMEM)
    except Exception:
        return False
    return hmac.compare_digest(key, want)


# --------------------------------------------------------------------------- #
def connect(path=None):
    """Open the DB; run schema; return a connection."""
    path = path or default_db_path()
    con = sqlite3.connect(path, timeout=5.0, isolation_level=None)        # autocommit
    con.row_factory = sqlite3.Row
    con.executescript(_SCHEMA)
    return con


# ---- bootstrap + users --------------------------------------------------- #
def bootstrap_admin(con, email, password, role="admin"):
    """Create the first user if the users table is empty. Returns (created, user_id).
    Called from the CLI during initial setup."""
    row = con.execute("SELECT COUNT(*) FROM users").fetchone()
    if row[0] > 0:
        return False, None
    pwh, salt = hash_password(password)
    cur = con.execute(
        "INSERT INTO users(email,pw_hash,pw_salt,role,created_at) VALUES(?,?,?,?,?)",
        (email.lower().strip(), pwh, salt, role, _now()))
    audit(con, cur.lastrowid, None, "bootstrap_admin", email)
    return True, cur.lastrowid


def get_user_by_email(con, email):
    r = con.execute("SELECT * FROM users WHERE email = ?",
                    (email.lower().strip(),)).fetchone()
    return dict(r) if r else None


def get_user(con, user_id):
    r = con.execute("SELECT * FROM users WHERE id = ?", (int(user_id),)).fetchone()
    return dict(r) if r else None


def list_users(con):
    return [dict(r) for r in con.execute(
        "SELECT id,email,role,created_at,disabled FROM users ORDER BY id").fetchall()]


def add_user(con, actor_id, email, password, role="operator"):
    pwh, salt = hash_password(password)
    cur = con.execute(
        "INSERT INTO users(email,pw_hash,pw_salt,role,created_at) VALUES(?,?,?,?,?)",
        (email.lower().strip(), pwh, salt, role, _now()))
    audit(con, actor_id, None, "user_add", f"{email} role={role}")
    return cur.lastrowid


def set_role(con, actor_id, user_id, role):
    con.execute("UPDATE users SET role = ? WHERE id = ?", (role, int(user_id)))
    audit(con, actor_id, None, "user_role", f"user {user_id} -> {role}")


def disable_user(con, actor_id, user_id, disabled=True):
    con.execute("UPDATE users SET disabled = ? WHERE id = ?",
                (1 if disabled else 0, int(user_id)))
    audit(con, actor_id, None, "user_disable" if disabled else "user_enable",
          f"user {user_id}")


def role_at_least(user, required):
    """True if `user`.role >= `required`."""
    if not user:
        return False
    return ROLES.get(user.get("role", ""), 0) >= ROLES.get(required, 0)


# ---- engagements --------------------------------------------------------- #
def list_engagements(con, user=None):
    rows = con.execute(
        "SELECT id,name,client,jurisdiction,status,noise_profile,"
        "created_by,created_at,updated_at FROM engagements ORDER BY id DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def get_engagement(con, eid):
    r = con.execute("SELECT * FROM engagements WHERE id = ?", (int(eid),)).fetchone()
    return dict(r) if r else None


def create_engagement(con, actor_id, *, name, client="", jurisdiction="",
                      noise_profile="normal", scope=None, roe_text="",
                      roe_parsed=None):
    now = _now()
    cur = con.execute(
        "INSERT INTO engagements(name,client,jurisdiction,noise_profile,"
        "scope_json,roe_text,roe_parsed_json,created_by,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)",
        (name, client, jurisdiction, noise_profile,
         json.dumps(scope or {}, ensure_ascii=False),
         roe_text or "",
         json.dumps(roe_parsed or {}, ensure_ascii=False),
         int(actor_id), now, now))
    eid = cur.lastrowid
    audit(con, actor_id, eid, "engagement_create", name)
    return eid


def update_engagement(con, actor_id, eid, **fields):
    allowed = ("name", "client", "jurisdiction", "status", "noise_profile",
               "scope_json", "roe_text", "roe_parsed_json",
               "engagement_json", "ledger_db")
    sets, vals = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            vals.append(v)
    if not sets:
        return
    vals.extend([_now(), int(eid)])
    con.execute(f"UPDATE engagements SET {', '.join(sets)}, updated_at = ? WHERE id = ?",
                vals)
    audit(con, actor_id, eid, "engagement_update",
          ",".join(k for k in fields if k in allowed))


# ---- jobs ---------------------------------------------------------------- #
def create_job(con, actor_id, engagement_id, kind, args):
    cur = con.execute(
        "INSERT INTO jobs(engagement_id,kind,args_json,created_by,created_at) "
        "VALUES(?,?,?,?,?)",
        (int(engagement_id), kind, json.dumps(args or {}, ensure_ascii=False),
         int(actor_id), _now()))
    audit(con, actor_id, engagement_id, "job_queued", f"{kind} id={cur.lastrowid}")
    return cur.lastrowid


def set_job_state(con, job_id, state, *, pid=None, exit_code=None, log_path=None):
    sets = ["state = ?"]
    vals = [state]
    if state == "running":
        sets.append("started_at = ?"); vals.append(_now())
    if state in ("done", "error"):
        sets.append("ended_at = ?"); vals.append(_now())
    if pid is not None:
        sets.append("pid = ?"); vals.append(int(pid))
    if exit_code is not None:
        sets.append("exit_code = ?"); vals.append(int(exit_code))
    if log_path:
        sets.append("log_path = ?"); vals.append(log_path)
    vals.append(int(job_id))
    con.execute(f"UPDATE jobs SET {', '.join(sets)} WHERE id = ?", vals)


def list_jobs(con, engagement_id=None, limit=50):
    if engagement_id:
        rows = con.execute(
            "SELECT * FROM jobs WHERE engagement_id = ? ORDER BY id DESC LIMIT ?",
            (int(engagement_id), int(limit))).fetchall()
    else:
        rows = con.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT ?",
                           (int(limit),)).fetchall()
    return [dict(r) for r in rows]


# ---- audit --------------------------------------------------------------- #
def audit(con, user_id, engagement_id, action, detail=""):
    con.execute("INSERT INTO audit(ts,user_id,engagement_id,action,detail) "
                "VALUES(?,?,?,?,?)",
                (_now(), int(user_id) if user_id else None,
                 int(engagement_id) if engagement_id else None, action,
                 (detail or "")[:400]))


def recent_audit(con, limit=200, engagement_id=None):
    if engagement_id:
        rows = con.execute(
            "SELECT * FROM audit WHERE engagement_id = ? ORDER BY id DESC LIMIT ?",
            (int(engagement_id), int(limit))).fetchall()
    else:
        rows = con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?",
                           (int(limit),)).fetchall()
    return [dict(r) for r in rows]


# ---- session-key kv ------------------------------------------------------ #
def get_or_create_session_key(con):
    """A single server-side HMAC key for cookie signing — rotated via `kv_set`."""
    r = con.execute("SELECT v FROM kv WHERE k = 'session_key'").fetchone()
    if r:
        return bytes.fromhex(r[0])
    k = secrets.token_bytes(32)
    con.execute("INSERT INTO kv(k,v) VALUES('session_key', ?)", (k.hex(),))
    return k


def rotate_session_key(con):
    k = secrets.token_bytes(32)
    con.execute("INSERT INTO kv(k,v) VALUES('session_key', ?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k.hex(),))
    return k
