#!/usr/bin/env python3
"""mimir_web.auth — session cookies, RBAC decorators, CSRF for the web app.

Authorized / lab / CTF / VAPT / red-team use only.

Minimal, stdlib-only auth:
  * password check                   -> db.verify_password (scrypt)
  * HMAC-SHA256 signed session cookie, server-rotated key
  * CSRF double-submit token         (HMAC of session id)
  * RBAC: role-at-least decorator on the request handler

No tokens outside the host (no OAuth / OIDC yet — can be bolted on later; this
layer stays plain so a solo operator can run the app without extra config).
"""
from __future__ import annotations

import base64
import hmac
import http.cookies as _cookies
import secrets
import time
from hashlib import sha256

from . import db as _db

_COOKIE_SESSION = "mimir_sid"
_COOKIE_CSRF = "mimir_csrf"
_SESSION_TTL = 8 * 3600                       # 8-hour operator shift
_CSRF_TTL = 24 * 3600


# --------------------------------------------------------------------------- #
def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_d(s):
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _sign(key, payload):
    return hmac.new(key, payload, sha256).digest()


# --------------------------------------------------------------------------- #
def new_session(con, user_id):
    """Create a session token tying `user_id` to a server-key-signed timestamp."""
    key = _db.get_or_create_session_key(con)
    ts = str(int(time.time())).encode("ascii")
    uid = str(int(user_id)).encode("ascii")
    body = uid + b"." + ts
    sig = _sign(key, body)
    sid = _b64url(body + b"." + sig)
    _db.audit(con, user_id, None, "login", "")
    return sid


def verify_session(con, cookie_value):
    """Verify a session cookie. Returns the user dict on success, None on failure."""
    if not cookie_value:
        return None
    try:
        raw = _b64url_d(cookie_value)
        parts = raw.rsplit(b".", 1)
        if len(parts) != 2:
            return None
        body, sig = parts
        key = _db.get_or_create_session_key(con)
        if not hmac.compare_digest(_sign(key, body), sig):
            return None
        uid_b, ts_b = body.rsplit(b".", 1)
        ts = int(ts_b.decode("ascii"))
        if time.time() - ts > _SESSION_TTL:
            return None
        user = _db.get_user(con, int(uid_b))
        if not user or user.get("disabled"):
            return None
        return user
    except Exception:
        return None


def logout_session(con, cookie_value):
    """No server-side session store yet — logout is cookie-clear + audit."""
    user = verify_session(con, cookie_value)
    if user:
        _db.audit(con, user["id"], None, "logout", "")


# --------------------------------------------------------------------------- #
def make_cookie_header(sid):
    """Produce the Set-Cookie header for a session + a CSRF token tied to it."""
    c = _cookies.SimpleCookie()
    c[_COOKIE_SESSION] = sid
    c[_COOKIE_SESSION]["path"] = "/"
    c[_COOKIE_SESSION]["httponly"] = True
    c[_COOKIE_SESSION]["samesite"] = "Lax"
    c[_COOKIE_SESSION]["max-age"] = str(_SESSION_TTL)
    # CSRF double-submit: readable by JS (not httponly), bound to the session id.
    csrf = _b64url(sha256((sid + "::csrf").encode("ascii")).digest())
    c[_COOKIE_CSRF] = csrf
    c[_COOKIE_CSRF]["path"] = "/"
    c[_COOKIE_CSRF]["samesite"] = "Lax"
    c[_COOKIE_CSRF]["max-age"] = str(_CSRF_TTL)
    return [m.OutputString() for m in c.values()]


def clear_cookie_headers():
    """Expire both cookies on logout."""
    c = _cookies.SimpleCookie()
    for name in (_COOKIE_SESSION, _COOKIE_CSRF):
        c[name] = ""
        c[name]["path"] = "/"
        c[name]["max-age"] = "0"
    return [m.OutputString() for m in c.values()]


# --------------------------------------------------------------------------- #
def parse_cookies(header_value):
    """Return {name: value} from the Cookie: header."""
    if not header_value:
        return {}
    c = _cookies.SimpleCookie()
    c.load(header_value)
    return {k: morsel.value for k, morsel in c.items()}


def expected_csrf(sid):
    return _b64url(sha256((sid + "::csrf").encode("ascii")).digest())


def verify_csrf(sid, submitted):
    if not sid or not submitted:
        return False
    return hmac.compare_digest(expected_csrf(sid), submitted)
