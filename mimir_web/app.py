#!/usr/bin/env python3
"""mimir_web.app — the operator-workflow web app (stdlib HTTP + SQLite).

Authorized / lab / CTF / VAPT / red-team use only.

End-to-end flow:
  1. First visit -> /bootstrap (create first admin)
  2. Thereafter -> /login
  3. /engagements          — list, filter
  4. /engagements/new      — scope + ROE + noise-profile wizard
  5. /engagements/<id>     — scope summary, attack-initiation form, job log, audit
  6. /engagements/<id>/launch (POST) — spawn assess.py as a subprocess (background);
                                       engagement.json + ledger + report populate
                                       as the job runs. State visible on the detail page.
  7. /engagements/<id>/view — the pre-existing read-only engagement viewer, served
                              against the engagement.json produced by (6).

Stdlib only — no FastAPI / Jinja / passlib. Session cookies are HMAC-signed with
a server-rotated key; passwords are scrypt-hashed.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import auth as _auth
from . import db as _db
from . import views as _views

# Repo root — used to invoke assess.py as a subprocess.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                      # pragma: no cover
            pass


_force_utf8_stdio()


# --------------------------------------------------------------------------- #
# Scan worker — runs assess.py in a subprocess; records state in the jobs row.
def _run_scan_job(db_path, job_id, engagement_id, args, log_path, art_dir):
    """Executes in a background thread. Spawns assess.py as a subprocess."""
    con = _db.connect(db_path)
    _db.set_job_state(con, job_id, "running")
    os.makedirs(art_dir, exist_ok=True)
    cmd = [sys.executable, os.path.join(_ROOT, "assess.py"),
           "--yes", "--mode", args.get("mode", "vapt")]
    target_source = args.get("target_source", "")
    if target_source.startswith("fixture:"):
        f = target_source.split(":", 1)[1]
        cmd += ["--from-xml", os.path.join(_ROOT, "tests", "fixtures", f + ".xml")]
    elif target_source == "scope":
        eng = _db.get_engagement(con, engagement_id)
        try:
            scope = json.loads(eng.get("scope_json") or "{}")
            targets = scope.get("in_scope") or []
        except Exception:
            targets = []
        if targets:
            cmd += [targets[0]]
        else:
            _db.set_job_state(con, job_id, "error", exit_code=2)
            return
    eng_json = os.path.join(art_dir, "engagement.json")
    cmd += ["--emit-json", eng_json]
    if args.get("enrich"):
        cmd += ["--enrich", "--offline"]
    if args.get("emit_report"):
        cmd += ["--report", os.path.join(art_dir, "report.html")]
    if args.get("emit_runbook"):
        cmd += ["--runbook", os.path.join(art_dir, "runbook.md")]
    if args.get("llm"):
        cmd += ["--llm"]
    ledger_path = os.path.join(art_dir, "ledger.db")
    cmd += ["--ledger", ledger_path]
    try:
        with open(log_path, "w", encoding="utf-8", errors="ignore") as log:
            log.write("$ " + " ".join(cmd) + "\n\n")
            log.flush()
            proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                                    cwd=_ROOT, env=os.environ.copy())
            _db.set_job_state(con, job_id, "running", pid=proc.pid, log_path=log_path)
            rc = proc.wait()
        if rc == 0 and os.path.exists(eng_json):
            with open(eng_json, encoding="utf-8") as fh:
                _db.update_engagement(con, 0, engagement_id,
                                      engagement_json=fh.read(),
                                      ledger_db=ledger_path,
                                      status="active")
        _db.set_job_state(con, job_id, "done" if rc == 0 else "error",
                          exit_code=rc)
    except Exception as exc:                                      # pragma: no cover
        _db.set_job_state(con, job_id, "error", exit_code=1)
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(f"\n[mimir-web] crashed: {exc}\n")


# --------------------------------------------------------------------------- #
# Request handler
class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):                            # quieter default
        sys.stderr.write("[web] " + (fmt % args) + "\n")

    # ---- helpers -------------------------------------------------------- #
    def _db(self):
        return _db.connect(self.server.db_path)

    def _user(self, con):
        cookies = _auth.parse_cookies(self.headers.get("Cookie", ""))
        return _auth.verify_session(con, cookies.get(_auth._COOKIE_SESSION))

    def _html(self, body, status=200, extra_headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for h in (extra_headers or []):
            self.send_header(*h)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, loc, extra_headers=None):
        self.send_response(303)
        self.send_header("Location", loc)
        for h in (extra_headers or []):
            self.send_header(*h)
        self.end_headers()

    def _form(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        return urllib.parse.parse_qs(body.decode("utf-8", "replace"),
                                     keep_blank_values=True)

    def _json(self, obj, status=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ---- routing -------------------------------------------------------- #
    def do_GET(self):
        con = self._db()
        path = urllib.parse.urlparse(self.path).path
        try:
            if path in ("/", "/engagements"):
                return self._guard_and_render("engagements", con)
            if path == "/health":
                return self._json({"ok": True, "app": "mimir-web"})
            if path == "/login":
                user = self._user(con)
                if user:
                    return self._redirect("/engagements")
                # Bootstrap flow when the users table is empty.
                if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
                    return self._html(_views.render_bootstrap())
                return self._html(_views.render_login())
            if path == "/logout":
                cookies = _auth.parse_cookies(self.headers.get("Cookie", ""))
                _auth.logout_session(con, cookies.get(_auth._COOKIE_SESSION))
                return self._redirect("/login",
                                      extra_headers=[("Set-Cookie", c)
                                                     for c in _auth.clear_cookie_headers()])
            if path == "/engagements/new":
                return self._guard_and_render("new_engagement", con)
            if path == "/users":
                return self._guard_and_render("users", con)
            if path == "/audit":
                return self._guard_and_render("audit", con)
            if path.startswith("/engagements/"):
                tail = path[len("/engagements/"):]
                if tail.endswith("/view"):
                    return self._guard_engagement_view(con, tail[:-5])
                if tail.endswith("/api"):
                    return self._guard_engagement_api(con, tail[:-4])
                if tail.endswith("/log"):
                    return self._guard_job_log(con, tail[:-4])
                return self._guard_engagement_detail(con, tail)
            self._html("<h1>404</h1>", status=404)
        finally:
            con.close()

    def do_POST(self):
        con = self._db()
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/bootstrap":
                return self._handle_bootstrap(con)
            if path == "/login":
                return self._handle_login(con)
            if path == "/engagements/new":
                return self._handle_new_engagement(con)
            if path.startswith("/engagements/") and path.endswith("/launch"):
                return self._handle_launch(con, path.split("/")[2])
            if path == "/users/add":
                return self._handle_user_add(con)
            self._html("<h1>404</h1>", status=404)
        finally:
            con.close()

    # ---- auth-gated renderers ------------------------------------------ #
    def _require_user(self, con, min_role="viewer"):
        user = self._user(con)
        if not user:
            self._redirect("/login")
            return None
        if not _db.role_at_least(user, min_role):
            self._html(f'<div class="err">403 — role {min_role!r} required.</div>',
                       status=403)
            return None
        return user

    def _guard_and_render(self, which, con):
        user = self._require_user(con)
        if not user:
            return
        if which == "engagements":
            return self._html(_views.render_engagements(user, _db.list_engagements(con)))
        if which == "new_engagement":
            if not _db.role_at_least(user, "lead"):
                return self._html(_views.render_engagements(user, _db.list_engagements(con)),
                                  extra_headers=[("X-Mimir-Error", "need lead role")])
            return self._html(_views.render_new_engagement(user))
        if which == "users":
            return self._html(_views.render_users(user, _db.list_users(con)))
        if which == "audit":
            return self._html(_views.render_audit(user, _db.recent_audit(con, limit=200)))

    def _guard_engagement_detail(self, con, raw_eid):
        user = self._require_user(con)
        if not user:
            return
        try:
            eid = int(raw_eid)
        except ValueError:
            return self._html("<h1>404</h1>", status=404)
        eng = _db.get_engagement(con, eid)
        if not eng:
            return self._html("<h1>404</h1>", status=404)
        jobs = _db.list_jobs(con, engagement_id=eid)
        audit_rows = _db.recent_audit(con, limit=25, engagement_id=eid)
        cookies = _auth.parse_cookies(self.headers.get("Cookie", ""))
        sid = cookies.get(_auth._COOKIE_SESSION, "")
        csrf = _auth.expected_csrf(sid)
        return self._html(_views.render_engagement_detail(user, eng, jobs, audit_rows, csrf))

    def _guard_engagement_api(self, con, raw_eid):
        """Serve the raw engagement JSON — same shape /api/engagement in webapi.py."""
        user = self._require_user(con)
        if not user:
            return
        try:
            eid = int(raw_eid)
        except ValueError:
            return self._json({"error": "bad id"}, status=404)
        eng = _db.get_engagement(con, eid)
        if not eng or not eng.get("engagement_json"):
            return self._json({"error": "no engagement data yet"}, status=404)
        try:
            payload = json.loads(eng["engagement_json"])
        except Exception:
            return self._json({"error": "corrupt engagement_json"}, status=500)
        return self._json(payload)

    def _guard_engagement_view(self, con, raw_eid):
        """Render the standalone read-only viewer at /engagements/<id>/view."""
        user = self._require_user(con)
        if not user:
            return
        try:
            eid = int(raw_eid)
        except ValueError:
            return self._html("<h1>404</h1>", status=404)
        eng = _db.get_engagement(con, eid)
        if not eng or not eng.get("engagement_json"):
            return self._html("<div class='err'>No engagement data yet. "
                              "Launch a scan from the engagement page.</div>",
                              status=404)
        try:
            payload = json.loads(eng["engagement_json"])
        except Exception:
            return self._html("<div class='err'>Corrupt engagement JSON.</div>",
                              status=500)
        # Serve the viewer HTML directly, with the engagement data inlined
        # (viewer fetches /engagements/<id>/api instead of /api/engagement).
        from webapi import INDEX_HTML
        html_body = INDEX_HTML.replace("/api/engagement", f"/engagements/{eid}/api")
        return self._html(html_body)

    def _guard_job_log(self, con, raw_eid):
        user = self._require_user(con)
        if not user:
            return
        try:
            eid = int(raw_eid)
        except ValueError:
            return self._json({"error": "bad id"}, status=404)
        jobs = _db.list_jobs(con, engagement_id=eid, limit=1)
        if not jobs:
            return self._json({"state": "none"})
        j = jobs[0]
        tail = ""
        if j.get("log_path") and os.path.exists(j["log_path"]):
            try:
                with open(j["log_path"], encoding="utf-8", errors="ignore") as fh:
                    tail = fh.read()[-16000:]
            except OSError:
                pass
        return self._json({"state": j["state"], "exit_code": j.get("exit_code"),
                           "log": tail})

    # ---- auth handlers -------------------------------------------------- #
    def _handle_bootstrap(self, con):
        if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
            return self._redirect("/login")
        form = self._form()
        email = (form.get("email", [""])[0] or "").strip()
        pw = form.get("password", [""])[0]
        confirm = form.get("confirm", [""])[0]
        if not email or len(pw) < 12 or pw != confirm:
            return self._html(_views.render_bootstrap(
                "Email + 12+ char passphrase + matching confirm required."))
        _db.bootstrap_admin(con, email, pw)
        return self._redirect("/login")

    def _handle_login(self, con):
        form = self._form()
        email = (form.get("email", [""])[0] or "").strip()
        pw = form.get("password", [""])[0]
        user = _db.get_user_by_email(con, email)
        if not user or user.get("disabled"):
            return self._html(_views.render_login("Invalid credentials."), status=401)
        if not _db.verify_password(pw, user["pw_hash"], user["pw_salt"]):
            return self._html(_views.render_login("Invalid credentials."), status=401)
        sid = _auth.new_session(con, user["id"])
        return self._redirect("/engagements",
                              extra_headers=[("Set-Cookie", c)
                                             for c in _auth.make_cookie_header(sid)])

    # ---- engagement handlers ------------------------------------------- #
    def _handle_new_engagement(self, con):
        user = self._require_user(con, min_role="lead")
        if not user:
            return
        form = self._form()
        name = (form.get("name", [""])[0] or "").strip()
        if not name:
            return self._html(_views.render_new_engagement(
                user, "Engagement name is required.", form={k: v[0] for k, v in form.items()}))
        in_scope = [x.strip() for x in form.get("in_scope", [""])[0].splitlines() if x.strip()]
        out_scope = [x.strip() for x in form.get("out_of_scope", [""])[0].splitlines() if x.strip()]
        forbidden_techs = []
        if form.get("forbid_dos", [""])[0]:
            forbidden_techs += ["T1498", "T1499", "T1499.001", "T1499.002", "T1499.004"]
        forbidden_risk = ["intrusive"] if form.get("forbid_intrusive", [""])[0] else []
        windows = []
        days = [d.strip() for d in form.get("window_days", [""])[0].split(",") if d.strip()]
        s = form.get("window_start", [""])[0].strip()
        e = form.get("window_end", [""])[0].strip()
        if days and s and e:
            windows.append({"days": days, "hours": [s, e]})
        scope = {"in_scope": in_scope, "out_of_scope": out_scope,
                 "forbidden_techniques": forbidden_techs,
                 "forbidden_risk": forbidden_risk,
                 "allowed_windows": windows,
                 "jurisdiction": form.get("jurisdiction", [""])[0].strip()}

        roe_text = form.get("roe_text", [""])[0]
        roe_parsed = {}
        if roe_text:
            try:
                import roe_parse
                roe_parsed = roe_parse.parse(roe_text, prefer_llm=False)
                for k in ("in_scope", "out_of_scope", "forbidden_techniques"):
                    if roe_parsed.get(k):
                        scope.setdefault(k, [])
                        for v in roe_parsed[k]:
                            if v not in scope[k]:
                                scope[k].append(v)
            except Exception:
                roe_parsed = {"_error": "regex parse failed"}

        eid = _db.create_engagement(
            con, user["id"], name=name,
            client=form.get("client", [""])[0].strip(),
            jurisdiction=form.get("jurisdiction", [""])[0].strip(),
            noise_profile=form.get("noise_profile", ["normal"])[0],
            scope=scope, roe_text=roe_text, roe_parsed=roe_parsed)
        return self._redirect(f"/engagements/{eid}")

    def _handle_launch(self, con, raw_eid):
        user = self._require_user(con, min_role="operator")
        if not user:
            return
        try:
            eid = int(raw_eid)
        except ValueError:
            return self._html("<h1>404</h1>", status=404)
        cookies = _auth.parse_cookies(self.headers.get("Cookie", ""))
        sid = cookies.get(_auth._COOKIE_SESSION, "")
        form = self._form()
        if not _auth.verify_csrf(sid, (form.get("csrf", [""])[0] or "")):
            return self._html('<div class="err">CSRF check failed. Reload the page.</div>',
                              status=400)
        args = {"mode": form.get("mode", ["vapt"])[0],
                "target_source": form.get("target_source", ["fixture:full_scan"])[0],
                "llm": form.get("llm", ["0"])[0] == "1",
                "enrich": bool(form.get("enrich", [""])[0]),
                "emit_report": bool(form.get("emit_report", [""])[0]),
                "emit_runbook": bool(form.get("emit_runbook", [""])[0])}
        job_id = _db.create_job(con, user["id"], eid, "scan", args)
        art_dir = os.path.join(self.server.art_root, f"eng-{eid}", f"job-{job_id}")
        log_path = os.path.join(art_dir, "job.log")
        thread = threading.Thread(
            target=_run_scan_job,
            args=(self.server.db_path, job_id, eid, args, log_path, art_dir),
            daemon=True)
        thread.start()
        return self._redirect(f"/engagements/{eid}")

    def _handle_user_add(self, con):
        user = self._require_user(con, min_role="admin")
        if not user:
            return
        form = self._form()
        email = (form.get("email", [""])[0] or "").strip()
        pw = form.get("password", [""])[0]
        role = form.get("role", ["operator"])[0]
        if not email or len(pw) < 12 or role not in _db.ROLES:
            return self._redirect("/users")
        try:
            _db.add_user(con, user["id"], email, pw, role=role)
        except Exception:
            pass
        return self._redirect("/users")


# --------------------------------------------------------------------------- #
def make_server(db_path, art_root, host, port):
    srv = ThreadingHTTPServer((host, port), _Handler)
    srv.db_path = db_path
    srv.art_root = art_root
    return srv


def serve(db_path, art_root, host="127.0.0.1", port=8788):
    os.makedirs(art_root, exist_ok=True)
    srv = make_server(db_path, art_root, host, port)
    print(f"[mimir-web] db        : {db_path}")
    print(f"[mimir-web] artifacts : {art_root}")
    print(f"[mimir-web] listening : http://{host}:{port}  "
          f"(Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.server_close()


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="mimir-ops",
        description="Mimir operator web app — auth + engagement workflow + scope + scan launcher")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8788)
    ap.add_argument("--db", default=None,
                    help=f"SQLite DB path (default: {_db.default_db_path()})")
    ap.add_argument("--art-root", default=None,
                    help="Directory for per-engagement artifacts (ledger / engagement.json / reports)."
                         " Default: ~/.mimir/artifacts")
    ap.add_argument("--bootstrap-admin", nargs=2, metavar=("EMAIL", "PASSWORD"),
                    help="Create first admin (CLI-side; alternative to the /bootstrap flow).")
    args = ap.parse_args(argv)
    db_path = args.db or _db.default_db_path()
    art_root = args.art_root or os.path.join(os.path.dirname(db_path), "artifacts")
    if args.bootstrap_admin:
        con = _db.connect(db_path)
        try:
            created, uid = _db.bootstrap_admin(con, args.bootstrap_admin[0], args.bootstrap_admin[1])
            if created:
                print(f"[mimir-web] bootstrapped admin #{uid}: {args.bootstrap_admin[0]}")
            else:
                print("[mimir-web] users already exist; bootstrap skipped")
        finally:
            con.close()
    return serve(db_path, art_root, args.host, args.port)


if __name__ == "__main__":
    sys.exit(main())
