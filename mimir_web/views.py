#!/usr/bin/env python3
"""mimir_web.views — HTML templates (stdlib f-strings; no Jinja dep).

Each `render_*` returns a complete HTML document. Styling is inlined and
shared via `_SHELL`. Mimir brand palette: cold indigo + rune-gold accent.
"""
from __future__ import annotations

import html

_h = html.escape


_SHELL_CSS = """
:root{
  --bg:#0b0e14;--surface:#121725;--surface-2:#1a2033;--line:#242c42;
  --text:#e6eaf2;--text-2:#a1a9b8;--muted:#6b7382;
  --accent:#d4af37;--accent-dim:rgba(212,175,55,.18);
  --ok:#5fb380;--warn:#e39a3c;--err:#e5484d;
  --crit:#e5484d;--high:#e39a3c;--medium:#c8b74a;--low:#5fb380;--info:#6b7382;
  --sans:-apple-system,"Segoe UI",Roboto,Inter,sans-serif;
  --mono:ui-monospace,"SF Mono",Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);
  font-size:14px;line-height:1.5}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1180px;margin:0 auto;padding:20px}
header.topnav{background:#070910;border-bottom:1px solid var(--line);padding:12px 20px;
  display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:10}
.brand{font-weight:700;font-size:16px;color:var(--accent);letter-spacing:.04em}
.brand small{color:var(--muted);font-weight:400;font-size:11px;margin-left:6px}
nav.topnav-links a{color:var(--text-2);margin-right:14px;font-size:13px}
nav.topnav-links a.on{color:var(--accent)}
.user{margin-left:auto;color:var(--text-2);font-size:12px;display:flex;gap:12px;align-items:center}
.user a.btn-ghost{color:var(--text-2);border:1px solid var(--line);padding:4px 10px;border-radius:6px}
h1{font-size:22px;margin:0 0 16px;font-weight:600;letter-spacing:-0.01em}
h2{font-size:17px;margin:24px 0 10px;font-weight:600}
h3{font-size:14px;margin:14px 0 6px;font-weight:600;color:var(--text-2)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:16px;
  margin-bottom:14px}
.card h2{margin-top:0}
label{display:block;font-size:12px;color:var(--text-2);margin:10px 0 4px;letter-spacing:.03em}
input[type=text],input[type=email],input[type=password],input[type=number],textarea,select{
  width:100%;background:var(--surface-2);border:1px solid var(--line);color:var(--text);
  padding:8px 10px;border-radius:6px;font-size:13px;font-family:var(--sans)}
textarea{font-family:var(--mono);font-size:12px;min-height:100px;line-height:1.4}
input:focus,textarea:focus,select:focus{outline:1px solid var(--accent);border-color:var(--accent)}
.btn{display:inline-block;background:var(--accent-dim);color:var(--accent);border:1px solid var(--accent);
  padding:7px 14px;border-radius:6px;font-size:13px;cursor:pointer;font-weight:500;text-decoration:none}
.btn:hover{background:var(--accent);color:#000}
.btn-ghost{background:transparent;color:var(--text-2);border:1px solid var(--line);
  padding:7px 14px;border-radius:6px;font-size:13px;cursor:pointer;text-decoration:none}
.btn-ghost:hover{color:var(--text);border-color:var(--text-2)}
.btn-danger{background:rgba(229,72,77,.15);color:var(--err);border-color:var(--err)}
.badge{display:inline-block;padding:1px 7px;border-radius:3px;font-size:11px;
  letter-spacing:.03em;text-transform:uppercase;font-weight:500}
.badge-crit{background:rgba(229,72,77,.2);color:var(--crit)}
.badge-high{background:rgba(227,154,60,.2);color:var(--high)}
.badge-med{background:rgba(200,183,74,.2);color:var(--medium)}
.badge-low{background:rgba(95,179,128,.2);color:var(--low)}
.badge-info{background:rgba(107,115,130,.2);color:var(--info)}
.row{display:flex;gap:14px;flex-wrap:wrap}
.row>*{flex:1;min-width:200px}
.table{width:100%;border-collapse:collapse}
.table th{text-align:left;color:var(--muted);font-weight:500;font-size:11px;letter-spacing:.06em;
  text-transform:uppercase;padding:8px 10px;border-bottom:1px solid var(--line)}
.table td{padding:10px;border-bottom:1px solid var(--line);font-size:13px}
.table tr:last-child td{border-bottom:0}
.table tr:hover td{background:var(--surface-2)}
.mono{font-family:var(--mono);font-size:12px;color:var(--text-2)}
.banner{background:var(--accent-dim);color:var(--accent);border:1px solid var(--accent);
  border-radius:6px;padding:10px 14px;margin-bottom:14px;font-size:13px}
.err{color:var(--err);background:rgba(229,72,77,.08);border:1px solid var(--err);
  padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:13px}
.ok{color:var(--ok);background:rgba(95,179,128,.08);border:1px solid var(--ok);
  padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:13px}
.dim{color:var(--muted)}
.rune{font-family:'Palatino Linotype',Georgia,serif;color:var(--accent);
  letter-spacing:.1em;font-size:14px;font-weight:400}
.hero{display:flex;align-items:center;gap:14px;margin-bottom:20px}
.hero .seal{width:46px;height:46px;border-radius:50%;border:1px solid var(--accent);
  display:flex;align-items:center;justify-content:center;background:#0b0e14;
  color:var(--accent);font-size:22px;font-family:'Palatino Linotype',serif}
.pill{display:inline-block;background:var(--surface-2);color:var(--text-2);
  padding:2px 10px;border-radius:999px;font-size:11px;letter-spacing:.03em}
.pill.on{background:var(--accent);color:#000}
.tabs{display:flex;gap:4px;margin-bottom:16px;border-bottom:1px solid var(--line);padding-bottom:0}
.tabs a{padding:10px 14px;color:var(--text-2);font-size:13px;border-bottom:2px solid transparent;
  margin-bottom:-1px}
.tabs a.on{color:var(--accent);border-bottom-color:var(--accent)}
.chip{display:inline-block;padding:2px 8px;margin:2px 2px;background:var(--surface-2);
  color:var(--text-2);border-radius:4px;font-size:11px;font-family:var(--mono)}
.chip.crit{background:rgba(229,72,77,.2);color:var(--crit)}
.auth-page{max-width:420px;margin:9vh auto;padding:30px;background:var(--surface);
  border:1px solid var(--line);border-radius:10px}
.auth-page h1{text-align:center;font-size:26px;letter-spacing:.08em;color:var(--accent);
  font-family:'Palatino Linotype',Georgia,serif;font-weight:400;margin:0 0 4px}
.auth-page .sub{text-align:center;color:var(--muted);font-size:12px;margin-bottom:28px;
  letter-spacing:.08em}
"""


def _shell(title, body, user=None, nav_active=None, extra_head=""):
    links = ""
    if user:
        navs = [
            ("Engagements", "/engagements", "engagements"),
            ("New",         "/engagements/new", "new"),
            ("Users",       "/users", "users"),
            ("Audit",       "/audit", "audit"),
        ]
        for label, href, slug in navs:
            cls = "on" if slug == nav_active else ""
            links += f'<a href="{href}" class="{cls}">{_h(label)}</a>'
        user_bits = (f'<span>{_h(user["email"])} '
                     f'<span class="pill">{_h(user["role"])}</span></span>'
                     f'<a class="btn-ghost" href="/logout">Sign out</a>')
    else:
        user_bits = ""
    nav = (f'<header class="topnav">'
           f'  <span class="brand">MIMIR<small>· knowledge-driven pentest engine</small></span>'
           f'  <nav class="topnav-links">{links}</nav>'
           f'  <div class="user">{user_bits}</div>'
           f'</header>') if user else ""
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>{_h(title)} — Mimir</title>'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<style>{_SHELL_CSS}</style>{extra_head}</head>'
            f'<body>{nav}{body}</body></html>')


# --------------------------------------------------------------------------- #
def render_login(error=""):
    err = f'<div class="err">{_h(error)}</div>' if error else ""
    body = f"""
<div class="auth-page">
  <h1>MIMIR</h1>
  <div class="sub">· keeper of the well of knowledge ·</div>
  {err}
  <form method="post" action="/login">
    <label>Email</label>
    <input type="email" name="email" required autofocus>
    <label>Password</label>
    <input type="password" name="password" required>
    <div style="margin-top:20px;display:flex;justify-content:space-between;align-items:center">
      <span class="dim" style="font-size:11px">Authorized operators only · AGPL-3.0</span>
      <button class="btn" type="submit">Sign in</button>
    </div>
  </form>
</div>"""
    return _shell("Sign in", body)


def render_bootstrap(error=""):
    err = f'<div class="err">{_h(error)}</div>' if error else ""
    body = f"""
<div class="auth-page">
  <h1>MIMIR</h1>
  <div class="sub">· first operator setup ·</div>
  <div class="banner">No users exist yet. Create the first admin to begin.</div>
  {err}
  <form method="post" action="/bootstrap">
    <label>Admin email</label>
    <input type="email" name="email" required autofocus>
    <label>Password (min 12 chars)</label>
    <input type="password" name="password" required minlength="12">
    <label>Confirm password</label>
    <input type="password" name="confirm" required minlength="12">
    <div style="margin-top:20px;text-align:right">
      <button class="btn" type="submit">Create admin account</button>
    </div>
  </form>
</div>"""
    return _shell("First setup", body)


# --------------------------------------------------------------------------- #
def render_engagements(user, engagements):
    rows = []
    for e in engagements:
        status_pill = ('<span class="pill on">active</span>' if e["status"] == "active"
                       else f'<span class="pill">{_h(e["status"])}</span>')
        rows.append(
            f'<tr><td><a href="/engagements/{e["id"]}">{_h(e["name"])}</a></td>'
            f'<td class="dim">{_h(e.get("client") or "-")}</td>'
            f'<td>{status_pill}</td>'
            f'<td class="dim">{_h(e.get("noise_profile", "normal"))}</td>'
            f'<td class="dim">{_h((e.get("updated_at") or "")[:10])}</td></tr>')
    body = f"""
<div class="wrap">
  <div class="hero"><div class="seal">ᛗ</div>
    <div><h1 style="margin:0">Engagements</h1>
    <div class="dim">The scope-of-work roster · {len(engagements)} total</div></div>
    <div style="margin-left:auto"><a class="btn" href="/engagements/new">New engagement</a></div>
  </div>
  <div class="card">
    {'<table class="table"><tr><th>Name</th><th>Client</th><th>Status</th><th>Profile</th><th>Updated</th></tr>' + ''.join(rows) + '</table>' if rows else '<p class="dim" style="text-align:center;padding:20px">No engagements yet. <a href="/engagements/new">Create the first one.</a></p>'}
  </div>
</div>"""
    return _shell("Engagements", body, user, nav_active="engagements")


# --------------------------------------------------------------------------- #
def render_new_engagement(user, error="", form=None):
    form = form or {}
    err = f'<div class="err">{_h(error)}</div>' if error else ""
    body = f"""
<div class="wrap">
  <div class="hero"><div class="seal">ᛟ</div>
    <div><h1 style="margin:0">New engagement</h1>
    <div class="dim">Scope-of-work · ROE · noise profile</div></div>
  </div>
  {err}
  <form method="post" action="/engagements/new" enctype="application/x-www-form-urlencoded">
    <div class="card">
      <h2>Identity</h2>
      <div class="row">
        <div><label>Engagement name *</label>
          <input type="text" name="name" required value="{_h(form.get("name", ""))}" placeholder="Acme Q4 Internal"></div>
        <div><label>Client</label>
          <input type="text" name="client" value="{_h(form.get("client", ""))}" placeholder="Acme Corp"></div>
        <div><label>Jurisdiction</label>
          <input type="text" name="jurisdiction" value="{_h(form.get("jurisdiction", ""))}" placeholder="US-CA"></div>
      </div>
    </div>
    <div class="card">
      <h2>Scope of work</h2>
      <div class="dim" style="margin-bottom:8px">
        CIDR, exact hostname, or dotted suffix (<span class="mono">.corp.lab</span>). One per line.
      </div>
      <div class="row">
        <div><label>In scope *</label>
          <textarea name="in_scope" required placeholder="10.0.0.0/24&#10;.acme.example&#10;web.acme.example">{_h(form.get("in_scope", ""))}</textarea></div>
        <div><label>Out of scope (hard-deny; wins over in_scope)</label>
          <textarea name="out_of_scope" placeholder="10.0.0.99&#10;.prod.acme.example">{_h(form.get("out_of_scope", ""))}</textarea></div>
      </div>
      <div class="row">
        <div><label>Allowed window — days (comma; mon tue wed thu fri sat sun or empty = any)</label>
          <input type="text" name="window_days" value="{_h(form.get("window_days", ""))}" placeholder="mon,tue,wed,thu,fri"></div>
        <div><label>Window start (HH:MM)</label>
          <input type="text" name="window_start" value="{_h(form.get("window_start", ""))}" placeholder="18:00"></div>
        <div><label>Window end (HH:MM)</label>
          <input type="text" name="window_end" value="{_h(form.get("window_end", ""))}" placeholder="04:00"></div>
      </div>
    </div>
    <div class="card">
      <h2>Rules of engagement</h2>
      <div class="dim" style="margin-bottom:8px">
        Paste the client ROE verbatim; Mimir regex-extracts + optionally LLM-parses it. .gov/.mil/.edu/.int are hard-blocked by default.
      </div>
      <label>Noise profile</label>
      <select name="noise_profile">
        {''.join(f'<option value="{v}" {"selected" if form.get("noise_profile") == v else ""}>{v}</option>' for v in ["stealth", "normal", "aggressive"])}
      </select>
      <label>ROE text (prose; markdown ok)</label>
      <textarea name="roe_text" placeholder="Engagement: ...&#10;In scope: 10.0.0.0/24&#10;No denial of service.&#10;...">{_h(form.get("roe_text", ""))}</textarea>
      <label><input type="checkbox" name="forbid_intrusive" value="1" {"checked" if form.get("forbid_intrusive") else ""}> Forbid intrusive checks (hide risk=intrusive from the staged queue)</label>
      <label><input type="checkbox" name="forbid_dos" value="1" {"checked" if form.get("forbid_dos") == "1" else "checked" if form.get("forbid_dos") is None else ""}> Forbid denial-of-service techniques (T1498/T1499; default ON)</label>
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="dim">The engagement is created in <b>draft</b> status. Launch scans from the engagement page.</div>
        <div><a class="btn-ghost" href="/engagements">Cancel</a> <button class="btn" type="submit">Create engagement</button></div>
      </div>
    </div>
  </form>
</div>"""
    return _shell("New engagement", body, user, nav_active="new")


# --------------------------------------------------------------------------- #
def render_engagement_detail(user, eng, jobs, audit_rows, csrf):
    scope = eng.get("scope_json") or "{}"
    try:
        import json
        scope_obj = json.loads(scope)
    except Exception:
        scope_obj = {}
    chips = "".join(f'<span class="chip">{_h(c)}</span>' for c in scope_obj.get("in_scope", []))
    out_chips = "".join(f'<span class="chip crit">{_h(c)}</span>' for c in scope_obj.get("out_of_scope", []))
    job_rows = "".join(
        f'<tr><td class="mono">#{j["id"]}</td><td>{_h(j["kind"])}</td>'
        f'<td><span class="pill">{_h(j["state"])}</span></td>'
        f'<td class="dim">{_h((j.get("started_at") or "-")[:19])}</td>'
        f'<td class="dim">{_h((j.get("ended_at") or "-")[:19])}</td>'
        f'<td class="mono dim">{j.get("exit_code") if j.get("exit_code") is not None else "-"}</td></tr>'
        for j in jobs)
    audit_html = "".join(
        f'<tr><td class="mono dim">{_h((a["ts"] or "")[:19])}</td>'
        f'<td>{_h(a["action"])}</td><td class="dim">{_h(a.get("detail") or "")}</td></tr>'
        for a in audit_rows)
    status = eng.get("status", "draft")
    body = f"""
<div class="wrap">
  <div class="hero"><div class="seal">ᛉ</div>
    <div>
      <h1 style="margin:0">{_h(eng["name"])}</h1>
      <div class="dim">
        <span class="pill {'on' if status == 'active' else ''}">{_h(status)}</span>
        · {_h(eng.get("client") or "-")} · noise profile <b>{_h(eng.get("noise_profile", "normal"))}</b>
      </div>
    </div>
    <div style="margin-left:auto">
      <a class="btn-ghost" href="/engagements">All engagements</a>
      {' <a class="btn" href="/engagements/' + str(eng["id"]) + '/view">Open live viewer ↗</a>' if eng.get("engagement_json") else ''}
    </div>
  </div>

  <div class="tabs">
    <a class="on" href="#scope">Scope</a>
    <a href="#initiate">Attack initiation</a>
    <a href="#live">Live jobs</a>
    <a href="#audit">Audit</a>
  </div>

  <section id="scope" class="card">
    <h2>Scope</h2>
    <h3>In scope</h3>
    <div>{chips or '<span class="dim">(none)</span>'}</div>
    <h3>Out of scope (hard-deny)</h3>
    <div>{out_chips or '<span class="dim">(none)</span>'}</div>
    <h3>Forbidden</h3>
    <div class="dim">
      {('<span class="chip">' + '</span><span class="chip">'.join(_h(t) for t in scope_obj.get("forbidden_techniques", [])) + '</span>') if scope_obj.get("forbidden_techniques") else '<span class="dim">(none)</span>'}
      {('risk: <span class="chip">' + '</span><span class="chip">'.join(_h(r) for r in scope_obj.get("forbidden_risk", [])) + '</span>') if scope_obj.get("forbidden_risk") else ''}
    </div>
    {'<h3>ROE prose</h3><pre class="mono" style="background:var(--surface-2);padding:12px;border-radius:6px;white-space:pre-wrap;max-height:280px;overflow:auto">' + _h(eng.get("roe_text") or "") + '</pre>' if eng.get("roe_text") else ''}
  </section>

  <section id="initiate" class="card">
    <h2>Attack initiation</h2>
    <p class="dim">Launches a staging pass against the scope above. The engine assesses + stages — no exploits are run.
      Operator takes each staged step from the live viewer and runs it manually.</p>
    <form method="post" action="/engagements/{eng["id"]}/launch">
      <input type="hidden" name="csrf" value="{_h(csrf)}">
      <div class="row">
        <div><label>Mode</label>
          <select name="mode"><option value="vapt">vapt (safe-biased)</option><option value="redteam">redteam (full tradecraft)</option></select></div>
        <div><label>Fixture / target source</label>
          <select name="target_source">
            <option value="fixture:full_scan">fixture: full_scan.xml (demo)</option>
            <option value="fixture:broad_scan">fixture: broad_scan.xml (demo)</option>
            <option value="scope">live: scan every host in scope (needs nmap on PATH)</option>
          </select></div>
        <div><label>Enable LLM co-pilot</label>
          <select name="llm"><option value="0">no</option><option value="1">yes (local Ollama)</option></select></div>
      </div>
      <div class="row" style="margin-top:12px">
        <div><label><input type="checkbox" name="emit_report" value="1" checked> Write HTML report</label></div>
        <div><label><input type="checkbox" name="emit_runbook" value="1" checked> Write operator runbook</label></div>
        <div><label><input type="checkbox" name="enrich" value="1" checked> Enrich with KEV + EPSS</label></div>
      </div>
      <div style="margin-top:14px;text-align:right">
        <button class="btn" type="submit">▶ Stage engagement</button>
      </div>
    </form>
  </section>

  <section id="live" class="card">
    <h2>Jobs</h2>
    {'<table class="table"><tr><th>#</th><th>Kind</th><th>State</th><th>Started</th><th>Ended</th><th>Exit</th></tr>' + job_rows + '</table>' if job_rows else '<p class="dim">No jobs yet.</p>'}
  </section>

  <section id="audit" class="card">
    <h2>Audit trail</h2>
    {'<table class="table"><tr><th>When</th><th>Action</th><th>Detail</th></tr>' + audit_html + '</table>' if audit_html else '<p class="dim">(no audit entries)</p>'}
  </section>
</div>"""
    return _shell(eng["name"], body, user)


# --------------------------------------------------------------------------- #
def render_users(user, users):
    def _status_cell(u):
        return "disabled" if u.get("disabled") else '<span class="dim">—</span>'
    rows = "".join(
        f'<tr><td class="mono">#{u["id"]}</td>'
        f'<td>{_h(u["email"])}</td>'
        f'<td><span class="pill">{_h(u["role"])}</span></td>'
        f'<td class="dim">{_h((u.get("created_at") or "")[:10])}</td>'
        f'<td>{_status_cell(u)}</td></tr>'
        for u in users)
    is_admin = user.get("role") == "admin"
    add_form = ""
    if is_admin:
        add_form = """
<div class="card">
  <h2>Add operator</h2>
  <form method="post" action="/users/add">
    <div class="row">
      <div><label>Email</label><input type="email" name="email" required></div>
      <div><label>Password (min 12)</label><input type="password" name="password" required minlength="12"></div>
      <div><label>Role</label><select name="role">
         <option value="viewer">viewer</option>
         <option value="operator" selected>operator</option>
         <option value="lead">lead</option>
         <option value="admin">admin</option>
      </select></div>
    </div>
    <div style="margin-top:12px;text-align:right"><button class="btn">Create user</button></div>
  </form>
</div>"""
    body = f"""
<div class="wrap">
  <div class="hero"><div class="seal">ᚦ</div>
    <div><h1 style="margin:0">Operators</h1>
    <div class="dim">{len(users)} user(s) · role-based access</div></div>
  </div>
  <div class="card">
    <table class="table"><tr><th>#</th><th>Email</th><th>Role</th><th>Created</th><th>Status</th></tr>{rows}</table>
  </div>
  {add_form}
</div>"""
    return _shell("Operators", body, user, nav_active="users")


# --------------------------------------------------------------------------- #
def render_audit(user, rows):
    html_rows = "".join(
        f'<tr><td class="mono dim">{_h((r["ts"] or "")[:19])}</td>'
        f'<td class="mono">{r.get("user_id") or "-"}</td>'
        f'<td class="mono">{r.get("engagement_id") or "-"}</td>'
        f'<td>{_h(r["action"])}</td>'
        f'<td class="dim">{_h(r.get("detail") or "")}</td></tr>'
        for r in rows)
    body = f"""
<div class="wrap">
  <div class="hero"><div class="seal">ᛟ</div>
    <div><h1 style="margin:0">Audit trail</h1>
    <div class="dim">Last {len(rows)} actions · append-only</div></div>
  </div>
  <div class="card">
    <table class="table"><tr><th>When</th><th>User</th><th>Engagement</th><th>Action</th><th>Detail</th></tr>{html_rows}</table>
  </div>
</div>"""
    return _shell("Audit", body, user, nav_active="audit")
