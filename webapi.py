#!/usr/bin/env python3
"""
webapi.py — read-only REST API + web GUI over the engagement JSON contract.

Authorized / lab / CTF use only.

Serves the engagement produced by `assess --emit-json engagement.json` — the same
contract the Flutter viewer consumes — as a small browser dashboard plus a JSON
API, so a team can review hosts / findings / ATT&CK attack paths / kill-chain in a
browser and copy staged commands.

STAGING BOUNDARY: this is **read-only**. It serves data that was already computed;
it exposes no scan, no exploit, and no mutation endpoint (GET only — everything
else is 405). It never contacts a target. Run it beside the operator, or on a
review box, pointed at an exported engagement file.

    python assess.py --from-xml scan.xml --yes --emit-json eng.json
    python webapi.py eng.json                 # -> http://127.0.0.1:8787
    (installed:  vantage-web eng.json)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_SLICES = ("meta", "hosts", "findings", "attack_paths", "killchain")


def load_engagement(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or data.get("schema") != "vantage.engagement":
        raise ValueError("not a vantage engagement JSON (run: assess --emit-json)")
    return data


def route(payload, path):
    """Map a GET path to (status, content_type, body_bytes). Pure + testable.

    Read-only JSON API:  /health  /api/engagement  /api/<slice>  (meta/hosts/
    findings/attack_paths/killchain). Everything else under /api is 404."""
    if path in ("/health", "/api/health"):
        return 200, "application/json", _j({"status": "ok", "schema": payload.get("schema")})
    if path in ("/api", "/api/engagement", "/api/"):
        return 200, "application/json", _j(payload)
    if path.startswith("/api/"):
        name = path[len("/api/"):].strip("/")
        if name in _SLICES:
            body = payload.get("killchain" if name == "killchain" else name,
                               {} if name in ("meta", "killchain") else [])
            return 200, "application/json", _j(body)
        return 404, "application/json", _j({"error": f"unknown resource: {name}"})
    return None                                   # not an API path -> caller serves the SPA


def _j(obj):
    return json.dumps(obj, indent=2).encode("utf-8")


def make_handler(payload):
    class Handler(BaseHTTPRequestHandler):
        server_version = "vantage-web/1.0"

        def _send(self, status, ctype, body):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            r = route(payload, path)
            if r is not None:
                self._send(*r)
                return
            if path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8", INDEX_HTML.encode("utf-8"))
                return
            self._send(404, "application/json", _j({"error": "not found"}))

        def _reject(self):                        # read-only: no mutation methods
            self._send(405, "application/json", _j({"error": "read-only API (GET only)"}))
        do_POST = do_PUT = do_DELETE = do_PATCH = _reject

        def log_message(self, *a):                # quiet by default
            pass
    return Handler


def serve(path, host="127.0.0.1", port=8787):
    payload = load_engagement(path)
    httpd = ThreadingHTTPServer((host, port), make_handler(payload))
    t = payload.get("meta", {}).get("totals", {})
    print(f"[+] vantage web — read-only. Serving {os.path.basename(path)} "
          f"({t.get('hosts', 0)} hosts, {t.get('findings', 0)} findings) at "
          f"http://{host}:{port}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] stopped")
    finally:
        httpd.server_close()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vantage-web",
                                 description="read-only REST API + web GUI over an "
                                             "engagement JSON (assess --emit-json)")
    ap.add_argument("engagement", help="path to an engagement JSON file")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args(argv)
    if not os.path.isfile(args.engagement):
        sys.stderr.write(f"no such file: {args.engagement}\n")
        return 2
    try:
        return serve(args.engagement, args.host, args.port)
    except ValueError as e:
        sys.stderr.write(f"{e}\n")
        return 2


INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>vantage — engagement</title>
<style>
:root{color-scheme:light dark;--bg:#0e1116;--card:#161b22;--line:#21262d;--txt:#c9d1d9;--dim:#8b95a5;--accent:#4c8dff}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--txt)}
header{background:var(--card);padding:12px 18px;border-bottom:1px solid var(--line);display:flex;gap:14px;align-items:baseline;flex-wrap:wrap}
h1{font-size:16px;margin:0}.dim{color:var(--dim)}.banner{background:rgba(229,72,77,.14);color:#e5484d;padding:8px 18px;font-weight:600;font-size:12.5px}
main{padding:18px;max-width:1100px;margin:0 auto}.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
.mc{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:96px}
.mc .n{font-size:24px;font-weight:600}.mc .l{font-size:11px;letter-spacing:1px;color:var(--dim);text-transform:uppercase}
.tabs{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}.tabs button{background:var(--card);color:var(--dim);border:1px solid var(--line);border-radius:8px;padding:6px 12px;cursor:pointer}
.tabs button.on{color:#fff;background:#1f2937}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--dim);font-size:11px;text-transform:uppercase;padding:6px 8px}
td{padding:6px 8px;border-top:1px solid var(--line)}.pill{padding:1px 7px;border-radius:6px;font-size:11px;font-weight:600}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:12px}
.step{background:#11151b;border-radius:8px;padding:9px 11px;margin-top:8px}.mono{font-family:ui-monospace,monospace;font-size:12px;color:#ffc14a;white-space:pre-wrap;word-break:break-all}
button.copy{background:transparent;border:1px solid var(--line);color:var(--txt);border-radius:6px;padding:3px 9px;cursor:pointer;font-size:12px}
.grade{display:inline-flex;width:24px;height:24px;align-items:center;justify-content:center;border-radius:5px;font-weight:600}
.sev-critical{color:#e5484d}.sev-high{color:#f76808}.sev-medium{color:#ffb224}.sev-low{color:#8b95a5}.sev-info{color:#4c8dff}
.chain{display:flex;flex-wrap:wrap;align-items:center;gap:3px}
.gnode{padding:4px 9px;border-radius:6px;border:1px solid var(--line);font-size:12px;font-weight:600;background:var(--card);color:var(--txt)}
.gnode.start{background:rgba(76,141,255,.18);color:#4c8dff}.gnode.hi{background:rgba(229,72,77,.18);color:#e5484d}
.arrow{display:inline-flex;flex-direction:column;align-items:center;color:var(--dim);line-height:1.1}.elabel{font-size:9px;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
</style></head><body>
<header><h1>vantage</h1><span id="meta" class="dim"></span></header>
<div class="banner">Read-only viewer — displays a staged engagement and copies commands. It executes nothing.</div>
<main>
  <div class="cards" id="cards"></div>
  <div class="tabs"><button data-t="dash" class="on">Dashboard</button><button data-t="reco">Next actions</button><button data-t="find">Findings</button><button data-t="paths">Attack paths</button><button data-t="graph">Graph</button></div>
  <div id="view"></div>
</main>
<script>
const SEV=['critical','high','medium','low','info'];
const gcol=g=>({F:'#e5484d',D:'#e5484d',C:'#ffb224'}[String(g).toUpperCase()]||'#7bd88f');
let E={},tab='dash';
function esc(s){return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
async function load(){E=await (await fetch('/api/engagement')).json();const m=E.meta||{};
  document.getElementById('meta').textContent=`${m.mode||''} · ${m.target||''} · ${(m.generated||'').slice(0,19)}`;
  const c=m.severity_counts||{},t=m.totals||{};
  document.getElementById('cards').innerHTML=
    SEV.map(s=>`<div class="mc"><div class="n sev-${s}">${c[s]||0}</div><div class="l">${s}</div></div>`).join('')
    +`<div class="mc"><div class="n">${(E.hosts||[]).length}</div><div class="l">hosts</div></div>`
    +`<div class="mc"><div class="n">${(E.attack_paths||[]).length}</div><div class="l">paths</div></div>`;
  render();}
function render(){const v=document.getElementById('view');
  if(tab==='dash')v.innerHTML=hostsTable();
  else if(tab==='reco')v.innerHTML=recoView();
  else if(tab==='find')v.innerHTML=findTable();
  else if(tab==='paths')v.innerHTML=pathsView();
  else v.innerHTML=chainView();
  v.querySelectorAll('button.copy').forEach(b=>b.onclick=()=>{navigator.clipboard.writeText(b.dataset.cmd);b.textContent='copied';setTimeout(()=>b.textContent='Copy command',1200)});}
function hostsTable(){const h=E.hosts||[];if(!h.length)return '<p class=dim>No hosts.</p>';
  return '<div class=card><table><tr><th>Grade</th><th>Host</th><th>IP</th><th>Device class</th><th>OS</th><th>Ports</th><th>Findings</th></tr>'
   +h.map(x=>`<tr><td><span class=grade style="background:${gcol(x.grade)}22;color:${gcol(x.grade)}">${esc(x.grade)}</span></td>
     <td><b>${esc(x.label)}</b></td><td>${esc(x.ip||'-')}</td><td style=color:var(--accent)>${esc(x.device_class||'-')}</td>
     <td class=dim>${esc(x.os||'-')}</td><td>${x.open_ports||0}</td><td>${x.finding_count||0}</td></tr>`).join('')+'</table></div>';}
function findTable(){const f=(E.findings||[]).slice().sort((a,b)=>SEV.indexOf(a.severity)-SEV.indexOf(b.severity));
  if(!f.length)return '<p class=dim>No findings.</p>';
  return '<div class=card><table><tr><th>Sev</th><th>Target</th><th>Title</th><th>OWASP/CWE</th></tr>'
   +f.map(x=>`<tr><td class=sev-${x.severity}>${esc(x.severity)}</td><td>${esc(x.host)}${x.port?':'+x.port:''}</td>
     <td>${esc(x.title)}</td><td class=dim>${esc([].concat(x.owasp||[],x.cwe||[]).join(' '))}</td></tr>`).join('')+'</table></div>';}
function pathsView(){const p=E.attack_paths||[];if(!p.length)return '<p class=dim>No attack paths.</p>';
  return p.map(a=>`<div class=card><div><span class="pill" style="background:${gcol('C')}22">${esc(a.id)}</span>
     <b style="margin-left:8px" class="sev-${a.severity}">${esc(a.name)}</b> <span class=dim>· ${esc(a.kind)} · score ${a.score||0}</span></div>`
   +(a.steps||[]).map(s=>`<div class=step><b>${s.order}. ${esc(s.tactic)}</b> <span style=color:#ffc14a>${esc(s.technique_id)}</span> ${esc(s.technique)} @ ${esc(s.host)}
     ${s.command?`<div style="display:flex;gap:8px;margin-top:6px;align-items:center"><div class=mono style=flex:1>${esc(s.command)}</div><button class=copy data-cmd="${esc(s.command)}">Copy command</button></div>`:''}</div>`).join('')
   +'</div>').join('');}
function recoView(){const r=E.recommendations||[];if(!r.length)return '<p class=dim>No recommendations.</p>';
  return '<p class=dim style="margin-top:0">Ranked by impact x confidence x objective-proximity x low-effort. Run in scope.</p>'+
   r.map(a=>`<div class=card><div style="display:flex;gap:8px;align-items:baseline;flex-wrap:wrap"><span class=pill style="background:#4c8dff22;color:#4c8dff">#${a.rank}</span><span class=pill style="background:#8b95a522">score ${esc(a.score)}</span><span class=pill style="background:#8b95a522">${esc(a.category)}</span><b>${esc(a.title)}</b></div>
    <div class=dim style="margin-top:4px">${esc(a.why)}</div>
    ${a.command?`<div style="display:flex;gap:8px;margin-top:8px;align-items:center"><div class=mono style=flex:1>${esc(a.command)}</div><button class=copy data-cmd="${esc(a.command)}">Copy command</button></div>`:''}</div>`).join('');}
function chainView(){const p=E.attack_paths||[];if(!p.length)return '<p class=dim>No attack paths.</p>';
  return p.map(a=>{const st=a.steps||[];
    const start=(a.hosts&&a.hosts[0])||(st[0]&&(st[0].src||st[0].host))||'start';
    let h=`<div class=card><div style="margin-bottom:8px"><span class=pill style="background:#8b95a522">${esc(a.id)}</span> <b class="sev-${a.severity}">${esc(a.name)}</b> <span class=dim>· ${esc(a.kind)}</span></div><div class=chain><span class="gnode start">${esc(start)}</span>`;
    st.forEach((s,i)=>{const lbl=s.edge||s.technique_id||'';const hi=(i===st.length-1)&&(a.kind==='domain'||a.severity==='critical');
      h+=`<span class=arrow><span class=elabel>${esc(lbl)}</span>&#9654;</span><span class="gnode ${hi?'hi':'mid'}">${esc(s.dst||s.host||'?')}</span>`;});
    return h+'</div></div>';}).join('');}
document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>{tab=b.dataset.t;
  document.querySelectorAll('.tabs button').forEach(x=>x.classList.toggle('on',x===b));render()});
load().catch(e=>document.getElementById('view').innerHTML='<p class=sev-critical>Failed to load: '+esc(e)+'</p>');
</script></body></html>"""


if __name__ == "__main__":
    sys.exit(main())
