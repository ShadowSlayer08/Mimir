#!/usr/bin/env python3
"""
reporting.py — engagement report (Markdown / HTML) + MITRE ATT&CK Navigator layer.

Authorized / lab / CTF use only.

Turns the pipeline output (inventory + findings + per-service methodology + staged
attack paths) into a single hand-off artifact, and emits an ATT&CK Navigator JSON
layer (https://mitre-attack.github.io/attack-navigator/) scored by how often each
technique shows up across the staged paths and module methodology.
"""
from __future__ import annotations

import html
import json
import re

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_ATT = re.compile(r"^T\d{4}(\.\d{3})?$")


# --------------------------------------------------------------------------- #
# ATT&CK Navigator layer
# --------------------------------------------------------------------------- #
def navigator_layer(modules, paths, name="Pentest Engine — staged techniques"):
    """Enterprise-ATT&CK Navigator layer. Score = occurrences across paths+methodology.

    ICS techniques (T0####) are a different ATT&CK domain and are omitted here.
    """
    counts, comments = {}, {}

    def add(tid, why):
        if not _ATT.match(tid or "") or tid.startswith("T0"):
            return
        counts[tid] = counts.get(tid, 0) + 1
        comments.setdefault(tid, set()).add(why)

    for p in paths:
        for s in p.get("steps", []):
            add(s.get("technique_id", ""), p.get("kind", "path"))
    for m in modules:
        for t in m.get("techniques", []):
            add(t, m.get("module", "module"))
        for c in m.get("checks", []):
            add(c.get("attack", ""), m.get("module", "module"))

    techniques = [{"techniqueID": tid, "score": n, "color": "",
                   "comment": ", ".join(sorted(comments.get(tid, [])))}
                  for tid, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    hi = max((n for n in counts.values()), default=1)
    return {
        "name": name,
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
        "domain": "enterprise-attack",
        "description": "Techniques staged by the pentest engine (analysis/staging only).",
        "sorting": 3,
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": hi},
        "techniques": techniques,
        "hideDisabled": True,
    }


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def build_markdown(report, modules, paths, scan=None):
    t = report["totals"]
    sc = report["severity_counts"]
    L = []
    L.append("# Pentest Engine — Engagement Report\n")
    L.append(f"_Generated {report.get('generated', '')}_  ")
    if scan:
        L.append(f"\n**Source:** {'evidence folder' if scan.get('from_dir') else ('offline XML' if scan.get('from_xml') else 'live scan')}"
                 f" · **Mode:** {scan.get('mode', '-')}  ")
    L.append("\n> Analysis & staging only — attack paths are executed manually by an "
             "authorized operator. No exploits were launched.\n")

    L.append("## Summary\n")
    L.append(f"- Hosts: **{t['hosts']}** · Open ports: **{t['open_ports']}** · "
             f"Findings: **{t['findings']}** · CVEs: **{len(report['unique_cves'])}**")
    L.append("- Severity: " + " · ".join(f"{s}={sc.get(s, 0)}" for s in SEV_ORDER) + "\n")

    L.append("## Hosts\n")
    L.append("| Host | IP | OS | Grade | Ports | Findings |")
    L.append("|---|---|---|---|---|---|")
    for h in report["host_summary"]:
        L.append(f"| {h['host']} | {h['ip'] or ''} | {h['os'] or ''} | "
                 f"**{h['grade']}** | {h['open_ports']} | {h['findings']} |")

    L.append("\n## Findings\n")
    L.append("| Target | Sev | Category | Issue | CVEs |")
    L.append("|---|---|---|---|---|")
    for f in report["findings"]:
        tgt = f"{f['host']}:{f['port']}" if f.get("port") else f["host"]
        L.append(f"| {tgt} | {f['severity'].upper()} | {f['category']} | "
                 f"{f['title']} | {' '.join(f['cve'][:6])} |")

    L.append("\n## Per-service methodology (what to test next)\n")
    for m in modules:
        L.append(f"### {m['title']} — {m['target']}  ({m['severity'].upper()})")
        if m.get("summary"):
            L.append(f"{m['summary']}\n")
        for s in m.get("attack_surface", []):
            L.append(f"- ⚠ {s}")
        for c in m.get("checks", []):
            ref = " ".join(x for x in (c.get("owasp", ""), c.get("cwe", "")) if x)
            ref = f" _({ref})_" if ref else ""
            L.append(f"- `{c['attack']}`{ref} **{c['name']}** — {c['purpose']}\n  ```\n  {c['command']}\n  ```")
        L.append("")

    L.append("## Staged attack paths (operator queue)\n")
    if not paths:
        L.append("_No attack paths derived._")
    for p in paths:
        L.append(f"### {p['id']} — {p['name']}  ({p['severity'].upper()}, conf={p['confidence']}, score={p['score']})")
        L.append(f"_{p['rationale']}_\n")
        for s in p["steps"]:
            L.append(f"{s['order']}. **{s['tactic']}** `{s['technique_id']}` {s['technique']} @ {s['host']}  \n"
                     f"   → {s['guidance']}")
        L.append("")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
_CSS = """
body{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:28px;background:#0d1017;color:#d7dde6}
h1,h2,h3{color:#fff} h3{margin-top:18px}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13.5px}
th,td{border:1px solid #262d3a;padding:6px 9px;text-align:left;vertical-align:top}
th{background:#1b212c} tr:nth-child(even){background:#141922}
code,pre{background:#11161f;border:1px solid #222b38;border-radius:6px}
pre{padding:8px 10px;overflow:auto} code{padding:1px 5px}
.sev{padding:1px 7px;border-radius:8px;color:#0d1017;font-weight:700;font-size:11.5px}
.banner{background:#1b212c;border:1px solid #2a3140;border-radius:8px;padding:8px 12px;color:#9aa4b2}
.warn{color:#ff8a3d}
"""
_SEVHEX = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224", "low": "#8b95a5", "info": "#4c8dff"}


def _h(x):
    return html.escape(str(x or ""))


def build_html(report, modules, paths, scan=None):
    t = report["totals"]
    sc = report["severity_counts"]

    def sev_badge(s):
        return f"<span class=sev style='background:{_SEVHEX.get(s, '#888')}'>{s.upper()}</span>"

    rows = "".join(
        f"<tr><td>{_h(f['host'])}{(':' + str(f['port'])) if f['port'] else ''}</td>"
        f"<td>{sev_badge(f['severity'])}</td><td>{_h(f['category'])}</td>"
        f"<td>{_h(f['title'])}</td><td>{' '.join(_h(c) for c in f['cve'][:6])}</td></tr>"
        for f in report["findings"])
    hosts = "".join(
        f"<tr><td>{_h(h['host'])}</td><td>{_h(h['ip'])}</td><td>{_h(h['os'])}</td>"
        f"<td><b>{_h(h['grade'])}</b></td><td>{h['open_ports']}</td><td>{h['findings']}</td></tr>"
        for h in report["host_summary"])
    mods = []
    for m in modules:
        mods.append(f"<h3>{_h(m['title'])} — {_h(m['target'])} {sev_badge(m['severity'])}</h3>")
        if m.get("summary"):
            mods.append(f"<p>{_h(m['summary'])}</p>")
        for s in m.get("attack_surface", []):
            mods.append(f"<p class=warn>⚠ {_h(s)}</p>")
        mods.append("<table><tr><th>ATT&CK</th><th>Refs</th><th>Check</th><th>Command</th></tr>" + "".join(
            f"<tr><td>{_h(c['attack'])}</td>"
            f"<td>{_h(' '.join(x for x in (c.get('owasp', ''), c.get('cwe', '')) if x))}</td>"
            f"<td>{_h(c['name'])}</td>"
            f"<td><code>{_h(c['command'])}</code></td></tr>" for c in m.get("checks", [])) + "</table>")
    paths_html = []
    for p in paths:
        paths_html.append(f"<h3>{_h(p['id'])} — {_h(p['name'])} {sev_badge(p['severity'])} "
                          f"<small>conf={_h(p['confidence'])} score={p['score']}</small></h3>"
                          f"<p><i>{_h(p['rationale'])}</i></p><ol>")
        for s in p["steps"]:
            paths_html.append(f"<li><b>{_h(s['tactic'])}</b> <code>{_h(s['technique_id'])}</code> "
                              f"{_h(s['technique'])} @ {_h(s['host'])}<br>→ {_h(s['guidance'])}</li>")
        paths_html.append("</ol>")
    src = ("evidence folder" if scan and scan.get("from_dir") else
           "offline XML" if scan and scan.get("from_xml") else "live scan") if scan else "scan"
    return f"""<!doctype html><html><head><meta charset=utf-8><title>Engagement Report</title>
<style>{_CSS}</style></head><body>
<h1>Pentest Engine — Engagement Report</h1>
<p class=banner>{_h(report.get('generated', ''))} · source: {_h(src)} · mode: {_h(scan.get('mode', '-') if scan else '-')}
&middot; Analysis &amp; staging only — no exploits were launched.</p>
<h2>Summary</h2>
<p>Hosts <b>{t['hosts']}</b> · Open ports <b>{t['open_ports']}</b> · Findings <b>{t['findings']}</b>
· CVEs <b>{len(report['unique_cves'])}</b> · {' '.join(f"{s}={sc.get(s, 0)}" for s in SEV_ORDER)}</p>
<h2>Hosts</h2><table><tr><th>Host</th><th>IP</th><th>OS</th><th>Grade</th><th>Ports</th><th>Findings</th></tr>{hosts}</table>
<h2>Findings ({len(report['findings'])})</h2>
<table><tr><th>Target</th><th>Sev</th><th>Category</th><th>Issue</th><th>CVEs</th></tr>{rows}</table>
<h2>Per-service methodology</h2>{''.join(mods)}
<h2>Staged attack paths</h2>{''.join(paths_html) or '<p>No attack paths derived.</p>'}
</body></html>"""


# --------------------------------------------------------------------------- #
def build_runbook(report, modules, paths, scan=None):
    """Operator runbook: a checkbox playbook of the staged ATT&CK paths plus the
    per-target reference commands. The OPERATOR runs each item manually with their
    own tooling — the engine executes nothing here."""
    L = []
    L.append("# Operator Runbook\n")
    L.append(f"_Generated {report.get('generated', '')}_  ")
    if scan:
        L.append(f"_Mode: {scan.get('mode', '-')}  ·  Target: {scan.get('target', '-')}_  ")
    L.append("\n> Execute each step **manually**, inside your authorized, scope-confirmed "
             "engagement, with your own tooling. The engine does **not** run any of these — "
             "it stages them. Tick items as you complete them.\n")

    L.append("## 1. Staged attack paths (priority order)\n")
    if not paths:
        L.append("_No attack paths derived._\n")
    for p in paths:
        L.append(f"### {p['id']} — {p['name']}  ({p['severity'].upper()}, conf={p['confidence']}, score={p['score']})")
        L.append(f"_{p['rationale']}_\n")
        for s in p["steps"]:
            L.append(f"- [ ] **{s['order']}. {s['tactic']}** · `{s['technique_id']}` {s['technique']} "
                     f"@ **{s['host']}**  \n      {s['guidance']}")
            ab = s.get("abuse")
            if ab:
                L.append(f"      - _Abuse:_ {ab.get('impact', '')}")
                L.append(f"      - _How:_ `{ab.get('how', '')}`")
                L.append(f"      - _Opsec:_ {ab.get('opsec', '')}")
        L.append("")

    L.append("## 2. Per-target methodology — commands to run yourself\n")
    by_target = {}
    for m in modules:
        by_target.setdefault(m["target"], []).append(m)
    for target, mods in by_target.items():
        L.append(f"### {target}")
        for m in mods:
            for note in m.get("attack_surface", []):
                L.append(f"> ⚠ {note}")
            for c in m.get("checks", []):
                ref = " ".join(x for x in (c.get("owasp", ""), c.get("cwe", "")) if x)
                ref = f" _({ref})_" if ref else ""
                L.append(f"- [ ] `{c['attack']}`{ref} **{c['name']}** — {c['purpose']}\n"
                         f"      ```\n      {c['command']}\n      ```")
        L.append("")
    return "\n".join(L) + "\n"


def write_runbook(report, modules, paths, path, scan=None):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_runbook(report, modules, paths, scan))


def write_report(report, modules, paths, path, scan=None):
    low = path.lower()
    if low.endswith((".html", ".htm")):
        data = build_html(report, modules, paths, scan)
    else:
        data = build_markdown(report, modules, paths, scan)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)


def write_navigator(modules, paths, path, name="Pentest Engine — staged techniques"):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(navigator_layer(modules, paths, name), fh, indent=2)
