#!/usr/bin/env python3
"""
timeline.py — engagement timeline from the persistent ledger.

Authorized / lab / CTF use only.

Reads the SQLite ledger (ledger.py) and emits a chronological timeline of the
engagement's runs, plus first-seen and last-seen for every finding. Renders as
Markdown (for embedding in the operator report) or a compact SVG stripe
(for the report's hero).

    python timeline.py eng.db                     # markdown
    python timeline.py eng.db --svg tl.svg        # rendered timeline strip
    python timeline.py eng.db --json tl.json      # structured
"""
from __future__ import annotations

import os
import sqlite3
import sys
from datetime import datetime, timezone

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLOR = {"critical": "#a02020", "high": "#c96612",
              "medium": "#8b7a1d", "low": "#316f5a", "info": "#5b6370"}


def _force_utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                          # pragma: no cover
            pass


_force_utf8_stdio()


def _parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def load(db_path):
    """Read runs + findings + hosts from the ledger; return the structured timeline."""
    if not db_path or not os.path.exists(db_path):
        return {"runs": [], "findings": [], "hosts": [], "span": None}
    con = sqlite3.connect(db_path)
    try:
        runs = [dict(id=r[0], ts=r[1], mode=r[2], source=r[3], target=r[4],
                     hosts=r[5], findings=r[6], paths=r[7])
                for r in con.execute(
                    "SELECT id,ts,mode,source,target,hosts,findings,paths FROM runs ORDER BY id"
                ).fetchall()]
        findings = [dict(key=r[0], host=r[1], port=r[2], category=r[3], severity=r[4],
                         title=r[5], first_seen=r[6], last_seen=r[7], seen=r[8])
                    for r in con.execute(
                        "SELECT key,host,port,category,severity,title,first_seen,last_seen,seen "
                        "FROM findings ORDER BY first_seen").fetchall()]
        hosts = [dict(key=r[0], ip=r[1], label=r[2], os=r[3], grade=r[4],
                      first_seen=r[5], last_seen=r[6], seen=r[7])
                 for r in con.execute(
                     "SELECT key,ip,label,os,grade,first_seen,last_seen,seen FROM hosts "
                     "ORDER BY first_seen").fetchall()]
    finally:
        con.close()

    times = [t for t in ((r.get("ts") for r in runs)) if t] + \
            [f["first_seen"] for f in findings if f.get("first_seen")]
    parsed = [t for t in (_parse_ts(x) for x in times) if t]
    span = None
    if parsed:
        span = {"start": min(parsed).isoformat(), "end": max(parsed).isoformat(),
                "days": (max(parsed) - min(parsed)).days + 1}
    return {"runs": runs, "findings": findings, "hosts": hosts, "span": span}


def to_markdown(tl):
    """Human-readable timeline for the report."""
    if not tl["runs"]:
        return "# Engagement timeline\n\n_No ledger entries yet._\n"
    L = ["# Engagement timeline", ""]
    sp = tl["span"] or {}
    if sp:
        L.append(f"_Span: {sp.get('start', '?')} → {sp.get('end', '?')}  "
                 f"({sp.get('days', 0)} day(s))_\n")
    L.append("## Runs")
    for r in tl["runs"]:
        L.append(f"- **{r['ts']}** — run #{r['id']}  ·  mode `{r['mode']}`  ·  "
                 f"source `{r['source']}`  ·  target `{r['target']}`  "
                 f"→ {r['hosts']} hosts, {r['findings']} findings, {r['paths']} paths")
    L.append("")
    if tl["findings"]:
        L.append("## Findings first observed (top 20 by severity)")
        for f in sorted(tl["findings"], key=lambda x: (
                _SEV_ORDER.get((x.get("severity") or "").lower(), 9),
                x.get("first_seen", "")))[:20]:
            fresh = "·" if f["seen"] <= 1 else "↺"
            L.append(f"- **{f.get('first_seen', '?')}** — [{(f.get('severity') or '?').upper():<8}] "
                     f"{f.get('title', '')[:80]}  @ **{f.get('host', '?')}:{f.get('port', 0)}**  {fresh}")
        L.append("")
    return "\n".join(L) + "\n"


def to_svg(tl, width=900, height=88):
    """A compact SVG stripe: horizontal timeline with a marker per run and a
    colour-coded dot per finding first_seen."""
    from xml.sax.saxutils import escape as _esc
    span = tl.get("span") or {}
    if not span:
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">'
                f'<text x="{width/2}" y="{height/2}" text-anchor="middle" '
                f'font-family="ui-monospace,monospace" font-size="12" fill="#7a8091">'
                f'No timeline data yet.</text></svg>')
    start = _parse_ts(span["start"])
    end = _parse_ts(span["end"])
    if not (start and end) or end <= start:
        end = start
    total = max((end - start).total_seconds(), 1.0)
    left, right = 60, width - 60
    y_axis = int(height * 0.55)

    def x(ts):
        t = _parse_ts(ts)
        if not t:
            return left
        frac = max(0.0, min(1.0, (t - start).total_seconds() / total))
        return round(left + frac * (right - left), 2)

    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
             f'viewBox="0 0 {width} {height}" role="img" aria-label="Engagement timeline">',
             '<style>.tl-lbl{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;'
             'font-size:10.5px;fill:#7a8091;letter-spacing:.03em;}'
             '.tl-run{stroke:#4d5464;stroke-width:1.4;}'
             '.tl-axis{stroke:#c9cdd6;stroke-width:1;}</style>',
             f'<line class="tl-axis" x1="{left}" y1="{y_axis}" x2="{right}" y2="{y_axis}"/>',
             f'<text class="tl-lbl" x="{left}" y="{y_axis + 24}">'
             f'{_esc(start.isoformat(timespec="minutes"))}</text>',
             f'<text class="tl-lbl" x="{right}" y="{y_axis + 24}" text-anchor="end">'
             f'{_esc(end.isoformat(timespec="minutes"))}</text>']

    # Runs — vertical ticks above the axis.
    for r in tl["runs"]:
        xr = x(r["ts"])
        parts.append(f'<line class="tl-run" x1="{xr}" y1="{y_axis - 18}" x2="{xr}" y2="{y_axis + 4}"/>')
        parts.append(f'<text class="tl-lbl" x="{xr}" y="{y_axis - 22}" text-anchor="middle">'
                     f'#{r["id"]}</text>')

    # Findings — coloured dots below the axis, jittered per severity band.
    for f in tl["findings"]:
        xf = x(f.get("first_seen"))
        sev = (f.get("severity") or "info").lower()
        yf = y_axis + 8 + _SEV_ORDER.get(sev, 4) * 2
        col = _SEV_COLOR.get(sev, "#5b6370")
        parts.append(f'<circle cx="{xf}" cy="{yf}" r="2.4" fill="{col}"/>')

    parts.append('</svg>')
    return "".join(parts)


def write_report_section(db_path, out_path):
    """Convenience: dump markdown timeline to a file."""
    tl = load(db_path)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(tl))


# --------------------------------------------------------------------------- #
def main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(prog="timeline.py",
                                 description="engagement timeline from the ledger")
    ap.add_argument("db", help="ledger SQLite path")
    ap.add_argument("--svg", metavar="FILE", help="also write an SVG timeline stripe")
    ap.add_argument("--json", metavar="FILE", help="also write structured JSON")
    args = ap.parse_args(argv)
    tl = load(args.db)
    print(to_markdown(tl))
    if args.svg:
        with open(args.svg, "w", encoding="utf-8") as fh:
            fh.write(to_svg(tl))
        print(f"[+] SVG timeline -> {args.svg}", file=sys.stderr)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(tl, fh, indent=2)
        print(f"[+] JSON timeline -> {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
