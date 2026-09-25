#!/usr/bin/env python3
"""
assess.py — single-CLI pipeline runner for the pentest orchestration engine.

Authorized / lab / CTF use only.

Runs the whole engine against a named target in four stages:

  Stage 0  Scope gate    — confirm authorization; optional in-scope allowlist.
  Stage 1  Enumeration   — shell out to nmap (safe, detection-only scripts) -> XML.
  Stage 2  Analysis      — parse + findings (inventory, grades, severities).
  Stage 3  Possible pentesting — per-service ATT&CK-mapped methodology ("what to test").
  Stage 4  Exploitation HANDOFF — prioritized attack paths STAGED for a human operator.

This tool performs ANALYSIS and STAGING only. It does NOT launch exploits or run
attack payloads. Attack paths are a planning queue: the operator validates scope,
executes each step manually within an authorized engagement, then re-runs assess.py
with the new results (see docs/instructions.md — the constitution).

Reuses the existing engine (no reimplementation):
  nmap_analyzer.load_scan / analyze / build_report
  modules.dispatch
  attack_path_engine.generate_paths
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from nmap_analyzer import (load_scan, analyze, build_report, parse_nmap_xml,
                           EXPOSURE_LEVELS, BUSINESS_LEVELS)
from modules import dispatch
from attack_path_engine import generate_paths
from profiles import get_profile, MODES, DEFAULT_MODE
from evidence import ingest_dir
from copilot import recommend as _cp_recommend

# Safe, detection-only default script set. No dos / brute / broad-vuln categories.
# (Kept for back-compat; canonical per-mode sets live in profiles.py.)
DEFAULT_SCRIPTS = get_profile("vapt")["scripts"]

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
FINDINGS_CAP = 40
PATHS_CAP = 25


# --------------------------------------------------------------------------- #
# Colour (degrades to plain text when piped / NO_COLOR / non-tty)
# --------------------------------------------------------------------------- #
class _C:
    def __init__(self, enabled):
        codes = {"red": "31", "ylw": "33", "grn": "32", "cyan": "36",
                 "blue": "34", "mag": "35", "gry": "90", "bold": "1", "dim": "2"}
        for name, code in codes.items():
            setattr(self, name, (lambda c: (lambda s: f"\033[{c}m{s}\033[0m"))(code)
                    if enabled else (lambda s: s))


def _make_color():
    enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    return _C(enabled)


C = _make_color()

_SEV_COLOR = {"critical": "red", "high": "red", "medium": "ylw",
              "low": "blue", "info": "gry"}


def sev_tag(sev):
    fn = getattr(C, _SEV_COLOR.get(sev, "gry"))
    return fn(f"[{sev.upper():8}]")


def banner(title):
    line = "=" * 72
    print(C.bold(C.cyan(f"\n{line}\n  {title}\n{line}")))


# --------------------------------------------------------------------------- #
# Stage 0 — scope gate
# --------------------------------------------------------------------------- #
def load_scope(path):
    """Parse a scope file: one CIDR/IP/hostname per line, '#' comments.

    Returns (networks, hostnames) — a list of ip_network objects and a set of
    exact-match hostname strings.
    """
    nets, names = [], set()
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                names.add(line.lower())
    return nets, names


def _token_in_scope(token, nets, names):
    """Is a single target token (IP, CIDR, or hostname) inside the scope?"""
    token = (token or "").strip()
    if not token:
        return False
    try:
        net = ipaddress.ip_network(token, strict=False)
        return any(net.version == n.version and net.subnet_of(n) for n in nets)
    except ValueError:
        return token.lower() in names


def target_in_scope(identifiers, nets, names):
    """A target (one or more identifiers — ip/ipv6/hostnames) is in scope if
    ANY of its identifiers matches the scope allowlist."""
    return any(_token_in_scope(t, nets, names) for t in identifiers)


def host_identifiers(host):
    ids = []
    for key in ("ip", "ipv6"):
        if host.get(key):
            ids.append(host[key])
    ids.extend(host.get("hostnames", []) or [])
    return ids


def host_label(host):
    return (host["hostnames"][0] if host.get("hostnames")
            else host.get("ip")) or host.get("ipv6") or "?"


def _confirm_authorization(args):
    """Interactive 'type yes' authorization gate; --yes bypasses and logs it."""
    if args.yes:
        print(C.ylw("[auth] Operator asserted authorization via --yes "
                    "(authorized-engagement attestation logged)."))
        return True
    print(C.bold("\nThis tool is for AUTHORIZED penetration testing / lab / CTF use only."))
    print("Targets must be inside a written engagement scope.")
    if not sys.stdin.isatty():
        print(C.red("[auth] No TTY to confirm authorization and --yes not given. Refusing."))
        return False
    try:
        resp = input("Type 'yes' to confirm you are authorized to assess this target: ")
    except EOFError:
        return False
    return resp.strip().lower() == "yes"


def scope_gate(args, targets):
    """targets: list of (label, [identifiers]). Returns True to proceed.

    Order: hard-refuse anything out of scope first (so we never prompt for auth
    on an out-of-scope run), then the authorization confirmation.
    """
    banner("Stage 0 — Scope gate")
    for label, _ids in targets:
        print(f"  target: {C.bold(label)}")

    if args.scope:
        if not os.path.isfile(args.scope):
            print(C.red(f"\n[error] scope file not found: {args.scope}"))
            print(C.dim("  --scope takes a file (one CIDR/host per line). "
                        "To assess a single host, pass it as the positional target:"))
            print(C.dim(f"      assess.py {args.scope}"))
            return False
        nets, names = load_scope(args.scope)
        out = [label for label, ids in targets
               if not target_in_scope(ids, nets, names)]
        if out:
            print(C.red(f"\n[REFUSED] Out of scope (per {args.scope}): "
                        + ", ".join(out)))
            print(C.red("No target may be assessed outside the engagement scope."))
            return False
        print(C.grn(f"  scope OK — all target(s) within {args.scope}"))
    else:
        print(C.dim("  (no --scope file given; relying on operator authorization)"))

    if not _confirm_authorization(args):
        print(C.red("\n[ABORTED] Authorization not confirmed."))
        return False
    return True


# --------------------------------------------------------------------------- #
# Stage 1 — enumeration (nmap)
# --------------------------------------------------------------------------- #
def build_nmap_cmd(target, scripts, timing, ports, pn=False, extra_args="",
                   os_detect=True, aggressive=False, full_ports=False, stats=False,
                   udp_ports=""):
    """Build the nmap argv + the temp XML path it will write. No execution.

    Shared by the CLI runner and the GUI scan worker so both produce identical
    scans. `aggressive` -> -A; `full_ports` -> all TCP; `udp_ports` adds a UDP
    scan (-sU) of those ports (UDP services have their own modules). An explicit
    `ports` spec overrides both full_ports and udp_ports.
    """
    fd, xml_path = tempfile.mkstemp(prefix="assess_", suffix=".xml")
    os.close(fd)
    use_udp = bool(udp_ports) and not ports
    cmd = ["nmap"]
    if aggressive:
        cmd.append("-A")
    else:
        cmd.append("-sV")
        if os_detect:
            cmd.append("-O")
    if use_udp:
        cmd.append("-sU")
    if scripts:
        cmd += ["--script", scripts]
    cmd += [f"-T{timing}", "-oX", xml_path]
    if pn:
        cmd.append("-Pn")
    if ports:
        cmd += ["-p", ports]
    elif full_ports and use_udp:
        cmd += ["-p", f"T:1-65535,U:{udp_ports}"]
    elif full_ports:
        cmd.append("-p-")
    elif use_udp:
        cmd += ["-p", f"U:{udp_ports}"]
    if stats:
        cmd += ["-v", "--stats-every", "6s"]
    if extra_args:
        # posix=False on Windows so cmd.exe-style quoting / backslash paths in
        # operator-supplied nmap flags aren't mangled by POSIX shlex rules.
        cmd += shlex.split(extra_args, posix=(os.name != "nt"))
    cmd.append(target)
    return cmd, xml_path


def run_nmap(target, scripts, timing, ports, pn=False, extra_args="",
             os_detect=True, aggressive=False, full_ports=False, udp_ports=""):
    """Run an enumeration nmap scan -> temp XML path. Raises on failure.

    Output is left attached to the terminal (not captured) so the operator sees
    live progress and the pipe is drained by the tty — it can never deadlock.
    nmap writes results to the -oX file regardless of stdout.
    """
    if shutil.which("nmap") is None:
        raise SystemExit(C.red(
            "[error] nmap not found on PATH. Install nmap, or analyse an existing\n"
            "        scan offline with:  assess.py --from-xml <scan.xml>"))
    cmd, xml_path = build_nmap_cmd(target, scripts, timing, ports, pn=pn,
                                   extra_args=extra_args, os_detect=os_detect,
                                   aggressive=aggressive, full_ports=full_ports, stats=True,
                                   udp_ports=udp_ports)
    print(f"  $ {' '.join(cmd)}")
    print(C.dim("  (-A/-O need root/admin; -p- scans all 65535 ports — this can take a "
                "while. Live nmap progress follows; --stats-every prints periodic status.)"))
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        raise SystemExit(C.red(f"[error] nmap exited {proc.returncode}."))
    return xml_path


# --------------------------------------------------------------------------- #
# Stage 1b — per-service deep enumeration (broad scan -> targeted NSE per service)
# --------------------------------------------------------------------------- #
def plan_service_scans(hosts):
    """For each host, the targeted NSE follow-up: (ip, ports_csv, scripts_csv).

    Driven by docs/nse_mapping.md (knowledge base). One scan per host, limited to
    its open service ports and the NSE scripts mapped to those services. Hosts
    with no mapped services are skipped. Enumeration scripts only.
    """
    try:
        from knowledge_loader import load_knowledge
        kb = load_knowledge()
    except Exception:
        return []
    plan = []
    for h in hosts:
        ip = h.get("ip") or h.get("ipv6") or (h["hostnames"][0] if h.get("hostnames") else None)
        if not ip:
            continue
        tcp, udp, scripts = [], [], []
        for p in h.get("ports", []):
            nse = kb.nse_for(p["service"].get("name", ""))
            if not nse:
                continue
            (udp if p.get("protocol") == "udp" else tcp).append(str(p["port"]))
            for s in nse:
                if s not in scripts:
                    scripts.append(s)
        if (tcp or udp) and scripts:
            plan.append((ip, ",".join(tcp), ",".join(udp), ",".join(scripts)))
    return plan


def build_service_scan_cmd(ip, tcp_csv, udp_csv, scripts_csv, stats=False):
    """nmap argv for a targeted per-service NSE scan + the temp XML it writes."""
    fd, xml_path = tempfile.mkstemp(prefix="assess_svc_", suffix=".xml")
    os.close(fd)
    cmd = ["nmap", "-sV", "-Pn"]
    if udp_csv:
        cmd.append("-sU")
    spec = ([f"T:{tcp_csv}"] if tcp_csv else []) + ([f"U:{udp_csv}"] if udp_csv else [])
    cmd += ["-p", ",".join(spec), "--script", scripts_csv, "-oX", xml_path]
    if stats:
        cmd += ["-v", "--stats-every", "10s"]
    cmd.append(ip)
    return cmd, xml_path


def merge_service_scripts(hosts, scan_hosts):
    """Merge NSE script output / TLS data from a targeted scan back into hosts (by ip+port)."""
    by_ip = {}
    for sh in scan_hosts:
        key = sh.get("ip") or sh.get("ipv6")
        ports = by_ip.setdefault(key, {})
        for p in sh.get("ports", []):
            ports[p["port"]] = p
    for h in hosts:
        smap = by_ip.get(h.get("ip") or h.get("ipv6"), {})
        for p in h.get("ports", []):
            sp = smap.get(p["port"])
            if not sp:
                continue
            p["scripts"].update(sp.get("scripts", {}))
            if sp.get("ssl_enum"):
                p["ssl_enum"], p["least_strength"] = sp["ssl_enum"], sp.get("least_strength")
            if sp.get("cert"):
                p["cert"] = sp["cert"]
    return hosts


def _run_service_scan(entry):
    """Run one host's per-service nmap (output captured so parallel runs don't
    interleave). Returns (ip, xml_path, returncode_or_exc)."""
    ip, tcp_csv, udp_csv, scripts_csv = entry
    cmd, xml = build_service_scan_cmd(ip, tcp_csv, udp_csv, scripts_csv, stats=False)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return ip, xml, proc.returncode
    except Exception as e:                                             # pragma: no cover
        return ip, None, e


def deep_service_scan(hosts, workers=4):
    """Run the per-host service scans IN PARALLEL (workers threads), then merge each
    result in the main thread (so the shared inventory is never raced)."""
    plan = plan_service_scans(hosts)
    if not plan:
        print(C.dim("  (no service-specific NSE scans mapped for discovered services)"))
        return hosts
    print(C.dim(f"  {len(plan)} per-host service scan(s) across {workers} parallel worker(s):"))
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = {ex.submit(_run_service_scan, e): e[0] for e in plan}
        for fut in as_completed(futures):
            ip, xml, rc = fut.result()
            if rc != 0 or xml is None:
                print(C.ylw(f"  [warn] service scan of {ip} failed ({rc}); skipping merge."))
                continue
            try:
                merge_service_scripts(hosts, parse_nmap_xml(xml)[0])   # main thread → no race
                print(C.dim(f"  merged: {ip}"))
            except Exception as e:
                print(C.ylw(f"  [warn] could not merge service scan of {ip}: {e}"))
    return hosts


# --------------------------------------------------------------------------- #
# Stage 2 — analysis printing
# --------------------------------------------------------------------------- #
def print_inventory(report):
    t = report["totals"]
    sc = report["severity_counts"]
    print(f"  {t['hosts']} host(s) · {t['open_ports']} open port(s) · "
          f"{t['findings']} finding(s) "
          f"(crit={sc['critical']} high={sc['high']} med={sc['medium']} "
          f"low={sc['low']} info={sc['info']}) · "
          f"{len(report['unique_cves'])} CVE(s)")
    print()
    hosts_by_label = {host_label(h): h for h in report.get("hosts", [])}
    for hs in report["host_summary"]:
        grade = hs["grade"]
        gcolor = "red" if grade in ("F", "D") else ("ylw" if grade == "C" else "grn")
        print(f"  {C.bold(hs['host']):<28} grade {getattr(C, gcolor)(grade)}  "
              f"ports={hs['open_ports']:<3} findings={hs['findings']:<3} "
              f"{C.cyan(hs.get('device_class') or '')} {C.dim(hs['os'] or '')}")
        h = hosts_by_label.get(hs["host"])
        if h:
            for p in h.get("ports", []):
                svc = p["service"]
                desc = " ".join(x for x in (svc.get("name"), svc.get("product"),
                                            svc.get("version")) if x)
                print(C.dim(f"       {p['port']:>5}/{p.get('protocol','tcp'):<3} {desc}"))


def print_findings(report):
    findings = report["findings"]
    if not findings:
        print(C.dim("  (no findings)"))
        return
    shown = findings[:FINDINGS_CAP]
    for f in shown:
        tgt = f["host"] + (f":{f['port']}" if f.get("port") else "")
        cves = (" " + C.dim("/".join(f["cve"][:4]))) if f.get("cve") else ""
        print(f"  {sev_tag(f['severity'])} {tgt:<26} {f['title']}{cves}")
    if len(findings) > len(shown):
        print(C.dim(f"  … +{len(findings) - len(shown)} more finding(s) "
                    f"(use --json for the full list)"))


# --------------------------------------------------------------------------- #
# Stage 3 — possible pentesting (per-service methodology)
# --------------------------------------------------------------------------- #
def print_modules(mods):
    if not mods:
        print(C.dim("  (no service modules matched)"))
        return
    print(C.dim("  Per-service enumeration / authorized-testing methodology "
                "(what to test). Commands are operator references — nothing runs.\n"))
    for m in mods:
        print(f"  {sev_tag(m['severity'])} {C.bold(m['target'])}  "
              f"{C.cyan(m['title'])} — {m['summary']}")
        for note in m.get("attack_surface", []):
            print(C.ylw(f"        ! {note}"))
        for c in m.get("checks", []):
            attack = c.get("attack", "")
            print(f"        - {c['name']:<24} {C.mag(attack):<9} "
                  f"{C.dim(c.get('command',''))}")
        print()


# --------------------------------------------------------------------------- #
# Stage 4 — exploitation HANDOFF (staging, not automation)
# --------------------------------------------------------------------------- #
def print_attack_paths(paths):
    print(C.bold(C.red(
        "  ┌────────────────────────────────────────────────────────────────┐")))
    print(C.bold(C.red(
        "  │  STAGING ONLY — this tool does NOT launch exploits.              │")))
    print(C.bold(C.red(
        "  │  Each path below is a planning queue for a HUMAN operator to     │")))
    print(C.bold(C.red(
        "  │  validate against scope and execute MANUALLY, then re-run        │")))
    print(C.bold(C.red(
        "  │  assess.py with the new results. No payloads are generated.      │")))
    print(C.bold(C.red(
        "  └────────────────────────────────────────────────────────────────┘")))
    print()
    if not paths:
        print(C.dim("  (no attack paths derived)"))
        return
    for p in paths[:PATHS_CAP]:
        print(f"  {C.bold(p['id'])}  {sev_tag(p['severity'])} "
              f"conf={p['confidence']:<6} score={p['score']:<4} {C.bold(p['name'])}")
        print(C.dim(f"        rationale: {p['rationale']}"))
        for s in p["steps"]:
            print(f"        {s['order']}. {s['tactic']:<20} "
                  f"{C.mag(s['technique_id']):<9} {s['technique']}  @ {s['host']}")
            print(C.dim(f"           → {s['guidance']}"))
            ab = s.get("abuse")
            if ab:
                print(C.dim(f"           abuse: {ab.get('impact','')}"))
                print(C.dim(f"           how:   {ab.get('how','')}"))
        print()
    if len(paths) > PATHS_CAP:
        print(C.dim(f"  … +{len(paths) - PATHS_CAP} more path(s) "
                    "(highest-scoring shown; use --json for the full list)"))


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def build_parser():
    ap = argparse.ArgumentParser(
        description="Run the full pentest-engine pipeline against a target "
                    "(authorized use only; stages methodology, does not exploit).")
    ap.add_argument("target", nargs="?", help="target IP / CIDR / hostname to assess")
    ap.add_argument("--from-xml", dest="from_xml",
                    help="analyse an existing nmap XML offline (no scanning)")
    ap.add_argument("--from-dir", dest="from_dir",
                    help="ingest an engagement EVIDENCE FOLDER (recursively merges all "
                         "nmap XML/.nmap/.gnmap + scans text artifacts) offline, then "
                         "guides the next stages. No scanning.")
    ap.add_argument("--scope", help="scope allowlist file (CIDR/host per line, # comments)")
    ap.add_argument("--mode", choices=MODES, default=DEFAULT_MODE,
                    help="operation profile: vapt (safe, detection-only; default) or "
                         "redteam (in-depth, intrusive enumeration, higher risk). "
                         "Both STAGE only — neither auto-exploits.")
    ap.add_argument("--scripts", default=None,
                    help="override the mode's nmap --script value")
    ap.add_argument("--exposure", choices=list(EXPOSURE_LEVELS),
                    help="asset exposure for composite risk scoring (default: config 0.5)")
    ap.add_argument("--business", choices=list(BUSINESS_LEVELS),
                    help="asset business criticality for composite risk scoring (default: 0.5)")
    ap.add_argument("--kev", dest="kev_file",
                    help="file of CISA-KEV CVE ids (one per line) — forces those CVEs to critical")
    ap.add_argument("--enrich", action="store_true",
                    help="enrich risk scoring with live CISA-KEV + FIRST-EPSS feeds "
                         "(cached under the app data dir; egress to public feeds only)")
    ap.add_argument("--offline", action="store_true",
                    help="use cached intel only, never fetch (implies --enrich)")
    ap.add_argument("--assets", dest="assets_file",
                    help="YAML/JSON map of host -> {exposure, business} for per-asset risk scoring")
    ap.add_argument("--ports", help="nmap -p port spec (default: nmap default ports)")
    ap.add_argument("--timing", default=None, help="override the mode's nmap -T timing template")
    ap.add_argument("--Pn", dest="pn", action="store_true",
                    help="skip host discovery (nmap -Pn); needed for hosts that "
                         "block ping, e.g. cloud/firewalled targets")
    ap.add_argument("--extra-args", dest="extra_args", default="",
                    help="extra nmap flags appended verbatim (e.g. '--min-rate 500 -Pn')")
    ap.add_argument("--json", dest="json_out", help="dump full pipeline result to JSON")
    ap.add_argument("--emit-json", dest="emit_json",
                    help="write the stable engagement JSON contract (hosts, findings, "
                         "ATT&CK attack paths, kill-chain) for the Flutter desktop viewer "
                         "/ external frontends")
    ap.add_argument("--web", action="append", default=[],
                    help="web app target URL for OWASP-WSTG AppSec methodology "
                         "(repeatable; comma-separated ok). Discovered http/https "
                         "services are auto-promoted to web targets regardless.")
    ap.add_argument("--api", action="append", default=[],
                    help="API target URL for OWASP API Security Top 10 methodology "
                         "(repeatable; REST/GraphQL).")
    ap.add_argument("--mobile", action="append", default=[],
                    help="mobile app file (APK/IPA) for OWASP MASVS methodology (repeatable).")
    ap.add_argument("--thick", action="append", default=[],
                    help="thick-client binary (exe/dll/jar/ELF/.app/.dmg) for desktop-app review; "
                         "platform (windows/linux/macos) inferred from extension (repeatable).")
    ap.add_argument("--cloud", action="append", default=[],
                    help="cloud target: aws|azure|gcp[:account] for ATT&CK-Cloud methodology (repeatable).")
    ap.add_argument("--wireless", action="append", default=[],
                    help="wireless/RF target: wifi|ble|zigbee|rf or an SSID (repeatable).")
    ap.add_argument("--k8s", action="append", default=[],
                    help="Kubernetes target: cluster endpoint / kubeconfig / context "
                         "for ATT&CK-Containers methodology (repeatable).")
    ap.add_argument("--source", action="append", default=[],
                    help="source/supply-chain target: repo path or URL (SAST/secrets/SCA/SBOM) (repeatable).")
    ap.add_argument("--identity", action="append", default=[],
                    help="SaaS identity target: entra|m365|okta|gworkspace|adfs[:tenant] (repeatable).")
    ap.add_argument("--hypervisor", action="append", default=[],
                    help="hypervisor target: esxi|vcenter|proxmox|xen|hyperv[:host] (repeatable).")
    ap.add_argument("--bloodhound",
                    help="BloodHound/SoapHound/RustHound export (zip/dir/json) -> staged AD paths")
    ap.add_argument("--owned", action="append", default=[],
                    help="owned starting principal for the AD graph (name or SID; repeatable)")
    ap.add_argument("--domain", help="AD/DNS domain to fill into staged commands (else inferred)")
    ap.add_argument("--user", help="username to fill into staged commands (non-secret)")
    ap.add_argument("--dc", help="domain-controller host/IP to fill into staged commands")
    ap.add_argument("--ctx", action="append", default=[],
                    help="extra context k=v filled as <k> in commands, e.g. --ctx listener=10.0.0.5 (repeatable)")
    ap.add_argument("--report", dest="report_out",
                    help="write an engagement report (.md or .html by extension)")
    ap.add_argument("--navigator", dest="navigator_out",
                    help="write a MITRE ATT&CK Navigator layer (.json)")
    ap.add_argument("--runbook", dest="runbook_out",
                    help="write an operator runbook (.md) — checkbox playbook of staged "
                         "paths + reference commands the operator runs manually")
    ap.add_argument("--killchain", dest="killchain_out",
                    help="write the 5-stage kill-chain playbook (.md): recon -> actions on "
                         "objectives, ATT&CK-mapped, staging only")
    ap.add_argument("--containers", dest="containers_out",
                    help="write containerized runners for the staged methodology into this dir "
                         "(operator runs them; engine executes nothing)")
    ap.add_argument("--runtime", choices=["podman", "docker", "kubernetes"], default="podman",
                    help="container runtime for --containers (default podman)")
    ap.add_argument("--run-containers", dest="run_containers", action="store_true",
                    help="opt-in: actually RUN the non-intrusive ENUMERATION checks in "
                         "containers (same category as the nmap scan). Never runs exploits "
                         "or credential brute — those stay staged for the operator.")
    ap.add_argument("--threads", type=int, default=6,
                    help="parallel container workers for --run-containers (default 6)")
    ap.add_argument("--ledger", dest="ledger_db",
                    help="record this run into a persistent SQLite engagement ledger")
    ap.add_argument("--llm", action="store_true",
                    help="enable the LOCAL LLM co-pilot (Ollama): AI executive summary, adviser "
                         "next-moves, and an AI operator playbook (concrete red-team tradecraft). "
                         "Offline-safe; runs locally so engagement data stays on this machine.")
    ap.add_argument("--llm-model", dest="llm_model", default=None,
                    help="force a specific local Ollama model for the co-pilot (else auto-picked)")
    ap.add_argument("--yes", action="store_true",
                    help="assert authorization non-interactively (logged)")
    return ap


def derive_targets(args):
    """Returns (targets, hosts, meta, source, evidence_findings).

    targets is a list of (label, [identifiers]) for the scope gate. For offline
    sources (--from-xml / --from-dir) the inventory is parsed up-front so targets
    come from real hosts. evidence_findings is non-empty only for --from-dir.
    """
    if args.from_dir:
        if not os.path.isdir(args.from_dir):
            raise SystemExit(C.red(f"[error] not a directory: {args.from_dir}"))
        hosts, meta, evidence, manifest = ingest_dir(args.from_dir)
        if not hosts and not evidence:
            raise SystemExit(C.red(f"[error] no nmap output or evidence parsed from {args.from_dir}"))
        targets = ([(host_label(h), host_identifiers(h)) for h in hosts]
                   or [(os.path.basename(os.path.normpath(args.from_dir)) or args.from_dir, [])])
        meta["_manifest"] = manifest
        return targets, hosts, meta, args.from_dir, evidence

    if args.from_xml:
        if not os.path.exists(args.from_xml):
            raise SystemExit(C.red(f"[error] no such file: {args.from_xml}"))
        hosts, meta, _ = load_scan(args.from_xml)
        if not hosts:
            raise SystemExit(C.red("[error] no hosts parsed from XML."))
        targets = [(host_label(h), host_identifiers(h)) for h in hosts]
        return targets, hosts, meta, args.from_xml, []

    target = args.target
    if not target:
        if not sys.stdin.isatty():
            raise SystemExit(C.red("[error] no target given (and no TTY to prompt). "
                                   "Pass a target, --from-xml or --from-dir."))
        target = input("Target to assess (IP / CIDR / hostname): ").strip()
    if not target:
        raise SystemExit(C.red("[error] no target given."))
    return [(target, [target])], None, None, None, []


def _num_or_none(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _load_assets(path):
    """Per-asset risk map: host -> {exposure: float, business: float}.

    YAML or JSON. Values may be level names (exposure: internet/internal/isolated;
    business: low/medium/high/critical) or raw 0-1 floats. Returns {} on any error
    so scoring falls back to the global --exposure/--business.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
        if path.lower().endswith((".yaml", ".yml")):
            import yaml
            data = yaml.safe_load(raw) or {}
        else:
            data = json.loads(raw)
    except Exception as e:
        print(C.ylw(f"  [assets] could not load {path}: {e}"))
        return {}
    if isinstance(data, dict) and isinstance(data.get("assets"), dict):
        data = data["assets"]
    out = {}
    for host, cfg in (data or {}).items():
        if not isinstance(cfg, dict):
            continue
        entry = {}
        if cfg.get("exposure") is not None:
            entry["exposure"] = EXPOSURE_LEVELS.get(str(cfg["exposure"]).lower(),
                                                    _num_or_none(cfg["exposure"]))
        if cfg.get("business") is not None:
            entry["business"] = BUSINESS_LEVELS.get(str(cfg["business"]).lower(),
                                                    _num_or_none(cfg["business"]))
        entry = {k: max(0.0, min(1.0, v)) for k, v in entry.items() if v is not None}
        if entry:
            out[host] = entry
    return out


def build_engagement_json(report, mods, paths, scan_meta):
    """Project the computed engagement into the stable JSON contract consumed by
    external frontends (the Flutter desktop viewer, a future web UI).

    Pure data projection of already-computed results — no scanning, no analysis,
    no execution. The output is a staging artifact a human reviews; every
    attack-path step carries its ATT&CK technique, abuse insight and the same
    ready command the console's Exploitation tab copies. Staging only.
    """
    offline = bool(scan_meta.get("from_xml") or scan_meta.get("from_dir"))
    source = scan_meta.get("from_xml") or scan_meta.get("from_dir") or "live"

    # ports keyed by the SAME host label build_report() uses, so hosts join cleanly
    ports_by_label = {}
    for h in report.get("hosts", []):
        label = (h["hostnames"][0] if h.get("hostnames") else h.get("ip")) or h.get("ipv6") or "?"
        plist = []
        for p in h.get("ports", []):
            svc = p.get("service", {})
            plist.append({"port": p.get("port", 0), "protocol": p.get("protocol", "tcp"),
                          "service": svc.get("name", ""), "product": svc.get("product", ""),
                          "version": svc.get("version", "")})
        ports_by_label[label] = plist

    hosts = [{
        "ip": hs.get("ip", ""), "label": hs.get("host", "?"), "os": hs.get("os", ""),
        "device_class": hs.get("device_class", ""), "grade": hs.get("grade", "?"),
        "score": hs.get("score", 0), "open_ports": hs.get("open_ports", 0),
        "finding_count": hs.get("findings", 0),
        "ports": ports_by_label.get(hs.get("host"), []),
    } for hs in report.get("host_summary", [])]

    findings = [{"host": f.get("host", "?"), "port": f.get("port", 0),
                 "severity": f.get("severity", "info"), "category": f.get("category", ""),
                 "title": f.get("title", ""), "cve": f.get("cve", []),
                 "owasp": f.get("owasp", []), "cwe": f.get("cwe", []),
                 "exploit_refs": f.get("exploit_refs", []),
                 "cvss4": f.get("cvss4", ""), "cvss4_band": f.get("cvss4_band", "")}
                for f in report.get("findings", [])]

    attack_paths = []
    for p in paths:
        steps = []
        for i, s in enumerate(p.get("steps", []), 1):
            abuse = s.get("abuse") or {}
            command = abuse.get("how") or s.get("guidance", "") or s.get("basis", "")
            steps.append({
                "order": s.get("order", i), "tactic": s.get("tactic", ""),
                "technique_id": s.get("technique_id", ""), "technique": s.get("technique", ""),
                "host": s.get("host", ""), "basis": s.get("basis", ""),
                "edge": s.get("edge", ""), "guidance": s.get("guidance", ""), "command": command,
                "abuse": {"impact": abuse.get("impact", ""), "how": abuse.get("how", ""),
                          "opsec": abuse.get("opsec", "")},
            })
        attack_paths.append({
            "id": p.get("id", ""), "name": p.get("name", ""), "kind": p.get("kind", ""),
            "severity": p.get("severity", "info"), "confidence": p.get("confidence", ""),
            "score": p.get("score", 0), "hosts": p.get("hosts", []),
            "tactics": p.get("tactics", []), "rationale": p.get("rationale", ""), "steps": steps})

    stages = []
    try:
        from killchain import build_killchain
        for st in build_killchain(report, mods, paths):
            stages.append({"id": st.get("id", 0), "name": st.get("name", ""),
                           "phases": st.get("phases", []), "tactics": st.get("tactics", []),
                           "objective": st.get("objective", ""), "boundary": st.get("boundary", ""),
                           "staged_step_count": len(st.get("staged_steps", [])),
                           "path_ids": st.get("path_ids", []),
                           "finding_count": len(st.get("findings", []))})
    except Exception:
        stages = []

    return {
        "schema": "redengine.engagement", "schema_version": 1,
        "meta": {
            "generated": datetime.now(timezone.utc).isoformat(),
            "tool": "redengine-cli", "engine_version": report.get("version", ""),
            "mode": scan_meta.get("mode", ""), "target": scan_meta.get("target", ""),
            "offline": offline, "source": source,
            "totals": report.get("totals", {}),
            "severity_counts": report.get("severity_counts", {}),
            "unique_cves": report.get("unique_cves", []),
            "boundary": ("STAGING ONLY — this engagement plan executes nothing. A human "
                         "operator runs each step manually, in authorized scope."),
        },
        "hosts": hosts, "findings": findings, "attack_paths": attack_paths,
        "killchain": {"stages": stages},
        "recommendations": _cp_recommend(findings, attack_paths),
    }


def main(argv=None):
    from nmap_analyzer import _force_utf8_stdio   # console safety, not just via import side-effect
    _force_utf8_stdio()
    args = build_parser().parse_args(argv)

    targets, hosts, meta, _src, evidence = derive_targets(args)

    # Stage 0 — scope gate
    if not scope_gate(args, targets):
        return 2

    # Stage 1 — enumeration (mode-driven profile)
    profile = get_profile(args.mode)
    scripts = args.scripts or profile["scripts"]
    timing = args.timing or profile["timing"]
    pn = args.pn or profile["pn"]
    banner("Stage 1 — Enumeration")
    tag = C.red if profile["risk"] == "high" else C.cyan
    print(f"  mode: {tag(C.bold(profile['label']))}  ({profile['banner']})")
    if args.from_dir:
        print(f"  offline: ingested evidence folder {C.bold(args.from_dir)} — "
              f"{len(hosts)} merged host(s), {len(evidence)} evidence finding(s) "
              "(no scanning; mode is informational here)")
        for rel, kind, n in (meta.get("_manifest") or [])[:40]:
            print(C.dim(f"        {kind:18} {rel}  ({n})"))
    elif args.from_xml:
        print(f"  offline: analysing existing scan {C.bold(args.from_xml)} "
              "(no scanning performed; mode does not change offline analysis)")
    else:
        target = targets[0][0]
        xml_path = run_nmap(target, scripts, timing, args.ports,
                            pn=pn, extra_args=args.extra_args or profile.get("extra", ""),
                            os_detect=profile["os_detect"],
                            aggressive=profile.get("aggressive", False),
                            full_ports=profile.get("full_ports", False),
                            udp_ports=profile.get("udp_ports", ""))
        hosts, meta, _ = load_scan(xml_path)
        if not hosts:
            print(C.ylw("  no live hosts / open ports found."))
        else:
            banner("Stage 1b — Per-service enumeration (targeted NSE)")
            print(C.dim("  Following the broad sweep with service-specific NSE scans "
                        "(per docs/nse_mapping.md), merged back into the inventory.\n"))
            hosts = deep_service_scan(hosts, workers=args.threads)

    # Stage 2 — analysis (merge ingested evidence findings with the parsed inventory)
    banner("Stage 2 — Analysis (inventory + findings)")
    expo = EXPOSURE_LEVELS.get(args.exposure) if args.exposure else None
    biz = BUSINESS_LEVELS.get(args.business) if args.business else None
    kev = set()
    if args.kev_file and os.path.isfile(args.kev_file):
        with open(args.kev_file, "r", encoding="utf-8", errors="ignore") as fh:
            import re as _re
            kev = {c.upper() for c in _re.findall(r"CVE-\d{4}-\d+", fh.read(), _re.I)}
    epss_map = None
    if args.enrich or args.offline:                # --offline implies cache-only enrichment
        try:
            from enrich import enrich as _enrich
            kev_live, epss_map = _enrich(offline=args.offline)
            kev |= kev_live
            print(C.dim(f"  enrichment: {len(kev_live)} KEV + {len(epss_map)} EPSS scores "
                        f"({'cache-only' if args.offline else 'live feeds'})"))
        except Exception as e:                                          # pragma: no cover
            print(C.ylw(f"  enrichment unavailable: {e}"))
    asset_cfg = _load_assets(args.assets_file) if args.assets_file else None
    findings = analyze(hosts, exposure=expo, business=biz, kev_cves=(kev or None),
                       epss_map=epss_map, asset_cfg=asset_cfg) + evidence
    findings.sort(key=lambda f: SEV_RANK.get(f["severity"], 9))
    # Exploit references (public links, never payloads) — always available from
    # the bundled seed; --enrich (live) or --offline (cache-only) opts into the
    # ExploitDB CSV cross-reference as well.
    try:
        from exploit_refs import enrich_findings as _enrich_exploits
        _enrich_exploits(findings, offline=(args.offline or not args.enrich))
        _n = sum(1 for f in findings if f.get("exploit_refs"))
        if _n:
            print(C.dim(f"  exploit references: {_n} finding(s) linked to public PoCs"))
    except Exception as e:                                              # pragma: no cover
        print(C.ylw(f"  exploit-refs unavailable: {e}"))
    # CVSS 4.0 vector on every finding — deterministic, offline-safe.
    try:
        from cvss4 import enrich_findings as _enrich_cvss4
        _enrich_cvss4(findings)
    except Exception as e:                                              # pragma: no cover
        print(C.ylw(f"  cvss4 unavailable: {e}"))
    report = build_report(hosts, meta, findings)
    print_inventory(report)
    print(C.bold("\n  Findings (by severity):"))
    print_findings(report)

    # Stage 3 — possible pentesting
    banner("Stage 3 — Possible pentesting (per-service methodology)")
    from apptargets import app_targets as _app_targets
    apps = _app_targets(report, web=args.web, api=args.api, mobile=args.mobile,
                        thick=args.thick, cloud=args.cloud, wireless=args.wireless,
                        k8s=args.k8s, source=args.source, identity=args.identity,
                        hypervisor=args.hypervisor)
    if apps:
        srcs = ", ".join(t["ref"] for t in apps[:6]) + (" ..." if len(apps) > 6 else "")
        print(C.dim(f"  {len(apps)} application target(s) for AppSec methodology: {srcs}"))
    mods = dispatch(report, mode=args.mode, app_targets=apps)
    print_modules(mods)
    # Tool availability advisory (config.missing_tools): flag operator tools not on PATH.
    import config as _cfg
    _tools = []
    for m in mods:
        for c in m.get("checks", []):
            cmd = (c.get("command") or "").strip()
            if cmd and not cmd.startswith("#") and cmd[:1].isalpha():
                _tools.append(cmd.split()[0])
    _missing = _cfg.missing_tools(_tools)
    if _missing:
        print(C.ylw(f"  [tools] not on PATH ({len(_missing)}): " + ", ".join(_missing[:14])
                    + (" …" if len(_missing) > 14 else "")))
        print(C.dim("  (install these, or set REDENGINE_* paths; methodology is still shown as reference)"))

    # Opt-in: run the non-intrusive ENUMERATION checks in containers (not exploits).
    if args.run_containers:
        banner("Stage 3b — Containerized enumeration (non-intrusive; operator-authorized)")
        import containers as _ct
        n_runnable = len(_ct.runnable_checks(mods))
        print(C.dim(f"  running {n_runnable} enumeration check(s) across {args.threads} "
                    f"parallel {args.runtime} worker(s); exploits/credential-testing excluded.\n"))
        try:
            results = _ct.run_enumeration(mods, runtime=args.runtime, workers=args.threads,
                                          progress=lambda s: print(C.dim(f"  · {s}")))
        except RuntimeError as e:
            print(C.red(f"  [skip] {e} — generate runners instead with --containers."))
            results = []
        from evidence import scan_text_indicators
        for r in results:
            tag = C.grn("ok") if r.get("rc") == 0 else C.ylw(f"rc={r.get('rc')}")
            print(f"  [{tag}] {C.bold(r['module'])} {r['name']}  ({r['attack']})")
            for ind in scan_text_indicators(r.get("output", ""), f"{r['module']}/{r['name']}"):
                report.setdefault("findings", []).append(ind)
                print(C.ylw(f"        + {ind['severity'].upper()} {ind['title']}"))
        if results:
            print(C.dim("  (enumeration only — exploits & credential testing were not run; "
                        "stage those for manual execution)"))

    # Stage 4 — exploitation handoff
    banner("Stage 4 — Exploitation handoff (staged operator queue)")
    paths = generate_paths(report)
    if args.bloodhound:
        try:
            from ad_graph import ingest as _bh_ingest
            _g, _adp = _bh_ingest(args.bloodhound, args.owned or ())
            paths += _adp
            print(C.grn(f"[+] AD graph: {len(_adp)} staged privilege path(s) from "
                        f"{os.path.basename(args.bloodhound)} ({len(_g.nodes)} nodes, "
                        f"{len(_g.high)} high-value)"))
        except Exception as e:                                         # pragma: no cover
            print(C.ylw(f"  [bloodhound] ingest failed: {e}"))
    print_attack_paths(paths)

    # Kill-chain coverage view (recon -> actions on objectives; staging only)
    from killchain import coverage_summary
    banner("Stage 5 — Kill-chain coverage (Recon → Actions on Objectives)")
    for sid, name, nsteps, npaths in coverage_summary(report, mods, paths):
        print(f"  Stage {sid}  {C.bold(name):<46} staged steps={nsteps:<3} paths={npaths}")
    print(C.dim("  (methodology + staging only — operator executes each step; "
                "--killchain writes the full playbook)"))

    # Optional JSON dump
    if args.json_out:
        payload = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "scan": {
                "target": targets[0][0] if len(targets) == 1 else [t[0] for t in targets],
                "from_xml": args.from_xml,
                "from_dir": args.from_dir,
                "mode": args.mode,
                "offline": bool(args.from_xml or args.from_dir),
                "scripts": None if (args.from_xml or args.from_dir) else scripts,
                "ports": None if (args.from_xml or args.from_dir) else args.ports,
                "meta": {k: v for k, v in meta.items() if k != "_manifest"},
            },
            "report": {k: v for k, v in report.items() if k != "hosts"},
            "modules": mods,
            "attack_paths": paths,
        }
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(C.grn(f"[+] JSON written: {args.json_out}"))

    from context import infer as _infer_ctx, apply as _apply_ctx
    _ctx = _infer_ctx(report, {"domain": args.domain, "user": args.user, "dc": args.dc,
                               **dict(kv.split("=", 1) for kv in args.ctx if "=" in kv)})
    if _ctx:
        _apply_ctx(mods, paths, _ctx)
        print(C.dim("  context filled into staged commands: "
                    + ", ".join(f"{k}={v}" for k, v in _ctx.items())))

    recs = _cp_recommend(report.get("findings", []), paths)
    if recs:
        print(C.bold("\n  Recommended next actions (co-pilot):"))
        for a in recs[:5]:
            print(f"    #{a['rank']} [{a['score']:>3}] {C.bold(a['title'])}  ({a['category']})")
            print(C.dim(f"        {a['why']}"))

    scan_meta = {"mode": args.mode, "from_xml": args.from_xml, "from_dir": args.from_dir,
                 "target": targets[0][0] if targets else ""}

    # Build the engagement projection once if anything downstream needs it.
    eng_payload = None
    if args.emit_json or args.llm:
        eng_payload = build_engagement_json(report, mods, paths, scan_meta)

    # Optional LOCAL LLM co-pilot — offline-safe, local (data stays on this machine).
    _llm_addendum = ""
    if args.llm:
        try:
            import advisor as _adv
            import llm as _llm
        except Exception as exc:                                       # pragma: no cover
            _adv = None
            print(C.dim(f"  --llm requested but co-pilot unavailable: {exc}"))
        if _adv is not None:
            if _llm.available():
                model = args.llm_model or None
                print(C.dim(f"  local LLM co-pilot online — planner={_llm.pick('planner')}, "
                            f"narrator={_llm.pick('narrator')} (data stays on this machine)"))
                # Fast role first (7B adviser) so the operator sees value immediately.
                advice = _adv.advise(eng_payload, model=model)
                if advice:
                    eng_payload["advice"] = advice
                    print(C.bold("\n  Adviser — next moves (local LLM):"))
                    for i, a in enumerate(advice, 1):
                        tag = f" [{a['attack']}]" if a.get("attack") else ""
                        print(f"    {i}. {a['suggestion']}{tag}")
                        if a.get("why"):
                            print(C.dim(f"        why: {a['why']}"))
                if args.runbook_out:
                    _llm_addendum = _adv.runbook_addendum_md(
                        eng_payload.get("attack_paths", []), ctx=_ctx or None, model=model)
                # Narrator last (may be a large, minutes-slow local model).
                _nar = _llm.pick("narrator")
                print(C.dim(f"  generating executive summary with {_nar} — a large local model, "
                            "this can take a few minutes; use --llm-model qwen2.5:7b for a faster one"))
                summary = _adv.exec_summary(eng_payload, model=model)
                if summary:
                    eng_payload["executive_summary"] = summary
                    print(C.grn("  executive summary ready (added to engagement JSON)"))
            else:
                print(C.dim("  --llm set but no local Ollama model reachable "
                            "(is `ollama serve` up?); LLM extras skipped, engine unaffected"))

    if args.emit_json:
        with open(args.emit_json, "w", encoding="utf-8") as fh:
            json.dump(eng_payload, fh, indent=2)
        print(C.grn(f"[+] Engagement JSON (frontend contract) written: {args.emit_json}"))
    if args.report_out:
        from reporting import write_report
        write_report(report, mods, paths, args.report_out, scan=scan_meta)
        print(C.grn(f"[+] Report written: {args.report_out}"))
    if args.navigator_out:
        from reporting import write_navigator
        write_navigator(mods, paths, args.navigator_out)
        print(C.grn(f"[+] ATT&CK Navigator layer written: {args.navigator_out}"))
    if args.runbook_out:
        from reporting import write_runbook
        write_runbook(report, mods, paths, args.runbook_out, scan=scan_meta)
        if _llm_addendum:
            with open(args.runbook_out, "a", encoding="utf-8") as fh:
                fh.write(_llm_addendum)
        print(C.grn(f"[+] Operator runbook written: {args.runbook_out}"
                    + (" (+ AI-expanded playbook)" if _llm_addendum else "")))
    if args.killchain_out:
        from killchain import write_killchain
        write_killchain(report, mods, paths, args.killchain_out, scan=scan_meta)
        print(C.grn(f"[+] Kill-chain playbook written: {args.killchain_out}"))
    if args.containers_out:
        import containers as _ct
        os.makedirs(args.containers_out, exist_ok=True)
        if args.runtime == "kubernetes":
            out = os.path.join(args.containers_out, "jobs.yaml")
            n = _ct.write_k8s_jobs(mods, out)
            print(C.grn(f"[+] {n} Kubernetes Job(s) written: {out} "
                        "(operator runs: kubectl apply -f)"))
        else:
            out = os.path.join(args.containers_out, "runners.sh")
            _ct.write_runner_script(mods, out, args.runtime)
            print(C.grn(f"[+] Container runner script written: {out} "
                        f"(operator runs each {args.runtime} command in scope)"))
    if args.ledger_db:
        from ledger import record_run, diff
        rid = record_run(args.ledger_db, report, mods, paths, scan_meta)
        print(C.grn(f"[+] Recorded run #{rid} in ledger {args.ledger_db}"))
        d = diff(args.ledger_db)
        if d and (d["new"] or d["fixed"] or d["grade_changes"]):
            muted = d.get("muted", [])
            print(C.bold("  Changes since previous run: ")
                  + C.red(f"{len(d['new'])} new") + ", "
                  + C.grn(f"{len(d['fixed'])} fixed") + ", "
                  + f"{len(d['still_open'])} still-open"
                  + (f", {len(muted)} muted" if muted else ""))
            for f in d["new"][:8]:
                tgt = f"{f['host']}:{f['port']}" if f['port'] else f['host']
                print(C.red(f"    + [{f['severity']}] {tgt}  {f['title']}"))
            for f in d["fixed"][:8]:
                tgt = f"{f['host']}:{f['port']}" if f['port'] else f['host']
                print(C.grn(f"    - fixed   {tgt}  {f['title']}"))
            for g in d["grade_changes"]:
                print(f"    ~ grade {g['label']}: {g['old']} -> {g['new']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
