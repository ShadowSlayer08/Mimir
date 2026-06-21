#!/usr/bin/env python3
"""
modules — knowledge-driven assessment dispatcher.

Authorized / lab / CTF use only.

The dispatcher is now driven by the docs/ knowledge base (service_registry +
per-module methodology in docs/modules/*.md), loaded via knowledge_loader. Each
host is routed to the modules its services map to; each module's checks and
attack-surface notes come from the Markdown, not from Python. If the knowledge
base is unavailable, it falls back to the built-in module classes.
"""
from __future__ import annotations

import os
import string
import sys

from .base import Module, ModuleResult, Check, host_label, looks_like_dc, SEV_RANK
from .web import WebModule
from .smb import SMBModule
from .active_directory import ADModule
from .database import DatabaseModule
from .ssh import SSHModule
from .rdp import RDPModule
from .ftp import FTPModule
from .telnet import TelnetModule
from .rservices import RServicesModule
from .mail import MailModule
from .dns import DNSModule
from .snmp import SNMPModule
from .vnc import VNCModule
from .nfs import NFSModule
from .winrm import WinRMModule
from .container import ContainerModule
from .ics import ICSModule
from .ipmi import IPMIModule
from .printer import PrinterModule
from .mq import MQModule
from .vpn import VPNModule
from .tftp import TFTPModule
from .rsync import RsyncModule
from .x11 import X11Module
from .ntp import NTPModule
from .finger import FingerModule
from .voip import VoIPModule
from .proxy import ProxyModule
from .cisco_smi import CiscoSMIModule
from .netconf import NetconfModule
from .aaa import AAAModule
from .afp import AFPModule
from .iscsi import IscsiModule
from .rtsp import RTSPModule
from .iot import IoTModule

# built-in fallback (used only if the knowledge base can't be loaded); mirrors
# the docs/modules/*.md set so the engine keeps full coverage without docs/.
REGISTRY = [
    WebModule(), SMBModule(), ADModule(), DatabaseModule(),
    SSHModule(), RDPModule(), FTPModule(), TelnetModule(), RServicesModule(),
    MailModule(), DNSModule(), SNMPModule(), VNCModule(), NFSModule(),
    WinRMModule(), ContainerModule(), ICSModule(), IPMIModule(), PrinterModule(),
    MQModule(), VPNModule(), TFTPModule(), RsyncModule(), X11Module(),
    NTPModule(), FingerModule(), VoIPModule(), ProxyModule(),
    CiscoSMIModule(), NetconfModule(), AAAModule(), AFPModule(), IscsiModule(),
    RTSPModule(), IoTModule(),
]

__all__ = ["dispatch", "REGISTRY", "Module", "ModuleResult", "Check", "host_label"]


# --------------------------------------------------------------------------- #
# knowledge-driven generation
# --------------------------------------------------------------------------- #
class _SafeDict(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(s, ctx):
    return string.Formatter().vformat(s or "", (), _SafeDict(ctx))


def _match(name, frag):
    name = (name or "").lower()
    return name == frag or name.startswith(frag) or frag in name


def _match_rank(name, frag):
    name = (name or "").lower()
    if name == frag:
        return 3
    if name.startswith(frag):
        return 2
    if frag in name:
        return 1
    return 0


def _flag(when, flags):
    when = (when or "").strip()
    if when in ("", "always"):
        return True
    neg = when.startswith("not ")
    key = when[4:].strip() if neg else when
    val = bool(flags.get(key, False))
    return (not val) if neg else val


def _matched_frag(name, matches):
    """Most-specific matching fragment (exact > prefix > substring, longest)."""
    best, best_key = None, (0, 0)
    for f in matches:
        r = _match_rank(name, f)
        if r and (r, len(f)) > best_key:
            best_key, best = (r, len(f)), f
    return best


def _build_result(mdef, host, findings, port_obj, ms17010):
    label = host_label(host)
    ip = host.get("ip") or label
    svc = port_obj["service"] if port_obj else {}
    name = (svc.get("name") or "").lower()
    matches = mdef.get("matches", [])
    frag = _matched_frag(name, matches) or name
    port = port_obj["port"] if port_obj else 0
    prod = " ".join(x for x in (svc.get("product"), svc.get("version")) if x) or "service"
    ver = svc.get("version", "")
    tls = (svc.get("tunnel", "") == "ssl" or name == "https"
           or port in (mdef.get("tls_ports") or []))
    scheme = "https" if tls else "http"

    labels = mdef.get("labels", {}) or {}
    disp = labels.get(frag, prod)
    connect = mdef.get("connect", {}) or {}
    ctx = {"ip": ip, "port": port, "scheme": scheme, "SCHEME": scheme.upper(),
           "label": label, "domain": "<domain>", "frag": frag, "disp": disp,
           "prod": prod, "ver": ver}
    try:
        from config import PATHS as _PATHS
        ctx.update(_PATHS)            # {seclists}/{wordlists}/{users}/{passwords}
    except Exception:                 # pragma: no cover
        pass
    ctx["auth_cmd"] = _fmt(connect.get(frag, ""), ctx)

    unauth = frag in (mdef.get("unauth_services") or [])

    # findings relevant to this result
    if mdef.get("scope") == "port":
        rel = [f for f in findings if f.get("port") == port]
    else:
        cats = set(mdef.get("finding_categories", []))
        kws = [k.lower() for k in mdef.get("finding_keywords", [])]
        port_ids = {p["port"] for p in host.get("ports", []) if _matched_frag((p["service"].get("name") or "").lower(), matches)}
        rel = [f for f in findings
               if f.get("port") in port_ids or f.get("category") in cats
               or any(k in f["title"].lower() for k in kws)]

    flags = {"tls": tls, "unauth": unauth, "ms17010": ms17010,
             "samba": "samba" in prod.lower(),
             "has_cve": any(f.get("category") == "CVE (vulners)" for f in rel)}

    surface = [_fmt(r["note"], ctx) for r in (mdef.get("attack_surface") or [])
               if _flag(r.get("when"), flags)]

    checks, techs = [], set(mdef.get("techniques_extra", []))
    for c in mdef.get("checks", []):
        if not _flag(c.get("when"), flags):
            continue
        checks.append(Check(c["name"], _fmt(c["command"], ctx), c.get("purpose", ""),
                            c.get("attack", "")).to_dict())
        if c.get("attack"):
            techs.add(c["attack"])

    sev = min((f["severity"] for f in rel), key=lambda s: SEV_RANK.get(s, 9)) if rel else "info"
    target = f"{label}:{port}" if (mdef.get("scope") == "port" and port) else label
    return ModuleResult(mdef["module"], mdef.get("title", mdef["module"]), target,
                        frag if mdef.get("scope") == "port" else mdef["module"],
                        _fmt(mdef.get("summary", "{prod}"), ctx), sev,
                        techniques=sorted(techs), attack_surface=surface,
                        checks=checks, findings=rel)


def _dispatch_kb(report, kb):
    from collections import defaultdict
    by_host = defaultdict(list)
    for f in report.get("findings", []):
        by_host[f["host"]].append(f)
    results = []
    for h in report.get("hosts", []):
        label = host_label(h)
        ff = by_host.get(label, [])
        ms17010 = any(("ms17-010" in f["title"].lower() or "eternalblue" in f["title"].lower())
                      for f in ff)
        # which modules apply to this host?
        applied = []
        for p in h.get("ports", []):
            for mname in kb.modules_for(p["service"].get("name", "")):
                if mname not in applied:
                    applied.append(mname)
        for mname, mdef in kb.modules.items():
            if mdef.get("condition") == "is_dc" and looks_like_dc(h) and mname not in applied:
                applied.append(mname)
        # generate
        for mname in applied:
            mdef = kb.modules.get(mname)
            if not mdef:
                continue
            if mdef.get("condition") == "is_dc" and not looks_like_dc(h):
                continue
            matches = mdef.get("matches", [])
            if mdef.get("scope") == "port":
                # Build one result per port that ROUTES here (best-match registry),
                # so a port-scoped module never grabs a port owned by another module
                # via loose substring overlap (e.g. ftp vs tftp).
                for p in h.get("ports", []):
                    if mname in kb.modules_for(p["service"].get("name", "")):
                        results.append(_build_result(mdef, h, ff, p, ms17010))
            else:
                rep = next((p for p in h.get("ports", [])
                            if _matched_frag((p["service"].get("name") or "").lower(), matches)), None)
                results.append(_build_result(mdef, h, ff, rep, ms17010))
    return [r.to_dict() for r in results]


def _dispatch_builtin(report):
    from collections import defaultdict
    by_host = defaultdict(list)
    for f in report.get("findings", []):
        by_host[f["host"]].append(f)
    results = []
    for h in report.get("hosts", []):
        ff = by_host.get(host_label(h), [])
        for m in REGISTRY:
            results += [r.to_dict() if isinstance(r, ModuleResult) else r for r in m.assess(h, ff)]
    return results


import re as _re

# Brute-force / credential-spraying / lockout-risky tooling -> "intrusive".
_INTRUSIVE_CMD = _re.compile(
    r"\b(hydra|medusa|ncrack|crackmapexec|crowbar|onesixtyone|svcrack|svwar|"
    r"kerbrute|psk-crack|patator|brute|spray)\b", _re.I)


def _is_intrusive(check):
    """A check is intrusive (hidden in VAPT mode) if explicitly tagged, mapped to
    the ATT&CK Brute Force family (T1110*), or it invokes credential-testing tooling."""
    if (check.get("risk") or "").lower() == "intrusive":
        return True
    if (check.get("attack") or "").startswith("T1110"):
        return True
    return bool(_INTRUSIVE_CMD.search(check.get("command", "")))


def _apply_mode(results, mode):
    """VAPT hides intrusive checks (and notes how many); Red Team / unset shows all."""
    if (mode or "").lower() != "vapt":
        return results
    for r in results:
        checks = r.get("checks", [])
        kept = [c for c in checks if not _is_intrusive(c)]
        hidden = len(checks) - len(kept)
        r["checks"] = kept
        if hidden:
            r.setdefault("attack_surface", []).append(
                f"{hidden} intrusive step(s) hidden in VAPT mode "
                "(credential-testing/brute — use Red Team mode to show).")
    return results


def dispatch(report, docs_dir=None, mode=None):
    """Route every host through the knowledge-driven modules (docs-backed).

    mode='vapt' hides intrusive (credential-testing/brute) checks; 'redteam' or
    None shows the full methodology."""
    try:
        from knowledge_loader import load_knowledge
        kb = load_knowledge(docs_dir)
        results = _dispatch_kb(report, kb) if kb.available() else _dispatch_builtin(report)
    except Exception:
        results = _dispatch_builtin(report)
    results = _apply_mode(results, mode)
    results.sort(key=lambda r: (SEV_RANK.get(r["severity"], 9), r["module"], r["target"]))
    return results
