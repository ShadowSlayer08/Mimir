#!/usr/bin/env python3
"""
modules.base — shared types for assessment modules.

Authorized / lab / CTF use only.

A Module takes a parsed host (from nmap_analyzer) plus the findings already
computed for that host, and returns ModuleResult objects: per-target
assessment summaries with an enumeration/methodology checklist (recon and
authorized credential-testing commands), attack-surface notes, relevant
findings, and the MITRE ATT&CK techniques each step maps to.

Modules describe methodology for a human operator. They do not run anything.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Check:
    """One enumeration/methodology step."""
    name: str
    command: str          # recon / authorized-testing command template
    purpose: str
    attack: str = ""      # MITRE ATT&CK technique id (mostly Discovery/Recon)
    owasp: str = ""       # OWASP ref (WSTG / API Top 10 / MASVS) for AppSec checks
    cwe: str = ""         # CWE id (AppSec)
    risk: str = ""        # "" | "safe" | "intrusive"  (intrusive is hidden in VAPT mode)

    def to_dict(self):
        return asdict(self)


@dataclass
class ModuleResult:
    module: str
    title: str
    target: str           # "host" or "host:port"
    service: str
    summary: str
    severity: str
    techniques: list = field(default_factory=list)
    attack_surface: list = field(default_factory=list)
    checks: list = field(default_factory=list)     # list[dict]
    findings: list = field(default_factory=list)   # report finding dicts

    def to_dict(self):
        return asdict(self)


def host_label(h):
    return (h["hostnames"][0] if h.get("hostnames") else h.get("ip")) or h.get("ipv6") or "?"


def worst(findings):
    sev = [f["severity"] for f in findings]
    return min(sev, key=lambda s: SEV_RANK.get(s, 9)) if sev else "info"


def looks_like_dc(host):
    names = [(p["service"].get("name") or "").lower() for p in host.get("ports", [])]
    if any(any(a in n for a in ("kerberos", "ldap", "kpasswd", "globalcat")) for n in names):
        return True
    return bool(re.search(r"(?i)(^|[^a-z])dc\d*([^a-z]|$)", host_label(host)))


class Module:
    name = "base"
    title = "Base"

    def assess(self, host, findings):     # -> list[ModuleResult]
        return []

    # helpers --------------------------------------------------------------
    def ports(self, host, names):
        out = []
        for p in host.get("ports", []):
            n = (p["service"].get("name") or "").lower()
            if any(n == frag or n.startswith(frag) or frag in n for frag in names):
                out.append(p)
        return out

    def findings_for_port(self, findings, ports):
        ids = ports if isinstance(ports, (set, list, tuple)) else {ports}
        return [f for f in findings if f.get("port") in ids]

    @staticmethod
    def techs(checks, extra=()):
        return sorted({c.attack for c in checks if c.attack} | set(extra))


# --------------------------------------------------------------------------- #
# Declarative built-in fallback module
# --------------------------------------------------------------------------- #
import string


class _SafeDict(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(s, ctx):
    return string.Formatter().vformat(s or "", (), _SafeDict(ctx))


class SpecModule(Module):
    """Declarative built-in fallback module.

    Subclasses set class attributes and ``assess()`` is generated, so each
    fallback file mirrors its ``docs/modules/<id>.md`` block in a dozen lines and
    the engine keeps a full module set even when the knowledge base is absent.

    Command/summary/note templates accept ``{ip} {port} {scheme} {label}
    {domain} {frag} {disp} {prod} {ver}``. ``when`` flags: ``always`` (default),
    ``tls``, ``not_tls``, ``unauth``, ``has_cve``.
    """
    NAMES = ()              # service-name fragments (== docs `matches`)
    SCOPE = "port"          # "port" (one result per matching port) | "host"
    SUMMARY = "{disp} ({prod})."
    CHECKS = ()             # tuples: (name, attack, command, purpose[, when])
    SURFACE = ()            # tuples: (when, note)
    UNAUTH = ()             # frags frequently unauthenticated -> 'unauth' flag
    LABELS = {}             # frag -> display label
    TLS_PORTS = ()          # ports that imply TLS
    EXTRA_TECH = ()
    CONDITION = None        # "is_dc"
    KEYWORDS = ()           # finding-title keywords to attach related findings

    def ports(self, host, names):
        # exact-or-prefix only: keeps a fallback module from grabbing another's
        # port via loose substring overlap (e.g. 'ftp' inside 'tftp').
        out = []
        for p in host.get("ports", []):
            n = (p["service"].get("name") or "").lower()
            if any(n == f or n.startswith(f) for f in names):
                out.append(p)
        return out

    def _frag(self, name):
        best, best_key = (name or self.name), (0, 0)
        for f in self.NAMES:
            r = 3 if name == f else (2 if name.startswith(f) else (1 if f in name else 0))
            if r and (r, len(f)) > best_key:
                best_key, best = (r, len(f)), f
        return best

    def assess(self, host, findings):
        if self.CONDITION == "is_dc" and not looks_like_dc(host):
            return []
        ports = self.ports(host, self.NAMES)
        if self.SCOPE == "host":
            if not ports and self.CONDITION != "is_dc":
                return []
            return [self._result(host, findings, ports[0] if ports else None, ports)]
        return [self._result(host, findings, p, [p]) for p in ports]

    def _result(self, host, findings, port_obj, scope_ports):
        label = host_label(host)
        ip = host.get("ip") or label
        svc = port_obj["service"] if port_obj else {}
        name = (svc.get("name") or "").lower()
        frag = self._frag(name)
        port = port_obj["port"] if port_obj else 0
        prod = " ".join(x for x in (svc.get("product"), svc.get("version")) if x) or "service"
        ver = svc.get("version", "")
        tls = (svc.get("tunnel", "").lower() == "ssl" or name == "https" or port in self.TLS_PORTS)
        scheme = "https" if tls else "http"
        disp = self.LABELS.get(frag, prod)
        ctx = {"ip": ip, "port": port, "scheme": scheme, "label": label,
               "domain": "<domain>", "frag": frag, "disp": disp, "prod": prod, "ver": ver}
        try:
            from config import PATHS as _PATHS
            ctx.update(_PATHS)        # {seclists}/{wordlists}/{users}/{passwords}
        except Exception:             # pragma: no cover
            pass

        ids = {p["port"] for p in scope_ports if p}
        kws = [k.lower() for k in self.KEYWORDS]
        rel = [f for f in findings
               if f.get("port") in ids or any(k in f["title"].lower() for k in kws)]

        flags = {"always": True, "tls": tls, "not_tls": not tls,
                 "unauth": frag in self.UNAUTH,
                 "has_cve": any(f.get("category") == "CVE (vulners)" for f in rel)}
        surface = [_fmt(note, ctx) for when, note in self.SURFACE if flags.get(when, False)]
        checks, techs = [], set(self.EXTRA_TECH)
        for c in self.CHECKS:
            nm, atk, cmd, purpose = c[0], c[1], c[2], c[3]
            when = c[4] if len(c) > 4 else "always"
            if not flags.get(when, False):
                continue
            checks.append(Check(nm, _fmt(cmd, ctx), purpose, atk).to_dict())
            if atk:
                techs.add(atk)
        target = f"{label}:{port}" if (self.SCOPE == "port" and port) else label
        return ModuleResult(self.name, self.title, target,
                            frag if self.SCOPE == "port" else self.name,
                            _fmt(self.SUMMARY, ctx), worst(rel),
                            techniques=sorted(techs), attack_surface=surface,
                            checks=checks, findings=rel)
