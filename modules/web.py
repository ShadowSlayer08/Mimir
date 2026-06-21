#!/usr/bin/env python3
"""modules.web — HTTP/HTTPS assessment methodology."""
from __future__ import annotations

from .base import Module, ModuleResult, Check, host_label, worst

try:
    from config import SECLISTS
except Exception:                                                    # pragma: no cover
    import os
    SECLISTS = os.path.join(os.path.expanduser("~"), ".redengine", "seclists")


class WebModule(Module):
    name = "web"
    title = "Web (HTTP/HTTPS)"
    NAMES = ("http", "https", "http-proxy", "http-alt", "www", "soap")

    def assess(self, host, findings):
        label, ip = host_label(host), host.get("ip") or host_label(host)
        results = []
        for p in self.ports(host, self.NAMES):
            port, svc = p["port"], p["service"]
            name = (svc.get("name") or "").lower()
            tls = svc.get("tunnel", "") == "ssl" or name == "https" or port in (443, 8443)
            scheme = "https" if tls else "http"
            base = f"{scheme}://{ip}:{port}"
            ff = self.findings_for_port(findings, port)
            prod = " ".join(x for x in (svc.get("product"), svc.get("version")) if x) or "unknown server"

            surface = []
            if not tls:
                surface.append("Cleartext HTTP — credentials and sessions exposed on-path.")
            else:
                surface.append("TLS endpoint — review TLS protocol/cipher/cert findings.")
            if any(f["category"] == "CVE (vulners)" for f in ff):
                surface.append("Server version has known CVEs (see findings).")

            checks = [
                Check("Fingerprint", f"whatweb {base}",
                      "Identify server, framework, CMS and technologies.", "T1592.002"),
                Check("Security headers", f"curl -skI {base}",
                      "Check HSTS, CSP, X-Frame-Options, cookie flags.", "T1595.002"),
                Check("HTTP methods", f"curl -skX OPTIONS {base} -i",
                      "Detect risky verbs (PUT/DELETE/TRACE/WebDAV).", "T1595"),
                Check("Content discovery",
                      f"feroxbuster -u {base} -k -w {SECLISTS}/Discovery/Web-Content/raft-medium-directories.txt",
                      "Enumerate hidden directories and files.", "T1595.003"),
                Check("Vhost discovery", f"ffuf -u {base} -H 'Host: FUZZ.{label}' -w subdomains.txt -fs 0",
                      "Discover virtual hosts on the same service.", "T1595"),
                Check("Template scan", f"nuclei -u {base}",
                      "Run known-CVE / misconfiguration templates.", "T1595.002"),
                Check("Robots / sitemap", f"curl -sk {base}/robots.txt {base}/sitemap.xml",
                      "Surface disallowed or listed paths.", "T1593"),
                Check("Param / input testing", f"# map inputs, then test injection in scope (e.g. sqlmap in test mode)",
                      "Identify injection / auth-bypass surface (authorized).", "T1190"),
            ]
            if tls:
                checks.append(Check("TLS posture", f"sslscan {ip}:{port}   # or: python3 ciphers_v4.py scan.xml",
                                    "Enumerate protocols, ciphers and certificate issues.", "T1595"))

            results.append(ModuleResult(
                self.name, self.title, f"{label}:{port}", name,
                f"{scheme.upper()} service ({prod}).", worst(ff),
                techniques=self.techs(checks),
                attack_surface=surface, checks=[c.to_dict() for c in checks], findings=ff))
        return results
