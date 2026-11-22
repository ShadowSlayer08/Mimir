"""parsers.base — ParseResult shape every parser returns."""
from __future__ import annotations


class ParseResult:
    """Structured intel extracted from one tool's output.

    Attributes:
      new_hosts:        ["10.0.0.5", "web.corp.lab", ...]
      new_services:     [{"host": "10.0.0.5", "port": 22, "proto": "tcp",
                          "service": "ssh", "version": "OpenSSH 8.9"}, ...]
      new_findings:     Mimir finding dicts (schema-aligned where possible —
                        host / port / severity / category / title / cve).
      new_credentials:  [{"host", "service", "user", "source"}] — NEVER passwords
                        (constitution: creds flow through vault.py only).
      notes:            freeform operator-visible one-liners.

    Parsers may populate any subset. The loop merges every list into the
    engagement JSON, dedup'd by its natural key.
    """

    __slots__ = ("new_hosts", "new_services", "new_findings",
                 "new_credentials", "new_urls", "new_subdomains",
                 "notes", "source_tool")

    def __init__(self, source_tool=""):
        self.new_hosts = []
        self.new_services = []
        self.new_findings = []
        self.new_credentials = []
        # Phase 26: AppSec surface — URLs/subdomains discovered by web_recon,
        # subfinder, httpx, feroxbuster, katana, gau, etc. The autopilot v2
        # loop re-dispatches `dispatch_apps` on these to grow the plan for
        # web/API targets the same way `new_services` grows it for ports.
        self.new_urls = []        # [{"url": "https://host/path", "status": 200,
                                  #   "tech": "...", "title": "..."}]
        self.new_subdomains = []  # ["sub.example.com", ...]
        self.notes = []
        self.source_tool = source_tool

    def is_empty(self):
        return not (self.new_hosts or self.new_services or
                    self.new_findings or self.new_credentials or
                    self.new_urls or self.new_subdomains or self.notes)

    def total_items(self):
        return (len(self.new_hosts) + len(self.new_services) +
                len(self.new_findings) + len(self.new_credentials) +
                len(self.new_urls) + len(self.new_subdomains))

    def to_dict(self):
        return {
            "source_tool": self.source_tool,
            "new_hosts": list(self.new_hosts),
            "new_services": list(self.new_services),
            "new_findings": list(self.new_findings),
            "new_credentials": list(self.new_credentials),
            "new_urls": list(self.new_urls),
            "new_subdomains": list(self.new_subdomains),
            "notes": list(self.notes),
        }

    def __repr__(self):
        return (f"ParseResult(tool={self.source_tool!r} "
                f"hosts={len(self.new_hosts)} svc={len(self.new_services)} "
                f"find={len(self.new_findings)} cred={len(self.new_credentials)} "
                f"urls={len(self.new_urls)} subs={len(self.new_subdomains)})")
