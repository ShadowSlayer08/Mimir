# AppSec Arsenal (WebHackersWeapons)

Reference tool map for the web/AppSec methodology, curated from
**WebHackersWeapons** by hahwul — `https://github.com/hahwul/WebHackersWeapons`
(a community-maintained list of web-hacking tools). This file is **reference
only**: the engine *stages* these tools in the `web_app` (OWASP-WSTG) methodology
for a human operator to run in scope. The engine launches nothing.

Tools are grouped by assessment phase. The `web_app` module's default commands
pick one per row; swap in any listed alternative for your workflow.

| Phase | WSTG / OWASP | Tools (WebHackersWeapons) |
| --- | --- | --- |
| Subdomain / DNS recon | WSTG-INFO-* | subfinder, assetfinder, amass, findomain, puredns, dnsx, alterx |
| Live-host / port triage | WSTG-INFO-02 | httpx, naabu, RustScan, masscan, nmap |
| URL / endpoint gathering | WSTG-INFO-01 | gau, waybackurls, waymore, katana, hakrawler, gospider, cariddi |
| Content discovery | WSTG-INFO-07 | feroxbuster, ffuf, dirsearch, wfuzz, kiterunner |
| Parameter discovery | WSTG-INFO-07 | arjun, paramspider, x8, Parth |
| Fingerprint / tech | WSTG-INFO-02/08/09 | whatweb, httpx, wappalyzer |
| Vulnerability templates | WSTG-INFO-08 | nuclei, jaeles, nikto, wapiti, wpscan, scan4all |
| Secrets in JS / repos | WSTG-INFO-05 | SecretFinder, trufflehog, gitleaks |
| XSS | WSTG-INPV-01 | dalfox, XSStrike, kxss, Gxss |
| SQL injection *(intrusive)* | WSTG-INPV-05 | sqlmap, ghauri, DSSS |
| Command injection *(intrusive)* | WSTG-INPV-12 | commix |
| SSTI | WSTG-INPV-18 | tplmap |
| SSRF / OOB | WSTG-INPV-19 | SSRFmap, interactsh (OAST), ssrf-sheriff |
| CRLF / open redirect | WSTG-CLNT-04 | crlfuzz, oralyzer |
| CORS | WSTG-CLNT-07 | Corsy, CorsMe |
| Auth / credential testing *(intrusive)* | WSTG-ATHN-02 | hydra, medusa, jwt_tool |
| Utility / glue | — | httpx, qsreplace, anew, unfurl, gf, interactsh-client |

**Boundary note.** Tools tagged *(intrusive)* (SQLi, OS-command injection,
credential testing) are hidden in VAPT mode and never auto-executed; the `web_app`
staged commands for them are `#`-prefixed manual steps. Read-only enumeration
(fingerprint, discovery, templates, CORS) can be run via the container runners
(`assess --containers` / `--run-containers`); active-exploitation tools stay
staged for the operator. See `docs/instructions.md` (the constitution).
