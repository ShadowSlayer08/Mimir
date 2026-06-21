#!/usr/bin/env python3
"""
check_ciphers_mega.py  —  TLS cipher-suite & certificate security analyzer.

Authorized / lab / CTF use.

What it does
------------
 * Parses cipher names from many sources:
     - raw cipher list (one per line)
     - nmap normal output (.txt / .nmap) and nmap XML (-oX)
     - sslscan / testssl plain text
     - Nessus .nessus XML
     - Qualys CSV (heuristic)
     - inline cipher names passed as CLI args
 * Rates every cipher against multiple authorities, in parallel:
     - ciphersuite.info API   (live)
     - Mozilla SSL config profiles (modern / intermediate / old)
     - NIST SP 800-52r2
     - BSI TR-02102-2
     - local heuristics
 * NEW: maps each cipher to concrete, named vulnerabilities + CVEs
        (SWEET32, RC4/Bar-Mitzvah, BEAST, Lucky13, POODLE, FREAK, Logjam,
         ROBOT, NULL, anon-MITM, ...) and uses them to floor the verdict.
 * NEW: optional X.509 certificate analysis (--cert host[:port] / --cert-file).
 * Output modes: A=table, B=verbose, C=minimal. Exports CSV and JSON.

The JSON schema is consumed by the Streamlit GUI (ciphers_gui_v3.py).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import re
import socket
import ssl
import sys
import threading
import xml.etree.ElementTree as ET
from collections import OrderedDict
from datetime import datetime, timezone

__version__ = "3.0"

# Force UTF-8 stdio before colorama wraps the stream, so non-ASCII output never
# raises UnicodeEncodeError on a legacy Windows code page (cp1252).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:                                              # pragma: no cover
        pass

# --------------------------------------------------------------------------- #
# Optional dependencies (degrade gracefully)
# --------------------------------------------------------------------------- #
try:
    import requests
except Exception:  # pragma: no cover
    requests = None

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
except Exception:  # pragma: no cover
    class _NoColor:
        def __getattr__(self, name):
            return ""

    Fore = Style = _NoColor()

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
BASE_URL = "https://ciphersuite.info/api/cs"
API_TIMEOUT = 10
DEFAULT_WORKERS = 10

CIPHER_RX = re.compile(r"TLS_[A-Z0-9_]+", re.IGNORECASE)

ALL_SOURCES = ("ciphersuite", "mozilla", "nist", "bsi", "heuristic")

# Aggregated severity ordering (worst first) used for sorting / flooring.
LEVEL_ORDER = {"insecure": 0, "weak": 1, "unknown": 2, "secure": 3, "recommended": 4}


# --------------------------------------------------------------------------- #
# Cipher-suite VULNERABILITY knowledge base
# --------------------------------------------------------------------------- #
# Each detector returns zero or more vulnerability records:
#   {id, name, cve:[...], severity, description}
# Severity floors the aggregated verdict:  critical/high -> insecure,
# medium/low -> at least weak.
SEVERITY_FLOOR = {
    "critical": "insecure",
    "high": "insecure",
    "medium": "weak",
    "low": "weak",
}


def _v(vid, name, cve, severity, description):
    return {"id": vid, "name": name, "cve": list(cve), "severity": severity,
            "description": description}


def cipher_vulnerabilities(cipher_name: str, tls_versions=None) -> list:
    """Map a cipher (IANA name + optional negotiated TLS versions) to known
    attacks/CVEs. Returns a list of vulnerability records, worst-first."""
    cn = cipher_name.upper()
    versions = {str(v).upper().replace(" ", "") for v in (tls_versions or [])}
    has_ssl3 = any(v in ("SSL3.0", "SSLV3", "SSL3") for v in versions)
    has_tls10 = any(v in ("TLS1.0", "TLSV1.0", "TLS1") for v in versions)

    vulns = []

    # No encryption at all.
    if "NULL" in cn:
        vulns.append(_v(
            "null", "NULL cipher (no encryption)", [], "critical",
            "Traffic is sent in cleartext; provides no confidentiality."))

    # Anonymous key exchange -> no server authentication -> trivial MITM.
    if "ANON" in cn:
        vulns.append(_v(
            "anon", "Anonymous key exchange (no authentication)", [], "critical",
            "No certificate/identity is verified, enabling man-in-the-middle attacks."))

    # Export-grade crypto.
    if "EXPORT" in cn or re.search(r"_EXP(?:ORT)?(?:1024)?(?:_|$)", cn):
        vulns.append(_v(
            "freak", "Export-grade RSA (FREAK)", ["CVE-2015-0204"], "high",
            "Deliberately weakened 512-bit export RSA can be factored to break the session."))
        if "DH" in cn:
            vulns.append(_v(
                "logjam", "Export-grade Diffie-Hellman (Logjam)", ["CVE-2015-4000"], "high",
                "512-bit export DH groups can be broken, allowing decryption/MITM."))

    # RC4 keystream biases.
    if "RC4" in cn:
        vulns.append(_v(
            "rc4", "RC4 stream cipher (Bar Mitzvah / NOMORE)",
            ["CVE-2015-2808", "CVE-2013-2566"], "high",
            "RC4 keystream biases allow plaintext recovery; prohibited by RFC 7465."))

    if "RC2" in cn:
        vulns.append(_v(
            "rc2", "RC2 cipher (obsolete)", [], "medium",
            "40/64-bit RC2 is cryptographically obsolete and brute-forceable."))

    # 64-bit block ciphers (3DES / DES) -> SWEET32 birthday attack.
    if "3DES" in cn or "DES_EDE" in cn:
        vulns.append(_v(
            "sweet32", "3DES 64-bit block cipher (SWEET32)", ["CVE-2016-2183"], "medium",
            "64-bit block size permits birthday-bound collision attacks on long sessions."))
    elif re.search(r"(?:^|_)DES(?:_|$)", cn) and "3DES" not in cn:
        vulns.append(_v(
            "des", "Single DES (56-bit key)", [], "high",
            "56-bit effective key is brute-forceable with modest resources."))

    if "IDEA" in cn:
        vulns.append(_v(
            "idea", "IDEA cipher (deprecated)", [], "low",
            "Removed from TLS 1.2+; no longer recommended."))
    if "SEED" in cn:
        vulns.append(_v(
            "seed", "SEED cipher (deprecated)", [], "low",
            "Legacy regional cipher, deprecated in modern TLS."))

    # MD5 MAC / PRF.
    if "MD5" in cn:
        vulns.append(_v(
            "md5", "MD5-based MAC (broken hash)", [], "medium",
            "MD5 is collision-broken and unfit for integrity protection."))

    # CBC mode (MAC-then-encrypt) family.
    if "CBC" in cn:
        vulns.append(_v(
            "lucky13", "CBC mode padding-oracle timing (Lucky13)", ["CVE-2013-0169"],
            "medium",
            "MAC-then-encrypt CBC is vulnerable to padding-oracle timing side channels."))
        if has_ssl3:
            vulns.append(_v(
                "poodle", "CBC over SSLv3 (POODLE)", ["CVE-2014-3566"], "high",
                "SSLv3 CBC padding can be exploited to decrypt traffic byte-by-byte."))
        if has_tls10:
            vulns.append(_v(
                "beast", "CBC over TLS 1.0 (BEAST)", ["CVE-2011-3389"], "medium",
                "Predictable IVs in TLS 1.0 CBC enable chosen-plaintext recovery."))

    # SHA-1 MAC/PRF (trailing _SHA, not SHA256/384/512).
    if re.search(r"_SHA(?![0-9])", cn):
        vulns.append(_v(
            "sha1", "SHA-1 based MAC/PRF (deprecated)", ["CVE-2015-7575"], "low",
            "SHA-1 is deprecated for integrity/signatures (SLOTH); migrate to SHA-2."))

    # Static RSA key exchange -> no forward secrecy + Bleichenbacher/ROBOT.
    if cn.startswith("TLS_RSA_WITH") or cn.startswith("TLS_RSA_EXPORT"):
        vulns.append(_v(
            "no_pfs", "Static RSA key exchange (no forward secrecy)", [], "low",
            "Session keys are not ephemeral; one stolen private key decrypts past traffic."))
        vulns.append(_v(
            "robot", "RSA PKCS#1 v1.5 key exchange (ROBOT / Bleichenbacher)",
            ["CVE-2017-13099"], "medium",
            "RSA encryption key exchange is exposed to Bleichenbacher padding oracles."))

    vulns.sort(key=lambda x: ({"critical": 0, "high": 1, "medium": 2, "low": 3}
                              .get(x["severity"], 4), x["id"]))
    return vulns


def vulns_floor_level(level: str, vulns: list) -> str:
    """Downgrade `level` so it is never better than the worst vulnerability."""
    cur = LEVEL_ORDER.get(level, 2)
    for v in vulns:
        floor = SEVERITY_FLOOR.get(v["severity"])
        if floor and LEVEL_ORDER[floor] < cur:
            cur = LEVEL_ORDER[floor]
    inv = {n: k for k, n in LEVEL_ORDER.items()}
    return inv[cur]


# --------------------------------------------------------------------------- #
# Local heuristics (fallback when API has no rating)
# --------------------------------------------------------------------------- #
INSECURE_KEYWORDS = ["RC4", "RC2", "DES", "3DES", "NULL", "ANON", "EXPORT", "IDEA", "SEED"]
WEAK_KEYWORDS = ["MD5", "CBC"]


def heuristic_security_from_name(cipher_name: str) -> str:
    cn = cipher_name.upper()
    for k in INSECURE_KEYWORDS:
        if k in cn:
            return "insecure"
    for k in WEAK_KEYWORDS:
        if k in cn:
            return "weak"
    if re.search(r"_SHA(?![0-9])", cn):
        return "weak"
    if cn.startswith("TLS_RSA_WITH"):
        return "weak"
    if "GCM" in cn or "CHACHA20" in cn or "POLY1305" in cn:
        return "recommended"
    if "ECDHE" in cn or "DHE" in cn:
        return "secure"
    return "unknown"


# --------------------------------------------------------------------------- #
# Authority profiles  (Mozilla, NIST SP 800-52r2, BSI TR-02102-2)
# --------------------------------------------------------------------------- #
MOZILLA_MODERN = frozenset({
    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
})
MOZILLA_INTERMEDIATE = MOZILLA_MODERN | frozenset({
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
})
MOZILLA_OLD = MOZILLA_INTERMEDIATE | frozenset({
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
})


def check_mozilla(cipher_name: str) -> str:
    cn = cipher_name.upper()
    if cn in MOZILLA_MODERN:
        return "modern"
    if cn in MOZILLA_INTERMEDIATE:
        return "intermediate"
    if cn in MOZILLA_OLD:
        return "old"
    return "not_listed"


NIST_APPROVED = frozenset({
    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_AES_128_CCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    "TLS_DHE_RSA_WITH_AES_128_CCM", "TLS_DHE_RSA_WITH_AES_256_CCM",
    "TLS_RSA_WITH_AES_128_CCM", "TLS_RSA_WITH_AES_256_CCM",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA",
})


def check_nist(cipher_name: str) -> str:
    return "approved" if cipher_name.upper() in NIST_APPROVED else "not_approved"


BSI_APPROVED = frozenset({
    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
})


def check_bsi(cipher_name: str) -> str:
    return "approved" if cipher_name.upper() in BSI_APPROVED else "not_approved"


def aggregate_security(ratings: dict) -> str:
    """Collapse per-source ratings into one verdict (worst negative wins,
    else best positive)."""
    mapping = {
        "insecure": "insecure", "weak": "weak", "old": "weak",
        "not_listed": "unknown", "not_approved": "unknown", "not_found": "unknown",
        "error": "unknown", "unknown": "unknown",
        "approved": "secure", "intermediate": "secure", "secure": "secure",
        "modern": "recommended", "recommended": "recommended",
    }
    canonical = [mapping.get(v, "unknown") for v in ratings.values()]
    for lvl in ("insecure", "weak"):
        if lvl in canonical:
            return lvl
    for lvl in ("recommended", "secure"):
        if lvl in canonical:
            return lvl
    return "unknown"


# --------------------------------------------------------------------------- #
# Input parsers
# --------------------------------------------------------------------------- #
def _scan_lines_for_ciphers(path):
    found = set()
    with open(path, "r", errors="ignore") as f:
        for ln in f:
            for m in CIPHER_RX.findall(ln):
                found.add(m.upper())
    return sorted(found)


def parse_raw_list_file(path):
    ciphers = []
    with open(path, "r", errors="ignore") as f:
        for ln in f:
            s = ln.strip()
            if not s:
                continue
            m = CIPHER_RX.search(s)
            ciphers.append(m.group(0) if m else s)
    return list(OrderedDict.fromkeys(c.strip() for c in ciphers if c.strip()))


def parse_nmap_xml(path):
    ciphers = set()
    try:
        root = ET.parse(path).getroot()
        for script in root.iter("script"):
            if "ssl-enum-ciphers" in script.get("id", ""):
                text = "".join(script.itertext())
                for m in CIPHER_RX.findall(text):
                    ciphers.add(m.upper())
    except Exception:
        pass
    return sorted(ciphers)


def parse_nessus_nessus(path):
    ciphers = set()
    try:
        root = ET.parse(path).getroot()
        for po in root.iter("plugin_output"):
            for m in CIPHER_RX.findall(po.text or ""):
                ciphers.add(m.upper())
    except Exception:
        pass
    if not ciphers:
        ciphers.update(_scan_lines_for_ciphers(path))
    return sorted(ciphers)


def detect_and_parse_input(first_arg, rest_args):
    """Identify input type and dispatch to the right parser. Returns unique
    uppercase cipher names."""
    if os.path.isfile(first_arg):
        ext = first_arg.lower().rsplit(".", 1)[-1] if "." in first_arg else ""
        if ext == "xml":
            return parse_nmap_xml(first_arg) or parse_nessus_nessus(first_arg)
        if ext == "nessus":
            return parse_nessus_nessus(first_arg)
        if ext in ("txt", "nmap", "out", "log", "csv"):
            found = _scan_lines_for_ciphers(first_arg)
            return found or parse_raw_list_file(first_arg)
        return parse_raw_list_file(first_arg)

    ciphers = []
    for token in [first_arg] + list(rest_args):
        for line in token.splitlines():
            line = line.strip()
            if not line:
                continue
            m = CIPHER_RX.search(line)
            ciphers.append((m.group(0) if m else line).upper())
    return list(OrderedDict.fromkeys(ciphers))


# --------------------------------------------------------------------------- #
# API query (parallel, cached)
# --------------------------------------------------------------------------- #
_cache_lock = threading.Lock()
_api_cache = {}


def _unwrap_ciphersuite_payload(data, cipher_key):
    """ciphersuite.info returns {"TLS_...": {...details...}}.  Unwrap to the
    inner details dict regardless of exact envelope shape."""
    if isinstance(data, list) and data:
        data = data[0]
    if isinstance(data, dict):
        if cipher_key in data and isinstance(data[cipher_key], dict):
            return data[cipher_key]
        # single-key envelope with a different-cased key
        if len(data) == 1:
            only = next(iter(data.values()))
            if isinstance(only, dict):
                return only
        return data  # already flat
    return {}


def query_api(cipher_name, sources=None):
    if sources is None:
        sources = ALL_SOURCES
    sources = set(sources)

    cipher_key = cipher_name.upper()
    cache_key = cipher_key + "|" + ",".join(sorted(sources))
    with _cache_lock:
        if cache_key in _api_cache:
            return _api_cache[cache_key]

    ret = {
        "cipher": cipher_key, "status": "ok", "security_level": "unknown",
        "details": None, "source_ratings": {}, "tls_version": None,
        "openssl_name": None, "gnutls_name": None, "vulnerabilities": [],
        "cves": [], "reason": "",
    }
    tls_versions = None

    # 1. ciphersuite.info -----------------------------------------------------
    if "ciphersuite" in sources:
        if requests is None:
            ret["source_ratings"]["ciphersuite"] = "error"
            ret["error_detail"] = "requests not installed"
        else:
            try:
                r = requests.get(f"{BASE_URL}/{cipher_key}", timeout=API_TIMEOUT)
                if r.status_code == 404:
                    ret["source_ratings"]["ciphersuite"] = "not_found"
                else:
                    details = _unwrap_ciphersuite_payload(r.json(), cipher_key)
                    ret["details"] = details
                    sec = details.get("security") if isinstance(details, dict) else None
                    ret["source_ratings"]["ciphersuite"] = (
                        sec.lower() if isinstance(sec, str) and sec
                        else heuristic_security_from_name(cipher_key))
                    tls_versions = details.get("tls_version")
                    ret["tls_version"] = (", ".join(tls_versions)
                                          if isinstance(tls_versions, list) else tls_versions)
                    ret["openssl_name"] = details.get("openssl_name")
                    ret["gnutls_name"] = details.get("gnutls_name")
            except Exception as e:
                ret["source_ratings"]["ciphersuite"] = "error"
                ret["error_detail"] = str(e)

    # 2-5. offline authorities ------------------------------------------------
    if "mozilla" in sources:
        ret["source_ratings"]["mozilla"] = check_mozilla(cipher_key)
    if "nist" in sources:
        ret["source_ratings"]["nist"] = check_nist(cipher_key)
    if "bsi" in sources:
        ret["source_ratings"]["bsi"] = check_bsi(cipher_key)
    if "heuristic" in sources:
        ret["source_ratings"]["heuristic"] = heuristic_security_from_name(cipher_key)

    # Vulnerability mapping ---------------------------------------------------
    vulns = cipher_vulnerabilities(cipher_key, tls_versions)
    ret["vulnerabilities"] = vulns
    ret["cves"] = sorted({c for v in vulns for c in v["cve"]})

    # Aggregate + floor by vulnerabilities ------------------------------------
    level = aggregate_security(ret["source_ratings"])
    ret["security_level"] = vulns_floor_level(level, vulns)
    ret["reason"] = ("; ".join(v["name"] for v in vulns) if vulns
                     else {"recommended": "Modern AEAD, no known weaknesses",
                           "secure": "Forward secrecy, acceptable",
                           "unknown": "No authoritative rating available"}
                     .get(ret["security_level"], ""))

    with _cache_lock:
        _api_cache[cache_key] = ret
    return ret


# --------------------------------------------------------------------------- #
# Certificate analysis
# --------------------------------------------------------------------------- #
def _cert_validity(cert):
    for attr in ("not_valid_before_utc", "not_valid_before"):
        if hasattr(cert, attr):
            nb = getattr(cert, attr)
            break
    for attr in ("not_valid_after_utc", "not_valid_after"):
        if hasattr(cert, attr):
            na = getattr(cert, attr)
            break
    if nb.tzinfo is None:
        nb = nb.replace(tzinfo=timezone.utc)
    if na.tzinfo is None:
        na = na.replace(tzinfo=timezone.utc)
    return nb, na


def _key_info(cert):
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA", pk.key_size
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return "EC", pk.curve.name
    if isinstance(pk, dsa.DSAPublicKey):
        return "DSA", pk.key_size
    return type(pk).__name__, "-"


def analyze_certificate(der_bytes, source):
    if not _HAVE_CRYPTO:
        return {"source": source, "error": "cryptography not installed"}
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception:
        try:
            cert = x509.load_pem_x509_certificate(der_bytes)
        except Exception as e:
            return {"source": source, "error": f"cannot parse certificate: {e}"}

    nb, na = _cert_validity(cert)
    now = datetime.now(timezone.utc)
    days_remaining = (na - now).days
    key_type, key_size = _key_info(cert)
    sig_alg = (cert.signature_algorithm_oid._name
               if cert.signature_algorithm_oid else "unknown")
    self_signed = cert.subject == cert.issuer

    issues = []
    if now > na:
        issues.append("Certificate is EXPIRED")
    elif days_remaining < 30:
        issues.append(f"Certificate expires soon ({days_remaining} days)")
    if now < nb:
        issues.append("Certificate is not yet valid")
    if key_type == "RSA" and isinstance(key_size, int) and key_size < 2048:
        issues.append(f"Weak RSA key ({key_size}-bit, <2048)")
    if any(w in sig_alg.lower() for w in ("md5", "sha1")):
        issues.append(f"Weak signature algorithm ({sig_alg})")
    if self_signed:
        issues.append("Self-signed certificate")

    return {
        "source": source,
        "summary": {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": nb.isoformat(),
            "not_after": na.isoformat(),
            "days_remaining": days_remaining,
            "key_type": key_type, "key_size": key_size,
            "signature_algorithm": sig_alg,
        },
        "self_signed": self_signed,
        "issues": issues,
    }


def fetch_and_analyze_host_cert(spec, timeout=10):
    host, _, port = spec.partition(":")
    port = int(port) if port else 443
    src = f"{host}:{port}"

    # Untrusted fetch (still works on self-signed / bad chains).
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except Exception as e:
        return {"source": src, "error": f"connection failed: {e}"}

    result = analyze_certificate(der, src)

    # Separate verifying handshake to report chain trust.
    try:
        vctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host):
                pass
        result["chain_trust"] = "trusted"
        result["chain_trust_error"] = None
    except ssl.SSLCertVerificationError as e:
        result["chain_trust"] = "untrusted"
        result["chain_trust_error"] = str(e.verify_message or e)
    except Exception as e:
        result["chain_trust"] = "unknown"
        result["chain_trust_error"] = str(e)
    return result


def analyze_cert_file(path):
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except Exception as e:
        return {"source": path, "error": f"cannot read file: {e}"}
    res = analyze_certificate(data, os.path.basename(path))
    res.setdefault("chain_trust", "not_checked")
    res.setdefault("chain_trust_error", None)
    return res


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #
def _source_badge(rating):
    badges = {
        "insecure": Fore.RED + "✗" + Style.RESET_ALL,
        "weak": Fore.RED + "~" + Style.RESET_ALL,
        "not_listed": Fore.RED + "✗" + Style.RESET_ALL,
        "not_approved": Fore.RED + "✗" + Style.RESET_ALL,
        "old": Fore.YELLOW + "~" + Style.RESET_ALL,
        "approved": Fore.GREEN + "✔" + Style.RESET_ALL,
        "intermediate": Fore.GREEN + "≈" + Style.RESET_ALL,
        "modern": Fore.GREEN + "✔" + Style.RESET_ALL,
        "recommended": Fore.GREEN + "✔" + Style.RESET_ALL,
        "secure": Fore.GREEN + "≈" + Style.RESET_ALL,
        "not_found": Fore.YELLOW + "?" + Style.RESET_ALL,
        "error": Fore.YELLOW + "?" + Style.RESET_ALL,
        "unknown": Fore.YELLOW + "?" + Style.RESET_ALL,
    }
    return badges.get(rating, Fore.YELLOW + "?" + Style.RESET_ALL)


def _level_colors(level):
    lvl = level.lower()
    if lvl in ("insecure", "weak"):
        return Fore.RED + "❌" + Style.RESET_ALL, Fore.RED
    if lvl in ("secure", "recommended"):
        return Fore.GREEN + "✔ " + Style.RESET_ALL, Fore.GREEN
    return Fore.YELLOW + "? " + Style.RESET_ALL, Fore.YELLOW


def print_table(results, active_sources):
    src_header = "  ".join(f"{s[:4]:4}" for s in active_sources)
    header = f"{'CIPHER':52}  {'LEVEL':11}  {'CVE':4}  {src_header}"
    print(header)
    print("-" * len(header))
    for r in results:
        marker, col = _level_colors(r["security_level"])
        lvl_col = col + f"{r['security_level'].upper():9}" + Style.RESET_ALL
        cves = r.get("cves") or []
        cve_cell = (Fore.RED + f"{len(cves):>2}!" + Style.RESET_ALL) if cves else "  -"
        src = "  ".join(f"{_source_badge(r['source_ratings'].get(s, '?')):4}"
                        for s in active_sources)
        print(f"{r['cipher']:52}  {marker}{lvl_col}  {cve_cell:4}  {src}")
    _print_vuln_section(results)


def _print_vuln_section(results):
    affected = [r for r in results if r.get("vulnerabilities")]
    if not affected:
        return
    print("\n" + Fore.RED + "VULNERABILITY INSIGHTS" + Style.RESET_ALL)
    print("=" * 60)
    for r in affected:
        print(f"\n{Fore.CYAN}{r['cipher']}{Style.RESET_ALL}  "
              f"[{r['security_level'].upper()}]")
        for v in r["vulnerabilities"]:
            cve = f"  ({', '.join(v['cve'])})" if v["cve"] else ""
            sev = v["severity"].upper()
            sev_col = (Fore.RED if sev in ("CRITICAL", "HIGH") else Fore.YELLOW)
            print(f"  {sev_col}• [{sev}] {v['name']}{cve}{Style.RESET_ALL}")
            print(f"      {v['description']}")


def print_verbose(results, active_sources):
    labels = {
        "ciphersuite": "  ciphersuite.info", "mozilla": "  Mozilla SSL Cfg ",
        "nist": "  NIST SP 800-52r2", "bsi": "  BSI TR-02102-2  ",
        "heuristic": "  Local heuristic ",
    }
    for r in results:
        print("=" * 80)
        print(f"Cipher       : {r['cipher']}")
        print(f"Security     : {r['security_level'].upper()}")
        print(f"Reason       : {r.get('reason') or '-'}")
        print(f"TLS Version  : {r.get('tls_version') or '-'}")
        print(f"OpenSSL name : {r.get('openssl_name') or '-'}")
        if r.get("source_ratings"):
            print("Source ratings:")
            for src in active_sources:
                rating = r["source_ratings"].get(src, "-")
                print(f"{labels.get(src, '  ' + src):18} : "
                      f"{_source_badge(rating)} {rating}")
        if r.get("vulnerabilities"):
            print("Vulnerabilities:")
            for v in r["vulnerabilities"]:
                cve = f" ({', '.join(v['cve'])})" if v["cve"] else ""
                print(f"  - [{v['severity'].upper()}] {v['name']}{cve}")
                print(f"      {v['description']}")
        print()


def print_minimal(results, active_sources):
    for r in results:
        src = ",".join(f"{s}={r['source_ratings'].get(s, '?')}" for s in active_sources)
        cves = "|".join(r.get("cves") or [])
        print(f"{r['cipher']},{r['security_level']},{r.get('status')},{cves},{src}")


def write_csv(results, path, active_sources):
    base = ["cipher", "security_level", "status", "tls_version", "openssl_name",
            "gnutls_name", "reason", "cves"]
    fieldnames = base + [f"src_{s}" for s in active_sources]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for r in results:
            row = {
                "cipher": r.get("cipher"), "security_level": r.get("security_level"),
                "status": r.get("status"), "tls_version": r.get("tls_version") or "",
                "openssl_name": r.get("openssl_name") or "",
                "gnutls_name": r.get("gnutls_name") or "",
                "reason": r.get("reason") or "",
                "cves": "; ".join(r.get("cves") or []),
            }
            for s in active_sources:
                row[f"src_{s}"] = r.get("source_ratings", {}).get(s, "")
            w.writerow(row)
    print(f"\n[+] CSV exported: {path}")


def build_summary(results):
    counts = {k: 0 for k in ("insecure", "weak", "secure", "recommended", "unknown")}
    for r in results:
        lvl = (r.get("security_level") or "unknown").lower()
        counts[lvl if lvl in counts else "unknown"] += 1
    return counts


def write_json(results, certificates, path, active_sources):
    payload = {
        "results": results,
        "certificates": certificates,
        "summary": build_summary(results),
        "active_sources": list(active_sources),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": __version__,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


# --------------------------------------------------------------------------- #
# CLI / main
# --------------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        description="Rate TLS cipher suites against multiple authorities, map "
                    "them to known vulnerabilities/CVEs, and analyze certificates.")
    p.add_argument("input", nargs="+", help="Input file path(s) or inline cipher names.")
    p.add_argument("--mode", choices=["A", "B", "C"], default="A",
                   help="A=Table (default), B=Verbose, C=Minimal")
    p.add_argument("--csv", help="Export results to CSV file")
    p.add_argument("--json", dest="json_out", help="Export full results to JSON file")
    p.add_argument("--cert", help="Fetch & analyze certificate from host[:port]")
    p.add_argument("--cert-file", help="Analyze a certificate file (PEM/DER)")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    p.add_argument("--quiet", action="store_true", help="Force minimal console output")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--sources", default=",".join(ALL_SOURCES),
                   help=f"Comma list. Available: {', '.join(ALL_SOURCES)}. Default: all.")
    p.add_argument("--use-async", action="store_true",
                   help="Accepted for compatibility (no-op).")
    p.add_argument("--version", action="version", version=f"check_ciphers_mega {__version__}")
    args = p.parse_args()

    if args.no_color:
        global Fore, Style
        class _NC:
            def __getattr__(self, n):
                return ""
        Fore = Style = _NC()

    requested = [s.strip().lower() for s in args.sources.split(",") if s.strip()]
    invalid = [s for s in requested if s not in ALL_SOURCES]
    if invalid:
        print(f"Unknown source(s): {', '.join(invalid)}. Valid: {', '.join(ALL_SOURCES)}")
        sys.exit(1)
    active_sources = [s for s in ALL_SOURCES if s in requested]

    quiet = args.quiet or bool(args.json_out and args.mode == "A" and not sys.stdout.isatty())
    if not args.json_out or args.mode != "A":
        print(f"[+] Active sources : {', '.join(active_sources)}")

    ciphers = detect_and_parse_input(args.input[0], args.input[1:])
    ciphers = [c.upper() for c in OrderedDict.fromkeys(ciphers)]
    if not ciphers:
        print("No ciphers found in input.")
        sys.exit(1)
    if not args.json_out:
        print(f"[+] Ciphers to check: {len(ciphers)}")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(query_api, c, active_sources): c for c in ciphers}
        for fut in concurrent.futures.as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"cipher": futs[fut], "status": "error",
                                "security_level": "unknown", "source_ratings": {},
                                "vulnerabilities": [], "cves": [], "error_detail": str(e)})

    results.sort(key=lambda r: (LEVEL_ORDER.get((r.get("security_level") or "unknown").lower(), 2),
                                r["cipher"]))

    # Certificate analysis
    certificates = []
    if args.cert:
        certificates.append(fetch_and_analyze_host_cert(args.cert))
    if args.cert_file:
        certificates.append(analyze_cert_file(args.cert_file))

    if args.json_out:
        write_json(results, certificates, args.json_out, active_sources)
        # Stay quiet on stdout when producing JSON for the GUI.
        if not quiet:
            print(f"[+] JSON exported: {args.json_out}")

    out_mode = "C" if args.quiet else args.mode
    if not args.json_out or sys.stdout.isatty():
        if out_mode == "A":
            print_table(results, active_sources)
        elif out_mode == "B":
            print_verbose(results, active_sources)
        else:
            print_minimal(results, active_sources)

    if args.csv:
        write_csv(results, args.csv, active_sources)

    if not args.json_out:
        counts = build_summary(results)
        total_cves = len({c for r in results for c in (r.get("cves") or [])})
        print("\nSummary:")
        for k in ("insecure", "weak", "secure", "recommended", "unknown"):
            print(f"  {k.capitalize():11}: {counts[k]}")
        print(f"  Unique CVEs: {total_cves}")
        print(f"\nChecked at: {datetime.now(timezone.utc).isoformat()}")


if __name__ == "__main__":
    main()
