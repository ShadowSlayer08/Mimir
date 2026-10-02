#!/usr/bin/env python3
"""
vault.py — AES-256-GCM encrypted credential vault for an engagement.

Authorized / lab / CTF / VAPT / red-team use only.

Pattern adopted from ARES (Mafifrizi/ARES, MIT) and adapted for Vantage's
staging-only boundary. A small, local-only, password-sealed JSON file that
holds credentials the operator harvests DURING an engagement — hashes,
tickets, API keys, test-tenant creds — so they aren't scattered across tmux
panes, bash history, or clipboard.

Design contract:
  * AES-256-GCM authenticated encryption (confidentiality + integrity).
  * Key derivation: PBKDF2-HMAC-SHA256, 600 000 iterations (OWASP 2024+).
  * Per-vault random 16-byte salt; per-write random 12-byte nonce.
  * The vault file is a single JSON blob: {version, kdf, salt, nonce, ct}.
  * Values are redacted in every log line (callers that go through this API
    get a `redact()` helper for the structlog / print path).
  * The vault NEVER auto-fills secrets into staged commands — the context.py
    placeholder rule still holds (`<pass>`/`<key>`/... stay unfilled).
    Operators retrieve values by key, in a human-visible step, deliberately.
  * File permissions set to owner-read on *nix; on Windows the file inherits
    the user's ACL — stays in the per-user data dir by default.

CLI:
    python vault.py init                       # create a new vault, prompts for passphrase
    python vault.py set <key>                  # stores stdin as the value (hidden input)
    python vault.py get <key>                  # prints decrypted value to stdout
    python vault.py list                       # prints keys only (never values)
    python vault.py del <key>                  # removes a key
    python vault.py rekey                      # change passphrase
"""
from __future__ import annotations

import base64
import getpass
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone

# Reuse enrich.py's per-OS cache dir discipline; vault stays beside it.
try:
    from enrich import _cache_file as _dir_file
except Exception:                                              # pragma: no cover
    def _dir_file(name):
        base = os.path.join(os.path.expanduser("~"), ".cache", "vantage")
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, name)

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_OK = True
except Exception:                                              # pragma: no cover
    _CRYPTO_OK = False

# --- constants ------------------------------------------------------------- #
_VERSION = 1
_KDF_ITER = 600_000
_SALT_BYTES = 16
_NONCE_BYTES = 12
_DEFAULT_NAME = "vault.json"

# Secret-looking key names that the vault MUST hold but never auto-fill
# into staged commands. The placeholder rule in context.py already blocks these.
_SECRET_KEYNAMES = re.compile(r"(pass|secret|key|token|cred|hash|ticket)", re.I)


# --- helpers --------------------------------------------------------------- #
def _default_path():
    return _dir_file(_DEFAULT_NAME)


def _b64e(b):
    return base64.b64encode(b).decode("ascii")


def _b64d(s):
    return base64.b64decode(s.encode("ascii"))


def _derive(passphrase, salt):
    if not _CRYPTO_OK:
        raise RuntimeError("cryptography package required: pip install cryptography")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=_KDF_ITER)
    return kdf.derive(passphrase.encode("utf-8"))


def _tighten_perms(path):
    """Owner-read-only on *nix; no-op elsewhere."""
    try:
        if os.name == "posix":
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:                                            # pragma: no cover
        pass


# --- low-level primitives (public but called by main() below) ------------- #
def _load_envelope(path):
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    if d.get("version") != _VERSION or "salt" not in d or "nonce" not in d or "ct" not in d:
        raise ValueError("not a Vantage vault file")
    return d


def _decrypt(envelope, passphrase):
    key = _derive(passphrase, _b64d(envelope["salt"]))
    aes = AESGCM(key)
    pt = aes.decrypt(_b64d(envelope["nonce"]), _b64d(envelope["ct"]),
                     associated_data=b"vantage.vault.v1")
    return json.loads(pt.decode("utf-8"))


def _encrypt(items, passphrase, salt=None):
    salt = salt or os.urandom(_SALT_BYTES)
    nonce = os.urandom(_NONCE_BYTES)
    key = _derive(passphrase, salt)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, json.dumps(items).encode("utf-8"),
                     associated_data=b"vantage.vault.v1")
    return {"version": _VERSION, "kdf": {"name": "PBKDF2-HMAC-SHA256",
                                         "iterations": _KDF_ITER},
            "salt": _b64e(salt), "nonce": _b64e(nonce), "ct": _b64e(ct),
            "updated": datetime.now(timezone.utc).isoformat(timespec="seconds")}


# --- public API ------------------------------------------------------------ #
def init_vault(passphrase, path=None):
    """Create a new empty vault. Overwrites any existing file at `path`."""
    path = path or _default_path()
    env = _encrypt({"_meta": {"created": datetime.now(timezone.utc).isoformat(timespec="seconds")}},
                   passphrase)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(env, fh)
    _tighten_perms(path)
    return path


def set_item(key, value, passphrase, path=None):
    """Set/overwrite one key -> value pair. Returns the item count after write."""
    path = path or _default_path()
    if os.path.exists(path):
        env = _load_envelope(path)
        items = _decrypt(env, passphrase)
    else:
        items = {}
    items[key] = value
    # Rotate salt + nonce on every write (defense in depth; costs ~0.3s per write).
    new_env = _encrypt(items, passphrase)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(new_env, fh)
    _tighten_perms(path)
    return sum(1 for k in items if not k.startswith("_"))


def get_item(key, passphrase, path=None):
    """Decrypt and return one value. Raises KeyError if missing."""
    path = path or _default_path()
    env = _load_envelope(path)
    items = _decrypt(env, passphrase)
    if key not in items:
        raise KeyError(key)
    return items[key]


def list_keys(passphrase, path=None):
    """Return keys only; never values."""
    path = path or _default_path()
    env = _load_envelope(path)
    items = _decrypt(env, passphrase)
    return sorted(k for k in items if not k.startswith("_"))


def delete_item(key, passphrase, path=None):
    path = path or _default_path()
    env = _load_envelope(path)
    items = _decrypt(env, passphrase)
    items.pop(key, None)
    new_env = _encrypt(items, passphrase)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(new_env, fh)
    _tighten_perms(path)
    return sum(1 for k in items if not k.startswith("_"))


def rekey(old_passphrase, new_passphrase, path=None):
    """Decrypt with old, re-encrypt with new. Rotates salt + nonce."""
    path = path or _default_path()
    env = _load_envelope(path)
    items = _decrypt(env, old_passphrase)
    new_env = _encrypt(items, new_passphrase)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(new_env, fh)
    _tighten_perms(path)
    return path


def redact(text, mask="«redacted»"):
    """Blank obvious secret-looking tokens in log/report output.
    This is a defense-in-depth secondary filter; the primary rule is 'never put
    the plaintext in a logged string in the first place'."""
    if not text:
        return text
    out = text
    # NTLM / NT hashes
    out = re.sub(r"\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b", mask, out)
    out = re.sub(r"\b[A-Fa-f0-9]{32}\b", mask, out)
    # Likely API tokens / long base64
    out = re.sub(r"\b(?:sk|rk|xoxp|xoxb|AIza|AKIA|ASIA|ghp_|gho_|github_pat_)[A-Za-z0-9_\-]{16,}", mask, out)
    # key=value where key looks sensitive
    out = re.sub(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key)"
                 r"\s*[:=]\s*\S+", lambda m: f"{m.group(1)}={mask}", out)
    return out


def is_secret_keyname(key):
    """Does this key name look like it holds a secret?"""
    return bool(_SECRET_KEYNAMES.search(key or ""))


def status(path=None):
    """Non-destructive info: does a vault exist, when was it last touched."""
    path = path or _default_path()
    if not os.path.exists(path):
        return {"path": path, "present": False}
    try:
        env = _load_envelope(path)
        return {"path": path, "present": True,
                "updated": env.get("updated", "?"),
                "kdf": env.get("kdf", {}).get("name", "?"),
                "version": env.get("version", "?")}
    except Exception as e:
        return {"path": path, "present": True, "error": str(e)}


# --- CLI ------------------------------------------------------------------- #
def _prompt(prompt="Passphrase: "):
    return getpass.getpass(prompt)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="vantage-vault",
                                 description="AES-256-GCM encrypted engagement credential vault")
    ap.add_argument("--path", help="override vault file location")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init",   help="create a new vault")
    sub.add_parser("list",   help="list key names (never values)")
    sub.add_parser("status", help="print presence / KDF / last-updated")

    s = sub.add_parser("set", help="store stdin as the value for a key")
    s.add_argument("key")

    g = sub.add_parser("get", help="print one decrypted value to stdout")
    g.add_argument("key")

    d = sub.add_parser("del", help="remove a key")
    d.add_argument("key")

    sub.add_parser("rekey",  help="change the vault passphrase")

    args = ap.parse_args(argv)
    if not _CRYPTO_OK:
        print("[vault] install cryptography: pip install cryptography", file=sys.stderr)
        return 2

    try:
        if args.cmd == "status":
            s = status(args.path)
            for k, v in s.items():
                print(f"  {k:<10} {v}")
            return 0

        if args.cmd == "init":
            p1 = _prompt("New passphrase: ")
            p2 = _prompt("Confirm:        ")
            if p1 != p2 or len(p1) < 12:
                print("[vault] passphrases differ or shorter than 12 chars", file=sys.stderr)
                return 2
            path = init_vault(p1, args.path)
            print(f"[vault] initialised: {path}")
            return 0

        if args.cmd == "list":
            keys = list_keys(_prompt(), args.path)
            for k in keys:
                tag = " *" if is_secret_keyname(k) else ""
                print(f"  {k}{tag}")
            return 0

        if args.cmd == "set":
            # Value from stdin (one line); or interactive hidden if a TTY.
            if sys.stdin.isatty():
                value = _prompt(f"Value for {args.key}: ")
            else:
                value = sys.stdin.readline().rstrip("\n")
            n = set_item(args.key, value, _prompt(), args.path)
            print(f"[vault] stored '{args.key}' ({n} item(s) in vault)")
            return 0

        if args.cmd == "get":
            value = get_item(args.key, _prompt(), args.path)
            # Write to stdout WITHOUT a trailing newline so operators can pipe cleanly.
            sys.stdout.write(value)
            if sys.stdout.isatty():
                sys.stdout.write("\n")
            return 0

        if args.cmd == "del":
            n = delete_item(args.key, _prompt(), args.path)
            print(f"[vault] removed '{args.key}' ({n} item(s) remain)")
            return 0

        if args.cmd == "rekey":
            old = _prompt("Old passphrase: ")
            new1 = _prompt("New passphrase: ")
            new2 = _prompt("Confirm:        ")
            if new1 != new2 or len(new1) < 12:
                print("[vault] passphrases differ or shorter than 12 chars", file=sys.stderr)
                return 2
            rekey(old, new1, args.path)
            print("[vault] rekeyed OK")
            return 0

    except KeyError as e:
        print(f"[vault] no such key: {e}", file=sys.stderr); return 1
    except Exception as e:
        print(f"[vault] error: {e}", file=sys.stderr); return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
