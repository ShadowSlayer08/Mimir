"""vault.py — AES-256-GCM encrypted engagement credential vault.

Locks the contracts that matter for a crypto module shipped in a security tool:
  * Round-trip integrity: set -> get returns the exact value.
  * Wrong passphrase -> decryption fails cleanly (never silent corruption).
  * Rekey preserves content; old passphrase stops working.
  * list_keys never exposes values.
  * redact() scrubs likely secrets from log/report prose.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import vault  # noqa: E402

# Guard: skip tests if cryptography isn't installed (shouldn't happen - it's a core dep).
pytestmark = []
if not getattr(vault, "_CRYPTO_OK", False):                        # pragma: no cover
    def test_crypto_backend_available():
        assert False, "cryptography missing from env"
else:
    def _tmp():
        fd, p = tempfile.mkstemp(suffix=".json", prefix="vault-test-")
        os.close(fd)
        os.unlink(p)                                               # vault creates fresh
        return p


    def test_init_and_roundtrip():
        p = _tmp()
        try:
            vault.init_vault("correct-horse-battery-staple", p)
            vault.set_item("test-tenant-pw", "s3cr3t!", "correct-horse-battery-staple", p)
            vault.set_item("ntlm-hash", "aad3b435:...:...", "correct-horse-battery-staple", p)
            assert sorted(vault.list_keys("correct-horse-battery-staple", p)) == \
                ["ntlm-hash", "test-tenant-pw"]
            assert vault.get_item("test-tenant-pw",
                                  "correct-horse-battery-staple", p) == "s3cr3t!"
        finally:
            os.path.exists(p) and os.unlink(p)


    def test_wrong_passphrase_fails_cleanly():
        p = _tmp()
        try:
            vault.init_vault("correct-horse-battery-staple", p)
            vault.set_item("k", "v", "correct-horse-battery-staple", p)
            raised = False
            try:
                vault.get_item("k", "wrong passphrase", p)
            except Exception:
                raised = True
            assert raised, "wrong passphrase must raise"
        finally:
            os.path.exists(p) and os.unlink(p)


    def test_rekey_rotates_passphrase():
        p = _tmp()
        try:
            vault.init_vault("old-passphrase-123456", p)
            vault.set_item("k", "v", "old-passphrase-123456", p)
            vault.rekey("old-passphrase-123456", "new-passphrase-abcdef", p)
            assert vault.get_item("k", "new-passphrase-abcdef", p) == "v"
            # Old passphrase stops working.
            raised = False
            try:
                vault.get_item("k", "old-passphrase-123456", p)
            except Exception:
                raised = True
            assert raised
        finally:
            os.path.exists(p) and os.unlink(p)


    def test_delete_item():
        p = _tmp()
        try:
            vault.init_vault("passphrase-twelve-chars", p)
            vault.set_item("a", "1", "passphrase-twelve-chars", p)
            vault.set_item("b", "2", "passphrase-twelve-chars", p)
            vault.delete_item("a", "passphrase-twelve-chars", p)
            assert vault.list_keys("passphrase-twelve-chars", p) == ["b"]
        finally:
            os.path.exists(p) and os.unlink(p)


    def test_status_without_vault():
        p = _tmp()
        s = vault.status(p)
        assert s["present"] is False and s["path"] == p


    def test_redact_scrubs_common_secret_shapes():
        s = ("auth header: Authorization=Bearer sk-abc123def456ghi789jkl, "
             "ntlm: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0, "
             "password=hunter2 "
             "github: ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8")
        out = vault.redact(s)
        assert "sk-abc123def456ghi789jkl" not in out
        assert "aad3b435b51404eeaad3b435b51404ee" not in out
        assert "hunter2" not in out
        assert "ghp_" not in out


    def test_is_secret_keyname_classifies():
        for name in ("pass", "password", "api_key", "ntlm_hash", "aws_secret", "kerb_ticket"):
            assert vault.is_secret_keyname(name), name
        for name in ("domain", "hostname", "target", "label"):
            assert not vault.is_secret_keyname(name), name
