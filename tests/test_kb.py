"""Knowledge-base integrity (validate_kb) must stay clean."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from validate_kb import validate  # noqa: E402


def test_kb_validates_clean():
    kb, errors, warnings = validate()
    assert not errors, "KB validation errors: " + "; ".join(errors)


def test_kb_has_expected_breadth():
    kb, _, _ = validate()
    assert len(kb.modules) >= 28
    assert len(kb.registry) >= 100      # ~103 routed service fragments
