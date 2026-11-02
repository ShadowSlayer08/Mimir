"""HelloModule — unit test using Mimir's shipped TestHarness.

Demonstrates:
  * typed `ModuleParams` get populated from a target dict
  * the module stages the expected check when inside scope
  * out-of-scope targets are refused by the harness (same contract as roe.py)
"""
import os
import sys

# Both the plugin package and Mimir's sdk/ are importable from a Mimir checkout.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN = os.path.dirname(_HERE)
_ROOT = os.path.dirname(os.path.dirname(_PLUGIN))
sys.path.insert(0, _PLUGIN)
sys.path.insert(0, _ROOT)

from sdk import TestHarness                                   # noqa: E402
from example_hello import HelloModule, HelloParams            # noqa: E402


def test_params_coerce_from_target():
    """ModuleParams gives you type-coerced params from the raw target dict."""
    p = HelloParams.from_target({"url": "https://acme.example", "timeout": "15"})
    assert p.url == "https://acme.example" and p.timeout == 15


def test_hello_module_in_scope_stages_the_check():
    with TestHarness(scope=["10.0.0.0/24"]) as h:
        results = h.run(
            HelloModule,
            {"kind": "example.hello", "ref": "10.0.0.5", "host": "10.0.0.5",
             "url": "https://10.0.0.5", "timeout": 10},
        )
    assert results and results[0]["module"] == "example.hello"
    assert len(results[0]["checks"]) == 1
    c = results[0]["checks"][0]
    assert c["attack"] == "T1595.002"
    assert c["risk"] == "safe"
    assert "curl" in c["command"]
    assert h.staged_count == 1


def test_hello_module_out_of_scope_is_refused():
    with TestHarness(scope=["10.0.0.0/24"]) as h:
        results = h.run(
            HelloModule,
            {"kind": "example.hello", "ref": "10.99.99.99",
             "host": "10.99.99.99", "url": "https://10.99.99.99"},
        )
    assert results == []
    assert h.out_of_scope == [("10.99.99.99", "not_in_scope")]
