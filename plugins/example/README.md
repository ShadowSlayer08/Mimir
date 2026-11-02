# example — a minimal Mimir plugin

A **copy-this-and-rename** starter for third-party module authors. It implements
one `BaseModule` subclass, registers it under the `mimir.modules` entry-point
group, declares typed parameters via `ModuleParams`, and ships a unit test that
uses the shipped `TestHarness` for isolated verification.

## What it does

Takes a URL target and stages one methodology check — "fingerprint the server
via `curl`". No weaponization, no exploit code — the engine does not run it;
the operator runs the staged command in their authorized scope. This is the
contract every third-party module honours.

## Layout

```
plugins/example/
  README.md
  pyproject.toml           # declares entry point: mimir.modules.example_hello
  example_hello/__init__.py   # the module class
  tests/test_example.py    # TestHarness-based unit test
```

## Install (dev)

```
cd plugins/example
pip install -e .
```

Then run Mimir with your plugin visible:

```
mimir-cli --from-xml tests/fixtures/full_scan.xml --yes \
          --ai-target example.hello://acme.example       # kind matches the plugin
```

(Or any arg path that produces an app target of this plugin's kind.)

## Reading list

- `sdk/__init__.py` — public API surface
- `sdk/base.py` — `BaseModule`, `ModuleParams`, `module_result`, `discover()`
- `sdk/testharness.py` — mock scope + synthetic vault for isolated tests
- `docs/instructions.md` — the staging-only constitution. **Read before publishing.**
