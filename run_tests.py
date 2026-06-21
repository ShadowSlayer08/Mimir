#!/usr/bin/env python3
"""
run_tests.py — run the whole test suite without requiring pytest.

Discovers tests/test_*.py, imports each, and calls every top-level `test_*`
callable (no fixtures), reporting pass/fail. `pytest` also works if installed.

    python run_tests.py
"""
from __future__ import annotations

import glob
import importlib.util
import os
import sys
import traceback

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)


def _load(path):
    spec = importlib.util.spec_from_file_location(
        "t_" + os.path.splitext(os.path.basename(path))[0], path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    passed = failed = 0
    for path in sorted(glob.glob(os.path.join(ROOT, "tests", "test_*.py"))):
        try:
            mod = _load(path)
        except Exception as exc:                                     # noqa: BLE001
            print(f"FAIL  import {os.path.basename(path)}: {exc!r}")
            failed += 1
            continue
        for name in sorted(dir(mod)):
            if not name.startswith("test_"):
                continue
            fn = getattr(mod, name)
            if not callable(fn):
                continue
            label = f"{os.path.basename(path)}::{name}"
            try:
                fn()
                print(f"PASS  {label}")
                passed += 1
            except Exception as exc:                                 # noqa: BLE001
                print(f"FAIL  {label}: {exc!r}")
                traceback.print_exc()
                failed += 1
    print(f"\n{passed}/{passed + failed} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
