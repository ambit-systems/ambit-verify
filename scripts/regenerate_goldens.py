# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Regenerate the public-surface golden that locks ambit-verify's exported API.

``tests/test_public_surface_snapshot.py`` compares ``__all__`` and the
signature of every exported name with ``tests/golden/public_surface.json``.
Run this script only after a change to the public surface that is intended and
reviewed. Then read the whole ``git diff tests/golden`` before you commit it.
A difference that the change does not explain is a defect, not a golden to
update.

Run from the repository root::

    uv run python scripts/regenerate_goldens.py
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType

REPO = Path(__file__).resolve().parent.parent
GOLDEN = REPO / "tests" / "golden" / "public_surface.json"
MODULES = ("ambit_verify", "ambit_verify.verify")


def _surface_lock() -> ModuleType:
    """Import the surface lock test module from the repository's ``tests`` directory."""
    tests = str(REPO / "tests")
    if tests not in sys.path:
        sys.path.insert(0, tests)
    return importlib.import_module("test_public_surface_snapshot")


def regenerate_surface() -> dict[str, int]:
    """Write the public-surface golden from the installed package.

    Returns:
        The number of exported names written for each module.
    """
    lock = _surface_lock()
    document: dict[str, object] = {}
    counts: dict[str, int] = {}
    for module_name in MODULES:
        module = importlib.import_module(module_name)
        exported = list(module.__all__)
        document[f"{module_name}.__all__"] = exported
        document[f"{module_name}.members"] = lock._describe(module, exported)
        counts[module_name] = len(exported)
    GOLDEN.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return counts


def main() -> int:
    """Regenerate the golden and print how many names each module exports."""
    for module_name, count in regenerate_surface().items():
        print(f"{module_name}: {count} exported names")
    return 0


if __name__ == "__main__":
    sys.exit(main())
