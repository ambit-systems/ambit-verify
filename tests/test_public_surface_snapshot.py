# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Characterization lock for the public surface, pinned before any refactor.

Records the exported names of ``ambit_verify`` and ``ambit_verify.verify``,
and the ``inspect.signature`` of every public callable, against a checked-in
snapshot. A diff here means the public surface changed; the refactor this
lock guards must not do that.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import ambit_verify.verify as verify_module

GOLDEN = json.loads((Path(__file__).parent / "golden" / "public_surface.json").read_text())


def _describe(module: object, names: list[str]) -> dict[str, str]:
    """Describe each exported name as its runtime type and, if callable, signature."""
    described: dict[str, str] = {}
    for name in names:
        obj = getattr(module, name)
        if callable(obj) and not isinstance(obj, str | int | float | bytes):
            try:
                signature = str(inspect.signature(obj))
            except (TypeError, ValueError) as exc:
                signature = f"<no signature: {exc}>"
            described[name] = f"{type(obj).__name__}{signature}"
        else:
            described[name] = f"{type(obj).__name__}={obj!r}"
    return described


def test_ambit_verify_verify_all_is_unchanged() -> None:
    assert list(verify_module.__all__) == GOLDEN["ambit_verify.verify.__all__"]


def test_ambit_verify_verify_signatures_are_unchanged() -> None:
    actual = _describe(verify_module, list(verify_module.__all__))
    assert actual == GOLDEN["ambit_verify.verify.members"]


def test_verify_module_still_carries_the_names_cli_imports_from_it() -> None:
    """``cli.py`` imports these private names directly from ``ambit_verify.verify``.

    They are not in ``__all__``, so the checks above do not cover them. A
    decomposition that moves their implementation elsewhere must still
    re-export them here, unchanged, or ``cli.py``'s import breaks.
    """
    for name in (
        "_Chain",
        "_InputLimitError",
        "_read_utf8_document",
        "_terminal_safe",
        "_walk_ledger",
    ):
        assert hasattr(verify_module, name), name


def test_verify_module_still_exposes_os_for_test_reflection() -> None:
    """Tests monkeypatch ``os.scandir`` via ``verify_module.os``.

    ``ambit_verify.verify`` must keep ``os`` reachable as a module attribute
    for that reflection to keep working: see ``tests/test_encoding.py``.
    """
    assert verify_module.os is __import__("os")


def test_verify_module_still_exposes_tunable_resource_limits() -> None:
    """Tests monkeypatch these constants via ``setattr(verify_module, name, ...)``.

    That only works if the functions that read them are defined in this same
    module, so both the constants and the functions that read them must stay
    co-located here across the refactor.
    """
    limits = {
        "MAX_JSON_DOCUMENT_BYTES": 1024 * 1024,
        "MAX_LEDGER_LINE_BYTES": 16 * 1024 * 1024,
        "MAX_LEDGER_BYTES": 1024 * 1024 * 1024,
        "MAX_LEDGER_PHYSICAL_LINES": 2_000_000,
        "MAX_LEDGER_DIRECTORY_ENTRIES": 100_000,
        "MAX_LEDGER_SEGMENTS": 10_000,
        "MAX_LEDGER_RECORDS": 1_000_000,
    }
    actual = {name: getattr(verify_module, name) for name in limits}
    assert actual == limits


def test_verify_module_still_exposes_lines_for_test_reflection() -> None:
    """``tests/test_ledger_checkpoint.py`` monkeypatches ``verify_module._lines``.

    That only takes effect if the chain walk that calls it looks the name up
    in this module's own globals, i.e. if ``_lines`` stays defined here.
    """
    assert callable(verify_module._lines)
