# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""JSON Schema files for the claim profiles that ambit-verify ships."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

_SCHEMA_NAMES = frozenset({"mcp-call-v1/dispatch-claims", "mcp-call-v1/outcome-claims"})


def load_schema(name: str) -> dict[str, Any]:
    """Load one packaged JSON Schema (draft 2020-12).

    Args:
        name: Schema name without the file suffix. Valid names are
            ``"mcp-call-v1/dispatch-claims"`` and ``"mcp-call-v1/outcome-claims"``.

    Returns:
        The parsed schema document.

    Raises:
        ValueError: If ``name`` is not a packaged schema.
    """
    if name not in _SCHEMA_NAMES:
        known = ", ".join(sorted(_SCHEMA_NAMES))
        raise ValueError(f"unknown schema {name!r}; known schemas: {known}")
    resource = resources.files(__package__).joinpath(f"{name}.schema.json")
    schema: dict[str, Any] = json.loads(resource.read_text(encoding="utf-8"))
    return schema
