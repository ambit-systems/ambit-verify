# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Canonical JSON and the SHA-256 digest a record hash is computed over."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialise *obj* as canonical JSON.

    Args:
        obj: Any JSON-serialisable value.

    Returns:
        UTF-8 bytes with keys sorted, no whitespace, and non-ASCII escaped.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def hash_object(obj: Any) -> str:
    """Hash the canonical JSON of *obj*.

    Args:
        obj: Any JSON-serialisable value.

    Returns:
        The SHA-256 digest as 64 lower-case hexadecimal characters.
    """
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


__all__ = ["canonical_json_bytes", "hash_object"]
