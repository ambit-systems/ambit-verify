# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Canonical JSON and the SHA-256 digest a record hash is computed over."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime
from typing import Any

MAX_JSON_NESTING = 64


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate object key {key!r}")
        value[key] = item
    return value


def _reject_constant(token: str) -> Any:
    raise ValueError(f"non-finite number {token!r}")


def _finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f"number {token!r} is outside the finite JSON domain")
    return value


def _check_json_nesting(text: str, *, maximum: int = MAX_JSON_NESTING) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > maximum:
                raise ValueError(f"JSON nesting exceeds {maximum} levels")
        elif character in "]}":
            depth -= 1


def _reject_unpaired_surrogates(value: Any) -> None:
    """Reject lone UTF-16 surrogate code points anywhere in a JSON value."""
    if isinstance(value, str):
        index = 0
        while index < len(value):
            codepoint = ord(value[index])
            if 0xD800 <= codepoint <= 0xDBFF:
                if index + 1 >= len(value) or not (0xDC00 <= ord(value[index + 1]) <= 0xDFFF):
                    raise ValueError("unpaired surrogate in JSON string")
                index += 2
                continue
            if 0xDC00 <= codepoint <= 0xDFFF:
                raise ValueError("unpaired surrogate in JSON string")
            index += 1
        return
    if isinstance(value, list):
        for item in value:
            _reject_unpaired_surrogates(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_unpaired_surrogates(key)
            _reject_unpaired_surrogates(item)


def strict_json_loads(text: str) -> Any:
    """Parse unambiguous JSON whose strings contain valid Unicode sequences."""
    _check_json_nesting(text)
    value = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
        parse_float=_finite_float,
    )
    _reject_unpaired_surrogates(value)
    return value


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
        allow_nan=False,
    ).encode("utf-8")


def hash_object(obj: Any) -> str:
    """Hash the canonical JSON of *obj*.

    Args:
        obj: Any JSON-serialisable value.

    Returns:
        The SHA-256 digest as 64 lower-case hexadecimal characters.
    """
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


def parse_nonnegative_amount_scaled(value: object) -> int | None:
    """Parse ``0|[1-9][0-9]*`` exactly, without coercing another JSON type."""
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        return None
    try:
        return int(value)
    except ValueError:
        # Respect Python's configured integer-string conversion bound.
        return None


def canonical_iso(dt: datetime) -> str:
    """Format *dt* as canonical UTC ISO-8601 with ``Z`` suffix and millisecond precision."""
    return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256_hex(data: bytes) -> str:
    """Return SHA-256 digest hex for *data* bytes."""
    return hashlib.sha256(data).hexdigest()


__all__ = [
    "canonical_iso",
    "canonical_json_bytes",
    "hash_object",
    "parse_nonnegative_amount_scaled",
    "sha256_hex",
]
