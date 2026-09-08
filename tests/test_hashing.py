# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

import hashlib

import pytest

from ambit_verify import canonical_json_bytes, hash_object
from ambit_verify.hashing import strict_json_loads


def test_hash_object_stable_across_key_ordering() -> None:
    payload_a = {
        "z": [3, 2, 1],
        "a": {"k2": "value", "k1": 1},
        "m": "x",
    }
    payload_b = {
        "m": "x",
        "a": {"k1": 1, "k2": "value"},
        "z": [3, 2, 1],
    }

    bytes_a = canonical_json_bytes(payload_a)
    bytes_b = canonical_json_bytes(payload_b)

    assert bytes_a == bytes_b
    assert hash_object(payload_a) == hash_object(payload_b)
    assert hash_object(payload_a) == hashlib.sha256(bytes_a).hexdigest()


def test_canonical_json_is_compact_sorted_ascii() -> None:
    assert canonical_json_bytes({"b": "é", "a": [1, {"d": None, "c": True}]}) == (
        b'{"a":[1,{"c":true,"d":null}],"b":"\\u00e9"}'
    )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_rejects_non_finite_numbers(value: float) -> None:
    with pytest.raises(ValueError):
        canonical_json_bytes({"value": value})


@pytest.mark.parametrize(
    "document",
    [
        r'"\ud800"',
        r'"\udc00"',
        r'{"\ud800": 1}',
        r'{"nested": ["\udc00"]}',
    ],
)
def test_strict_json_rejects_unpaired_surrogates_recursively(document: str) -> None:
    with pytest.raises(ValueError, match="unpaired surrogate"):
        strict_json_loads(document)


def test_strict_json_preserves_valid_surrogate_pairs() -> None:
    document = r'{"\ud83d\ude00": ["\ud83d\ude80"]}'
    assert strict_json_loads(document) == {"😀": ["🚀"]}
