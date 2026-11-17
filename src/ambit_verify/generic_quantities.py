# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Recompute generic debits from an independently installed quantity policy."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .hashing import canonical_json_bytes


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip()


def generic_quantities(
    *,
    policy: Mapping[str, Any] | None,
    action_type: str,
    action_boundary: str,
    arguments: Mapping[str, Any],
) -> dict[tuple[str, str], int]:
    """Derive quantities without trusting a ledger-declared amount or selector.

    The caller supplies the resolver policy from independent configuration.
    This checks the forwarded arguments. It does not measure an external effect.
    """
    if (
        not isinstance(policy, Mapping)
        or policy.get("enabled") is not True
        or set(policy) - {"enabled", "records_field_by_action", "argument_quantity_by_action"}
    ):
        raise ValueError("generic quantitative replay requires an enabled independent policy")
    fields = policy.get("records_field_by_action", {})
    quantities = policy.get("argument_quantity_by_action", {})
    if not isinstance(fields, Mapping) or not isinstance(quantities, Mapping):
        raise ValueError("generic quantity policy mappings are malformed")
    if any(not _text(key) or not _text(value) for key, value in fields.items()):
        raise ValueError("generic record-count policy is malformed")
    for key, value in quantities.items():
        if (
            not _text(key)
            or not isinstance(value, Mapping)
            or set(value) != {"argument", "kind", "unit", "scale"}
            or not all(_text(value[name]) for name in ("argument", "kind", "unit"))
            or value["kind"] in {"payload_size", "record_count", "git_push"}
            or type(value["scale"]) is not int
            or value["scale"] < 0
        ):
            raise ValueError("generic argument-quantity policy is malformed")
    result: dict[tuple[str, str], int] = {}
    if action_boundary in {"network_egress", "memory"}:
        result[("payload_size", "bytes")] = len(canonical_json_bytes(dict(arguments)))
        field = fields.get(action_type)
        records = arguments.get(field) if isinstance(field, str) else None
        if isinstance(records, list):
            result[("record_count", "count:records")] = len(records)
    quantity = quantities.get(action_type)
    if isinstance(quantity, Mapping) and quantity["argument"] in arguments:
        amount = arguments[quantity["argument"]]
        if type(amount) is not int or amount < 0:
            raise ValueError("generic quantity argument must be a non-negative integer")
        scaled = amount * 10 ** quantity["scale"]
        # Match the runtime's decimal representation boundary.
        str(scaled)
        result[(quantity["kind"], quantity["unit"])] = scaled
    return result
