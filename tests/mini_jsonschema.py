# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""A stdlib validator for the JSON Schema keywords the mcp-call/1 schemas use.

It supports ``type``, ``const``, ``enum``, ``pattern``, ``minLength``, ``minimum``,
``minItems``, ``maxItems``, ``maxLength``, ``uniqueItems``, ``items``, ``properties``,
``required``, ``additionalProperties: false``, ``dependentRequired``, ``allOf``, ``oneOf``
and ``if``/``then``. An unsupported keyword raises, so a schema cannot pass by being ignored.
"""

from __future__ import annotations

import re
from typing import Any

_IGNORED = frozenset({"$schema", "$id", "title", "description"})
_TYPES: dict[str, type | tuple[type, ...]] = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


def _is_type(value: Any, name: str) -> bool:
    """Return whether ``value`` has the JSON type ``name``."""
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, _TYPES[name])


def is_valid(instance: Any, schema: dict[str, Any]) -> bool:
    """Return whether ``instance`` satisfies ``schema``."""
    return not errors(instance, schema)


def errors(instance: Any, schema: dict[str, Any]) -> list[str]:
    """Return one message per violated keyword. An empty list means the instance is valid."""
    found: list[str] = []
    for keyword, rule in schema.items():
        if keyword in _IGNORED:
            continue
        if keyword == "additionalProperties":
            found.extend(_additional(instance, rule, declared=set(schema.get("properties", {}))))
            continue
        if keyword == "if":
            if is_valid(instance, rule) and "then" in schema:
                found.extend(errors(instance, schema["then"]))
            continue
        if keyword == "then":
            continue
        handler = _KEYWORDS.get(keyword)
        if handler is None:
            raise ValueError(f"unsupported schema keyword: {keyword}")
        found.extend(handler(instance, rule))
    return found


def _type(instance: Any, rule: Any) -> list[str]:
    names = rule if isinstance(rule, list) else [rule]
    ok = any(_is_type(instance, name) for name in names)
    return [] if ok else [f"type is not {names}"]


def _const(instance: Any, rule: Any) -> list[str]:
    same = instance == rule and type(instance) is type(rule)
    return [] if same else [f"value is not {rule!r}"]


def _enum(instance: Any, rule: Any) -> list[str]:
    return [] if instance in rule else [f"value is not one of {rule}"]


def _pattern(instance: Any, rule: Any) -> list[str]:
    ok = not isinstance(instance, str) or re.search(rule, instance) is not None
    return [] if ok else [f"value does not match {rule}"]


def _bound(check: Any, message: str) -> Any:
    def handler(instance: Any, rule: Any) -> list[str]:
        return [] if check(instance, rule) else [message.format(rule)]

    return handler


def _properties(instance: Any, rule: Any) -> list[str]:
    if not isinstance(instance, dict):
        return []
    found: list[str] = []
    for name, sub in rule.items():
        if name in instance:
            found.extend(f"{name}: {e}" for e in errors(instance[name], sub))
    return found


def _required(instance: Any, rule: Any) -> list[str]:
    if not isinstance(instance, dict):
        return []
    return [f"missing {name}" for name in rule if name not in instance]


def _additional(instance: Any, rule: Any, *, declared: set[str]) -> list[str]:
    if rule is not False:
        raise ValueError("only additionalProperties: false is supported")
    if not isinstance(instance, dict):
        return []
    return [f"unexpected {name}" for name in instance if name not in declared]


def _dependent(instance: Any, rule: Any) -> list[str]:
    if not isinstance(instance, dict):
        return []
    return [
        f"{name} requires {other}"
        for name, others in rule.items()
        if name in instance
        for other in others
        if other not in instance
    ]


def _items(instance: Any, rule: Any) -> list[str]:
    if not isinstance(instance, list):
        return []
    return [f"[{i}]: {e}" for i, item in enumerate(instance) for e in errors(item, rule)]


def _unique(instance: Any, rule: Any) -> list[str]:
    if not rule or not isinstance(instance, list):
        return []
    return [] if len(set(map(repr, instance))) == len(instance) else ["items are not unique"]


def _all_of(instance: Any, rule: Any) -> list[str]:
    return [e for sub in rule for e in errors(instance, sub)]


def _one_of(instance: Any, rule: Any) -> list[str]:
    matches = sum(is_valid(instance, sub) for sub in rule)
    return [] if matches == 1 else [f"matches {matches} of oneOf, not 1"]


_KEYWORDS: dict[str, Any] = {
    "type": _type,
    "const": _const,
    "enum": _enum,
    "pattern": _pattern,
    "minLength": _bound(lambda i, r: not isinstance(i, str) or len(i) >= r, "shorter than {}"),
    "maxLength": _bound(lambda i, r: not isinstance(i, str) or len(i) <= r, "longer than {}"),
    "minimum": _bound(
        lambda i, r: not isinstance(i, int) or isinstance(i, bool) or i >= r, "below {}"
    ),
    "minItems": _bound(lambda i, r: not isinstance(i, list) or len(i) >= r, "fewer than {}"),
    "maxItems": _bound(lambda i, r: not isinstance(i, list) or len(i) <= r, "more than {}"),
    "uniqueItems": _unique,
    "items": _items,
    "properties": _properties,
    "required": _required,
    "dependentRequired": _dependent,
    "allOf": _all_of,
    "oneOf": _one_of,
}
