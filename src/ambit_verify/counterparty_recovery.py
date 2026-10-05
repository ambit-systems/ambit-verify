# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Public verification primitives for bilateral counterparty recovery evidence."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from .admission import ADMISSION_SCHEMA_VERSION, AuthorityAdmission, verify_authority_admission
from .consumption import CONSUMPTION_PROFILE, validate_operation_descriptor
from .resource_protocol import (
    CUSTOMER_DELETE_PROFILE,
    counterparty_consent_hash,
    verify_dispatch,
    verify_reconciliation,
)

_HEX = frozenset("0123456789abcdef")
_SEAL_FIELDS = frozenset({"seq", "prev_hash", "record_hash", "timestamp_utc"})
_CANCELLATION_FIELDS = frozenset(
    {
        "record_type",
        "profile",
        "event",
        "operation",
        "evaluated_at",
        "adapter_id",
        "domain_id",
        "ledger_id",
        "enforcement_point_id",
        "admission_token",
        "foreign_dispatch",
        "recovery_request",
    }
)
_RECOVERY_FIELDS = frozenset(
    {
        "record_type",
        "profile",
        "event",
        "operation",
        "evaluated_at",
        "decision_hash",
        "intent_hash",
        "authentication_hash",
        "recovery_request",
        "resource_outcome",
    }
)
_RECOVERY_JOIN_FIELDS = (
    "version",
    "profile",
    "domain_id",
    "ledger_id",
    "enforcement_point_id",
    "resource_id",
    "resource_binding_hash",
    "operation_id",
    "request_hash",
    "payload_hash",
    "decision_hash",
    "intent_hash",
    "customer_id",
)


def _text(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be nonempty canonical text")
    return value


def _ascii_token(value: object, *, name: str) -> str:
    value = _text(value, name=name)
    if not value.isascii():
        raise ValueError(f"{name} must be ASCII")
    return value


def _digest(value: object, *, name: str, size: int = 64) -> str:
    if not isinstance(value, str) or len(value) != size or set(value) - _HEX:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _moment(value: object, *, name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} requires an explicit timezone")
    return parsed.astimezone(UTC)


def _point_dispatch(
    foreign_dispatch: str, *, point_id: str, point: Mapping[str, Any]
) -> dict[str, Any]:
    """Verify the frozen A dispatch through one signed B-admitted point."""
    _digest(point_id, name="counterparty point id", size=16)
    if not isinstance(point, Mapping):
        raise ValueError("counterparty point is invalid")
    for name in ("domain_id", "ledger_id", "resource_id", "consent_delegation_token"):
        _text(point.get(name), name=f"counterparty point {name}")
    _digest(point.get("resource_binding_hash"), name="counterparty point resource binding hash")
    public_key = _digest(point.get("public_key"), name="counterparty point public key")
    if point.get("profile") != CUSTOMER_DELETE_PROFILE:
        raise ValueError("counterparty point profile is invalid")
    parents = point.get("consent_parent_delegation_tokens")
    if not isinstance(parents, list) or any(
        not isinstance(token, str) or not token or token != token.strip() for token in parents
    ):
        raise ValueError("counterparty point consent ancestry is invalid")
    claims = verify_dispatch(foreign_dispatch, public_key=public_key)
    if "foreign_dependency" in claims:
        raise ValueError("foreign dispatch must not nest a foreign dependency")
    if (
        claims.get("profile") != CUSTOMER_DELETE_PROFILE
        or claims.get("enforcement_point_id") != point_id
        or claims.get("domain_id") != point["domain_id"]
        or claims.get("ledger_id") != point["ledger_id"]
        or claims.get("resource_id") != point["resource_id"]
        or claims.get("resource_binding_hash") != point["resource_binding_hash"]
    ):
        raise ValueError("foreign dispatch does not match the admitted counterparty point")
    consent_hash = counterparty_consent_hash(
        delegation_token=point["consent_delegation_token"],
        parent_delegation_tokens=parents,
    )
    if claims.get("counterparty_consent_hash") != consent_hash:
        raise ValueError("foreign dispatch counterparty consent hash differs")
    return claims


def counterparty_foreign_dispatch_identity(
    foreign_dispatch: str, *, points: Mapping[str, Any]
) -> tuple[str, dict[str, Any]]:
    """Return the one admitted A point and dispatch claims selected by a raw token."""
    foreign_dispatch = _ascii_token(foreign_dispatch, name="foreign dispatch")
    if not isinstance(points, Mapping):
        raise ValueError("trusted counterparty points are invalid")
    candidates: list[tuple[str, dict[str, Any]]] = []
    for point_id, point in points.items():
        if not isinstance(point_id, str) or not isinstance(point, Mapping):
            continue
        try:
            claims = _point_dispatch(foreign_dispatch, point_id=point_id, point=point)
        except (TypeError, ValueError):
            continue
        candidates.append((point_id, claims))
    if len(candidates) != 1:
        raise ValueError("foreign dispatch does not select one admitted counterparty point")
    return candidates[0]


def verify_counterparty_recovery_request(
    foreign_dispatch: str,
    recovery_request: str,
    *,
    point_id: str,
    point: Mapping[str, Any],
    at: datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify a fresh A query/cancel request against one B-admitted A point.

    Recovery closes prior authority and deliberately does not require the raw A
    dispatch to remain live. The reconciliation request itself is always fresh.
    """
    if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("counterparty recovery verification time is invalid")
    foreign_dispatch = _ascii_token(foreign_dispatch, name="foreign dispatch")
    recovery_request = _ascii_token(recovery_request, name="recovery request")
    dispatch = _point_dispatch(foreign_dispatch, point_id=point_id, point=point)
    reconciliation = verify_reconciliation(recovery_request, public_key=point["public_key"])
    if reconciliation.get("verb") not in {"query", "cancel"}:
        raise ValueError("recovery request verb is invalid")
    if any(reconciliation.get(name) != dispatch.get(name) for name in _RECOVERY_JOIN_FIELDS):
        raise ValueError("recovery request does not join the original foreign dispatch")
    verified_at = at.astimezone(UTC)
    issued_at = _moment(reconciliation.get("issued_at"), name="recovery request issued_at")
    expires_at = _moment(reconciliation.get("expires_at"), name="recovery request expires_at")
    if not issued_at <= verified_at < expires_at:
        raise ValueError("recovery request is not active")
    return dict(dispatch), dict(reconciliation)


def validate_counterparty_cancellation_record_shape(record: Mapping[str, Any]) -> None:
    """Validate the exact sealed grammar of a B ``counterparty_cancelled`` event."""
    if not isinstance(record, Mapping) or set(record) - _SEAL_FIELDS != _CANCELLATION_FIELDS:
        raise ValueError("counterparty cancellation record fields are invalid")
    if (
        record.get("record_type") != "consumption"
        or record.get("profile") != CONSUMPTION_PROFILE
        or record.get("event") != "counterparty_cancelled"
        or record.get("operation") is not None
    ):
        raise ValueError("counterparty cancellation record identity is invalid")
    _moment(record.get("evaluated_at"), name="counterparty cancellation evaluated_at")
    for name in ("adapter_id", "domain_id", "ledger_id", "enforcement_point_id"):
        _text(record.get(name), name=f"counterparty cancellation {name}")
    for name in ("admission_token", "foreign_dispatch", "recovery_request"):
        _ascii_token(record.get(name), name=f"counterparty cancellation {name}")


def verify_counterparty_cancellation_record(
    record: Mapping[str, Any],
    *,
    admission_trust_roots: Mapping[str, Mapping[str, Any]],
    expected_domain: str,
    expected_ledger_id: str,
) -> tuple[AuthorityAdmission, dict[str, Any], dict[str, Any]]:
    """Verify B cancellation evidence under caller-pinned admission roots."""
    validate_counterparty_cancellation_record_shape(record)
    evaluated_at = _moment(record["evaluated_at"], name="counterparty cancellation evaluated_at")
    admission_result = verify_authority_admission(
        record["admission_token"],
        admission_trust_roots=admission_trust_roots,
        expected_domain=expected_domain,
        expected_ledger_id=expected_ledger_id,
        at=evaluated_at,
    )
    admission = admission_result.admission
    if not admission_result.valid or admission is None:
        raise ValueError("counterparty cancellation admission does not verify")
    binding = admission.claims.get("resource_binding")
    points = admission.claims.get("trusted_counterparty_points")
    if (
        admission.claims.get("schema_version") != ADMISSION_SCHEMA_VERSION
        or admission.claims.get("domain_id") != record["domain_id"]
        or admission.claims.get("ledger_id") != record["ledger_id"]
        or admission.claims.get("enforcement_point_id") != record["enforcement_point_id"]
        or not isinstance(binding, Mapping)
        or binding.get("adapter_id") != record["adapter_id"]
        or not isinstance(points, Mapping)
    ):
        raise ValueError("counterparty cancellation does not bind its B admission")
    point_id, _candidate_dispatch = counterparty_foreign_dispatch_identity(
        record["foreign_dispatch"], points=points
    )
    point = points[point_id]
    if not isinstance(point, Mapping):
        raise ValueError("counterparty cancellation selects an invalid point")
    dispatch, reconciliation = verify_counterparty_recovery_request(
        record["foreign_dispatch"],
        record["recovery_request"],
        point_id=point_id,
        point=point,
        at=evaluated_at,
    )
    if reconciliation["verb"] != "cancel":
        raise ValueError("counterparty cancellation requires a cancel request")
    return admission, dispatch, reconciliation


def validate_counterparty_recovery_record(record: Mapping[str, Any]) -> None:
    """Validate the exact sealed grammar of an A ``counterparty_recovered`` event."""
    if not isinstance(record, Mapping) or set(record) - _SEAL_FIELDS != _RECOVERY_FIELDS:
        raise ValueError("counterparty recovery record fields are invalid")
    if (
        record.get("record_type") != "consumption"
        or record.get("profile") != CONSUMPTION_PROFILE
        or record.get("event") != "counterparty_recovered"
    ):
        raise ValueError("counterparty recovery record identity is invalid")
    validate_operation_descriptor(record.get("operation"))
    _moment(record.get("evaluated_at"), name="counterparty recovery evaluated_at")
    for name in ("decision_hash", "intent_hash", "authentication_hash"):
        _digest(record.get(name), name=f"counterparty recovery {name}")
    for name in ("recovery_request", "resource_outcome"):
        _ascii_token(record.get(name), name=f"counterparty recovery {name}")


__all__ = [
    "counterparty_foreign_dispatch_identity",
    "validate_counterparty_cancellation_record_shape",
    "validate_counterparty_recovery_record",
    "verify_counterparty_cancellation_record",
    "verify_counterparty_recovery_request",
]
