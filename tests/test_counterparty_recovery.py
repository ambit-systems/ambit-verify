# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Public wire regressions for bilateral counterparty recovery validators."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify.consumption import validate_consumption_record
from ambit_verify.counterparty_recovery import verify_counterparty_recovery_request
from ambit_verify.hashing import canonical_json_bytes
from ambit_verify.resource_protocol import (
    CUSTOMER_DELETE_PROFILE,
    counterparty_consent_hash,
    dispatch_message,
    reconciliation_message,
)


def _token(claims: dict[str, object], message: bytes, key: Ed25519PrivateKey) -> str:
    payload = base64.urlsafe_b64encode(canonical_json_bytes(claims)).rstrip(b"=")
    signature = base64.urlsafe_b64encode(key.sign(message)).rstrip(b"=")
    return f"{payload.decode()}.{signature.decode()}"


def _material() -> tuple[
    str,
    dict[str, object],
    dict[str, object],
    dict[str, object],
    Ed25519PrivateKey,
]:
    key = Ed25519PrivateKey.generate()
    point_id = "0" * 16
    point = {
        "domain_id": "domain-a",
        "ledger_id": "ledger-a",
        "resource_id": "customer-door",
        "resource_binding_hash": "1" * 64,
        "public_key": key.public_key().public_bytes_raw().hex(),
        "profile": CUSTOMER_DELETE_PROFILE,
        "consent_delegation_token": "consent-token",
        "consent_parent_delegation_tokens": [],
    }
    dispatch = {
        "version": 1,
        "profile": CUSTOMER_DELETE_PROFILE,
        "domain_id": "domain-a",
        "ledger_id": "ledger-a",
        "enforcement_point_id": point_id,
        "resource_id": "customer-door",
        "resource_binding_hash": "1" * 64,
        "operation_id": "delete-1",
        "request_hash": "2" * 64,
        "payload_hash": "3" * 64,
        "decision_hash": "4" * 64,
        "intent_hash": "5" * 64,
        "customer_id": "customer-1",
        "action_type": "delete",
        "action_boundary": "network_egress",
        "action_domain": "http",
        "action_path": "https://a.invalid/v1/customer",
        "authorized_at": "2026-01-01T00:00:00Z",
        "not_after": "2026-01-01T00:01:00Z",
        "counterparty_consent_hash": counterparty_consent_hash(
            delegation_token="consent-token", parent_delegation_tokens=[]
        ),
    }
    reconciliation = {
        name: dispatch[name]
        for name in (
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
    } | {
        "verb": "cancel",
        "issued_at": "2026-01-01T00:01:00Z",
        "expires_at": "2026-01-01T00:03:00Z",
    }
    return point_id, point, dispatch, reconciliation, key


def test_recovery_request_accepts_expired_raw_dispatch_but_fresh_exact_cancel() -> None:
    point_id, point, dispatch, reconciliation, key = _material()
    raw_dispatch = _token(dispatch, dispatch_message(dispatch), key)
    request = _token(reconciliation, reconciliation_message(reconciliation), key)

    actual_dispatch, actual_request = verify_counterparty_recovery_request(
        raw_dispatch,
        request,
        point_id=point_id,
        point=point,
        at=datetime(2026, 1, 1, 0, 2, tzinfo=UTC),
    )

    assert actual_dispatch == dispatch
    assert actual_request == reconciliation


def test_recovery_request_refuses_resigned_customer_or_operation_substitution() -> None:
    point_id, point, dispatch, reconciliation, key = _material()
    raw_dispatch = _token(dispatch, dispatch_message(dispatch), key)
    forged = {**reconciliation, "customer_id": "customer-2"}
    request = _token(forged, reconciliation_message(forged), key)

    with pytest.raises(ValueError, match="does not join"):
        verify_counterparty_recovery_request(
            raw_dispatch,
            request,
            point_id=point_id,
            point=point,
            at=datetime(2026, 1, 1, 0, 2, tzinfo=UTC),
        )


def test_cancellation_and_recovery_shapes_are_closed_canonical_events() -> None:
    cancellation = {
        "record_type": "consumption",
        "profile": "canonical-operation/1",
        "event": "counterparty_cancelled",
        "operation": None,
        "evaluated_at": "2026-01-01T00:02:00Z",
        "adapter_id": "http",
        "domain_id": "domain-b",
        "ledger_id": "ledger-b",
        "enforcement_point_id": "point-b",
        "admission_token": "admission.token",
        "foreign_dispatch": "dispatch.token",
        "recovery_request": "recovery.token",
    }
    validate_consumption_record(cancellation)

    with pytest.raises(ValueError, match="fields"):
        validate_consumption_record({**cancellation, "operation_id": "delete-1"})

    recovery = {
        "record_type": "consumption",
        "profile": "canonical-operation/1",
        "event": "counterparty_recovered",
        "operation": {
            "operation_id": "delete-1",
            "domain_id": "domain-a",
            "ledger_id": "ledger-a",
            "enforcement_point_id": "point-a",
            "actor_key_fingerprint": "owner-key",
            "request_hash": "1" * 64,
            "payload_hash": "2" * 64,
            "resource_binding_hash": "3" * 64,
        },
        "evaluated_at": "2026-01-01T00:02:00Z",
        "decision_hash": "4" * 64,
        "intent_hash": "5" * 64,
        "authentication_hash": "6" * 64,
        "recovery_request": "recovery.token",
        "resource_outcome": "outcome.token",
    }
    validate_consumption_record(recovery)

    with pytest.raises(ValueError, match="fields"):
        validate_consumption_record({**recovery, "status": "committed"})
