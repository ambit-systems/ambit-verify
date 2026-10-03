# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify.consumption import validate_consumption_record
from ambit_verify.hashing import canonical_json_bytes, sha256_hex
from ambit_verify.resource_protocol import (
    COUNTERPARTY_CONTEXT_CONTEXT,
    counterparty_pending_ack_approval_expectations,
    counterparty_pending_ack_message,
    verify_counterparty_context,
    verify_counterparty_pending_ack,
)


def _digest(character: str) -> str:
    return character * 64


def _token(claims: dict[str, object], key: Ed25519PrivateKey) -> str:
    payload = canonical_json_bytes(claims)
    signature = key.sign(counterparty_pending_ack_message(claims))
    return ".".join(
        (
            base64.urlsafe_b64encode(payload).decode("ascii").rstrip("="),
            base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        )
    )


def _context_token(claims: dict[str, object], key: Ed25519PrivateKey) -> str:
    payload = canonical_json_bytes(claims)
    payload_b64 = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = key.sign(f"{COUNTERPARTY_CONTEXT_CONTEXT}.{payload_b64}".encode("ascii"))
    return f"{payload_b64}.ed25519:{base64.b64encode(signature).decode('ascii')}"


def _review_claims() -> dict[str, object]:
    return {
        "version": 1,
        "profile": "counterparty_pending_ack/1",
        "state": "awaiting_review",
        "foreign_dispatch_hash": _digest("a"),
        "foreign_descriptor_hash": _digest("b"),
        "operation_hash": _digest("c"),
        "request_body_hash": _digest("d"),
        "acknowledged_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-01T00:10:00Z",
    }


def _verify(
    token: str, key: Ed25519PrivateKey, *, state: str, **kwargs: object
) -> dict[str, object]:
    arguments: dict[str, object] = {
        "public_key": key.public_key().public_bytes_raw(),
        "expected_state": state,
        "expected_foreign_dispatch_hash": _digest("a"),
        "expected_foreign_descriptor_hash": _digest("b"),
        "expected_operation_hash": _digest("c"),
        "expected_request_body_hash": _digest("d"),
        "expected_dispatch_not_after": datetime(2026, 1, 1, 0, 20, tzinfo=UTC),
        "at": datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
    }
    arguments.update(kwargs)
    return verify_counterparty_pending_ack(token, **arguments)


def test_review_ack_is_a_strict_disjoint_shape() -> None:
    key = Ed25519PrivateKey.generate()
    token = _token(_review_claims(), key)

    assert _verify(token, key, state="awaiting_review")["state"] == "awaiting_review"

    claims = _review_claims()
    claims["b_request_fingerprint"] = _digest("e")
    with pytest.raises(ValueError, match="claim fields"):
        counterparty_pending_ack_message(claims)


def test_review_ack_rejects_a_forged_or_wrong_outcome_key() -> None:
    signer = Ed25519PrivateKey.generate()
    token = _token(_review_claims(), signer)

    with pytest.raises(ValueError, match="signature does not verify"):
        _verify(token, Ed25519PrivateKey.generate(), state="awaiting_review")

    expired = _review_claims() | {"expires_at": "2026-01-01T00:04:00Z"}
    with pytest.raises(ValueError, match="not active"):
        _verify(_token(expired, signer), signer, state="awaiting_review")


def test_counterparty_resume_record_cannot_replace_the_retained_utf8_body() -> None:
    operation = {
        "operation_id": "op-1",
        "domain_id": "domain-a",
        "ledger_id": "ledger-a",
        "enforcement_point_id": "point-a",
        "actor_key_fingerprint": "actor-a",
        "request_hash": _digest("1"),
        "payload_hash": _digest("2"),
        "resource_binding_hash": _digest("3"),
    }
    body = '{"foreign_dispatch":"token"}'
    record = {
        "record_type": "consumption",
        "profile": "canonical-operation/1",
        "event": "counterparty_resume_fenced",
        "operation": operation,
        "evaluated_at": "2026-01-01T00:05:00Z",
        "decision_hash": _digest("4"),
        "intent_hash": _digest("5"),
        "dispatch_token": "abc.def",
        "dispatch_claims": {"payload_hash": _digest("2")},
        "foreign_dispatch_hash": sha256_hex(b"abc.def"),
        "foreign_descriptor_hash": _digest("6"),
        "operation_hash": _digest("7"),
        "request_body": body,
        "request_body_hash": sha256_hex(body.encode("utf-8")),
        "pending_ack": "ack",
        "pending_hash": _digest("8"),
        "b_request_fingerprint": _digest("a"),
        "b_escalation_record_hash": _digest("b"),
        "resume_authentication_hash": _digest("d"),
        "counterparty_context_hash": _digest("c"),
    }

    validate_consumption_record(record)

    record["request_body"] = '{"foreign_dispatch":"replacement"}'
    with pytest.raises(ValueError, match="body hash"):
        validate_consumption_record(record)


def test_context_requires_the_single_admitted_approval_authority() -> None:
    signer = Ed25519PrivateKey.generate()
    claims = {
        "version": 1,
        "profile": "counterparty_context/1",
        "trust_root_id": "approval-root",
        "foreign_dispatch_hash": _digest("a"),
        "foreign_descriptor_hash": _digest("b"),
        "operation_hash": _digest("c"),
        "request_body_hash": _digest("d"),
        "destination_hash": _digest("e"),
        "consent_hash": _digest("f"),
        "justification": "customer deletion is approved for the stated purpose",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-01T00:10:00Z",
    }
    token = _context_token(claims, signer)
    roots = {
        "approval-root": {
            "scheme": "ed25519",
            "public_key": signer.public_key().public_bytes_raw().hex(),
        }
    }

    assert (
        verify_counterparty_context(
            token,
            trust_roots=roots,
            expected_foreign_dispatch_hash=_digest("a"),
            expected_foreign_descriptor_hash=_digest("b"),
            expected_operation_hash=_digest("c"),
            expected_request_body_hash=_digest("d"),
            expected_destination_hash=_digest("e"),
            expected_consent_hash=_digest("f"),
            expected_justification="customer deletion is approved for the stated purpose",
            expected_dispatch_not_after=datetime(2026, 1, 1, 0, 20, tzinfo=UTC),
            at=datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
        )["trust_root_id"]
        == "approval-root"
    )

    with pytest.raises(ValueError, match="justification does not match"):
        verify_counterparty_context(
            token,
            trust_roots=roots,
            expected_foreign_dispatch_hash=_digest("a"),
            expected_foreign_descriptor_hash=_digest("b"),
            expected_operation_hash=_digest("c"),
            expected_request_body_hash=_digest("d"),
            expected_destination_hash=_digest("e"),
            expected_consent_hash=_digest("f"),
            expected_justification="substituted justification",
            expected_dispatch_not_after=datetime(2026, 1, 1, 0, 20, tzinfo=UTC),
            at=datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
        )

    with pytest.raises(ValueError, match="one explicitly admitted root"):
        verify_counterparty_context(
            token,
            trust_roots=roots | {"unrelated": roots["approval-root"]},
            expected_foreign_dispatch_hash=_digest("a"),
            expected_foreign_descriptor_hash=_digest("b"),
            expected_operation_hash=_digest("c"),
            expected_request_body_hash=_digest("d"),
            expected_destination_hash=_digest("e"),
            expected_consent_hash=_digest("f"),
            expected_dispatch_not_after=datetime(2026, 1, 1, 0, 20, tzinfo=UTC),
            expected_justification="customer deletion is approved for the stated purpose",
            at=datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
        )


def test_approval_ack_binds_all_frozen_preflight_and_transport_joins() -> None:
    key = Ed25519PrivateKey.generate()
    claims = _review_claims() | {
        "state": "awaiting_approval",
        "counterparty_context_hash": _digest("e"),
        "b_request_fingerprint": _digest("0"),
        "b_escalation_record_hash": _digest("1"),
    }
    token = _token(claims, key)

    assert (
        _verify(
            token,
            key,
            state="awaiting_approval",
            expected_counterparty_context_hash=_digest("e"),
            expected_b_request_fingerprint=_digest("0"),
            expected_b_escalation_record_hash=_digest("1"),
        )["state"]
        == "awaiting_approval"
    )

    assert counterparty_pending_ack_approval_expectations(
        token,
        public_key=key.public_key().public_bytes_raw(),
        expected_foreign_dispatch_hash=_digest("a"),
        expected_foreign_descriptor_hash=_digest("b"),
        expected_operation_hash=_digest("c"),
        expected_request_body_hash=_digest("d"),
        expected_dispatch_not_after=datetime(2026, 1, 1, 0, 20, tzinfo=UTC),
        at=datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
    ) == {
        "counterparty_context_hash": _digest("e"),
        "b_request_fingerprint": _digest("0"),
        "b_escalation_record_hash": _digest("1"),
    }

    with pytest.raises(ValueError, match="request_body_hash does not match"):
        _verify(
            token,
            key,
            state="awaiting_approval",
            expected_request_body_hash=_digest("2"),
            expected_counterparty_context_hash=_digest("e"),
            expected_b_request_fingerprint=_digest("0"),
            expected_b_escalation_record_hash=_digest("1"),
        )

    with pytest.raises(ValueError, match="exceeds dispatch expiry"):
        verify_counterparty_pending_ack(
            token,
            public_key=key.public_key().public_bytes_raw(),
            expected_state="awaiting_approval",
            expected_foreign_dispatch_hash=_digest("a"),
            expected_foreign_descriptor_hash=_digest("b"),
            expected_operation_hash=_digest("c"),
            expected_request_body_hash=_digest("d"),
            expected_dispatch_not_after=datetime(2026, 1, 1, 0, 9, tzinfo=UTC),
            at=datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
            expected_counterparty_context_hash=_digest("e"),
            expected_b_request_fingerprint=_digest("0"),
            expected_b_escalation_record_hash=_digest("1"),
        )
