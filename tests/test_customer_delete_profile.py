# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Strict public grammar regressions for the customer-delete resource profile."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify import canonical_json_bytes, verify_authority_admission
from ambit_verify.resource_protocol import (
    CUSTOMER_DELETE_PROFILE,
    dispatch_max_revocation_age_ms,
    dispatch_message,
    dispatch_revocation_identity,
    outcome_message,
    reconciliation_message,
    resource_binding_hash,
    verify_dispatch,
    verify_reconciliation,
    verify_resource_outcome,
)

_HASH = "a" * 64


def _token(claims: dict[str, object], message: bytes, key: Ed25519PrivateKey) -> str:
    payload = base64.urlsafe_b64encode(canonical_json_bytes(claims)).rstrip(b"=")
    signature = base64.urlsafe_b64encode(key.sign(message)).rstrip(b"=")
    return f"{payload.decode()}.{signature.decode()}"


def _dispatch() -> dict[str, object]:
    return {
        "version": 1,
        "profile": CUSTOMER_DELETE_PROFILE,
        "domain_id": "customer-domain",
        "ledger_id": "customer-ledger",
        "enforcement_point_id": "0123456789abcdef",
        "resource_id": "customer-door",
        "resource_binding_hash": _HASH,
        "operation_id": "delete-customer-1",
        "request_hash": _HASH,
        "payload_hash": _HASH,
        "decision_hash": _HASH,
        "intent_hash": _HASH,
        "customer_id": "cust_001",
        "action_type": "delete",
        "action_boundary": "network_egress",
        "action_domain": "http",
        "action_path": "http://tool-gateway:9000/v1/tools/call",
        "authorized_at": "2026-01-01T00:00:00Z",
        "not_after": "2026-01-01T00:01:00Z",
    }


def _outcome(*, status: str = "committed") -> dict[str, object]:
    claims = _dispatch()
    for field in (
        "action_type",
        "action_boundary",
        "action_domain",
        "action_path",
        "authorized_at",
        "not_after",
    ):
        claims.pop(field)
    if status == "committed":
        claims.update(
            {
                "status": "committed",
                "accepted_at": "2026-01-01T00:00:01Z",
                "recorded_at": "2026-01-01T00:00:02Z",
                "deleted_count": 1,
                "before_hash": _HASH,
                "before_state": "present",
                "after_state": "absent",
                "reason": "deleted",
            }
        )
    else:
        claims.update(
            {
                "status": "not_executed",
                "accepted_at": None,
                "recorded_at": "2026-01-01T00:00:02Z",
                "deleted_count": 0,
                "before_hash": None,
                "before_state": "absent",
                "after_state": "absent",
                "reason": "already_absent",
            }
        )
    return claims


def _reconciliation() -> dict[str, object]:
    dispatch = _dispatch()
    return {
        key: dispatch[key]
        for key in (
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
        "issued_at": "2026-01-01T00:00:01Z",
        "expires_at": "2026-01-01T00:01:00Z",
    }


def test_customer_delete_dispatch_and_binding_are_strict() -> None:
    key = Ed25519PrivateKey.generate()
    claims = _dispatch()
    token = _token(claims, dispatch_message(claims), key)

    assert verify_dispatch(token, public_key=key.public_key().public_bytes_raw()) == claims
    binding = {
        "adapter_id": "http",
        "downstream_url": "http://tool-gateway:9000",
        "downstream_path": "/v1/tools/call",
        "receipt_public_key": "b" * 64,
        "outcome_profile": CUSTOMER_DELETE_PROFILE,
        "outcome_public_key": "c" * 64,
    }
    assert resource_binding_hash(binding)

    claims["action_boundary"] = "tool_execution"
    with pytest.raises(ValueError):
        dispatch_message(claims)
    with pytest.raises(ValueError):
        resource_binding_hash({**binding, "unexpected": True})
    with pytest.raises(ValueError):
        resource_binding_hash({**binding, "adapter_id": "mcp"})


def test_customer_delete_outcomes_require_explicit_state_transition() -> None:
    key = Ed25519PrivateKey.generate()
    committed = _outcome()
    token = _token(committed, outcome_message(committed), key)
    assert (
        verify_resource_outcome(token, public_key=key.public_key().public_bytes_raw()) == committed
    )

    absent = _outcome(status="not_executed")
    token = _token(absent, outcome_message(absent), key)
    assert verify_resource_outcome(token, public_key=key.public_key().public_bytes_raw()) == absent

    revoked = _outcome(status="not_executed")
    revoked["before_state"] = "unknown"
    revoked["after_state"] = "unknown"
    revoked["reason"] = "delegation_revoked"
    token = _token(revoked, outcome_message(revoked), key)
    assert verify_resource_outcome(token, public_key=key.public_key().public_bytes_raw()) == revoked

    invalid_revoked_absent = _outcome(status="not_executed")
    invalid_revoked_absent["reason"] = "delegation_revoked"
    with pytest.raises(ValueError):
        outcome_message(invalid_revoked_absent)

    invalid_revoked_present = _outcome(status="not_executed")
    invalid_revoked_present["before_state"] = "present"
    invalid_revoked_present["reason"] = "delegation_revoked"
    with pytest.raises(ValueError):
        outcome_message(invalid_revoked_present)

    missing_post_state = _outcome()
    missing_post_state.pop("after_state")
    with pytest.raises(ValueError):
        outcome_message(missing_post_state)

    invalid_absent = _outcome(status="not_executed")
    invalid_absent["before_state"] = "unknown"
    with pytest.raises(ValueError):
        outcome_message(invalid_absent)


def test_customer_delete_reconciliation_is_bound_to_the_customer() -> None:
    key = Ed25519PrivateKey.generate()
    claims = _reconciliation()
    token = _token(claims, reconciliation_message(claims), key)
    assert verify_reconciliation(token, public_key=key.public_key().public_bytes_raw()) == claims

    claims.pop("customer_id")
    with pytest.raises(ValueError):
        reconciliation_message(claims)


def _admission_token(claims: dict[str, object], key: Ed25519PrivateKey) -> str:
    payload = {**claims, "trust_root_id": "admission"}
    encoded = base64.urlsafe_b64encode(canonical_json_bytes(payload)).rstrip(b"=")
    signature = base64.b64encode(key.sign(b"ambit:authority-admission:v1." + encoded))
    return f"{encoded.decode()}.ed25519:{signature.decode()}"


def test_customer_delete_six_field_binding_is_admitted_under_schema2() -> None:
    signer = Ed25519PrivateKey.generate()
    claims: dict[str, object] = {
        "schema_version": 2,
        "domain_id": "customer-domain",
        "principal_id": "customer-owner",
        "resource_id": "customer-door",
        "ledger_id": "customer-ledger",
        "enforcement_point_id": "0123456789abcdef",
        "version": 1,
        "previous_admission_hash": None,
        "nbf": "2026-01-01T00:00:00Z",
        "exp": "2027-01-01T00:00:00Z",
        "credential_trust_roots": {"issuer": {"scheme": "ed25519", "public_key": "1" * 64}},
        "credential_registration_public_keys": {"registrar": "2" * 64},
        "revocation_attestation_public_keys": {"revocation": "3" * 64},
        "cumulative_attestation_public_keys": {"cumulative": "4" * 64},
        "origin_grant_hashes": ["5" * 64],
        "resource_binding": {
            "adapter_id": "http",
            "downstream_url": "http://tool-gateway:9000",
            "downstream_path": "/v1/tools/call",
            "receipt_public_key": "b" * 64,
            "outcome_profile": CUSTOMER_DELETE_PROFILE,
            "outcome_public_key": "c" * 64,
        },
        "max_revocation_age_ms": 1000,
        "max_cumulative_age_ms": 1000,
        "max_actor_proof_age_seconds": 10,
    }

    verified = verify_authority_admission(
        _admission_token(claims, signer),
        admission_trust_roots={
            "admission": {
                "scheme": "ed25519",
                "public_key": signer.public_key().public_bytes_raw().hex(),
            }
        },
        expected_domain="customer-domain",
        expected_ledger_id="customer-ledger",
        at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert verified.valid and verified.admission is not None


def test_dispatch_revocation_identity_is_optional_and_strict() -> None:
    key = Ed25519PrivateKey.generate()
    public_key = key.public_key().public_bytes_raw()
    bare = _dispatch()
    assert dispatch_revocation_identity(bare) is None

    claims = {**_dispatch(), "delegation_jtis": ["grant-1", "grant-0"], "revocation_epoch": 7}
    token = _token(claims, dispatch_message(claims), key)
    verified = verify_dispatch(token, public_key=public_key)
    assert verified == claims
    assert dispatch_revocation_identity(verified) == (("grant-1", "grant-0"), 7)

    for broken in (
        {**claims, "revocation_epoch": None},
        {**claims, "revocation_epoch": -1},
        {**claims, "revocation_epoch": True},
        {**claims, "delegation_jtis": []},
        {**claims, "delegation_jtis": ["grant-1", "grant-1"]},
        {**claims, "delegation_jtis": ["grant-1", 2]},
        {**claims, "delegation_jtis": "grant-1"},
    ):
        with pytest.raises(ValueError):
            dispatch_message(broken)
    half = dict(claims)
    half.pop("revocation_epoch")
    with pytest.raises(ValueError):
        dispatch_message(half)
    half = dict(claims)
    half.pop("delegation_jtis")
    with pytest.raises(ValueError):
        dispatch_message(half)


def test_dispatch_max_revocation_age_ms_travels_only_with_the_pair() -> None:
    key = Ed25519PrivateKey.generate()
    public_key = key.public_key().public_bytes_raw()
    paired = {**_dispatch(), "delegation_jtis": ["grant-1", "grant-0"], "revocation_epoch": 7}

    bounded = {**paired, "max_revocation_age_ms": 5000}
    token = _token(bounded, dispatch_message(bounded), key)
    verified = verify_dispatch(token, public_key=public_key)
    assert verified == bounded
    assert dispatch_max_revocation_age_ms(verified) == 5000

    token = _token(paired, dispatch_message(paired), key)
    verified = verify_dispatch(token, public_key=public_key)
    assert verified == paired
    assert dispatch_max_revocation_age_ms(verified) is None

    unpaired = {**_dispatch(), "max_revocation_age_ms": 5000}
    with pytest.raises(ValueError):
        dispatch_message(unpaired)

    for broken in (0, -1, True, "5000"):
        with pytest.raises(ValueError, match="dispatch max_revocation_age_ms is invalid"):
            dispatch_message({**bounded, "max_revocation_age_ms": broken})
    # A float fails the shared payload rule against floating-point values first.
    with pytest.raises(ValueError):
        dispatch_message({**bounded, "max_revocation_age_ms": 1.5})
