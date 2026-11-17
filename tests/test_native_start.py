# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify.native_start import (
    JOIN_FIELDS,
    PROFILE,
    digest,
    message,
    validate_start_record,
    verify_token,
)
from ambit_verify.resource_protocol import dispatch_message
from test_git_publication_profile import _dispatch, _token


def _material():
    authority = Ed25519PrivateKey.generate()
    resource = Ed25519PrivateKey.generate()
    dispatch = _dispatch()
    dispatch.update(delegation_jtis=["grant-1"], revocation_epoch=0)
    dispatch_token = _token(dispatch, dispatch_message(dispatch), authority)
    request = {
        "version": 1,
        "profile": PROFILE,
        "dispatch_token": dispatch_token,
        "resource_binding_hash": dispatch["resource_binding_hash"],
        "nonce": "a" * 64,
        "issued_at": "2026-01-01T00:00:01Z",
    }
    request_token = _token(request, message(request, grant=False), resource)
    record = {
        "record_type": "native_start",
        "version": 1,
        "profile": PROFILE,
        **{name: dispatch[name] for name in JOIN_FIELDS},
        "dispatch_token": dispatch_token,
        "dispatch_hash": digest(dispatch_token),
        "request_token": request_token,
        "accepted_at": "2026-01-01T00:00:02Z",
        "not_after": dispatch["not_after"],
        "revocation_epoch": 0,
        "authority_public_key": authority.public_key().public_bytes_raw().hex(),
        "resource_public_key": resource.public_key().public_bytes_raw().hex(),
    }
    return authority, resource, request, request_token, record


def test_native_start_request_signature_and_exact_record_join():
    _authority, resource, request, token, record = _material()
    assert (
        verify_token(token, public_key=resource.public_key().public_bytes_raw(), grant=False)
        == request
    )
    assert validate_start_record(record)["operation_id"] == record["operation_id"]


@pytest.mark.parametrize(
    "name,value",
    [
        ("operation_id", "other"),
        ("payload_hash", "b" * 64),
        ("accepted_at", "2026-01-01T00:01:00Z"),
        ("resource_public_key", "a" * 64),
    ],
)
def test_native_start_record_refuses_changed_operation_evidence(name, value):
    *_unused, record = _material()
    record[name] = value
    with pytest.raises(ValueError):
        validate_start_record(record)


def test_request_is_not_a_grant_and_wrong_signer_fails():
    _authority, resource, _request, token, _record = _material()
    with pytest.raises(ValueError):
        verify_token(token, public_key=resource.public_key().public_bytes_raw(), grant=True)
    with pytest.raises(ValueError):
        verify_token(
            token,
            public_key=Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
            grant=False,
        )


def test_grant_carries_original_deadline_and_exact_challenge():
    authority, _resource, _request, token, record = _material()
    grant = {
        "version": 1,
        "profile": PROFILE,
        **{name: record[name] for name in JOIN_FIELDS},
        "challenge_hash": digest(token),
        "dispatch_hash": record["dispatch_hash"],
        "start_record_hash": "d" * 64,
        "accepted_at": record["accepted_at"],
        "not_after": record["not_after"],
    }
    signed = _token(grant, message(grant, grant=True), authority)
    assert (
        verify_token(signed, public_key=authority.public_key().public_bytes_raw(), grant=True)
        == grant
    )


def test_start_history_rejects_terminal_operation_and_prior_applied_revocation():
    from ambit_verify.native_start import validate_start_history

    *_unused, record = _material()
    decision = {
        "record_type": "decision",
        "record_hash": record["decision_hash"],
        "evidence": {
            "authority_admission": {
                "resource_binding": {"outcome_public_key": record["resource_public_key"]}
            }
        },
    }
    fence = {
        "record_type": "consumption",
        "event": "dispatch_fenced",
        "dispatch_token": record["dispatch_token"],
    }
    validate_start_history(
        record, [decision, fence], authority_public_key=record["authority_public_key"]
    )
    settlement = {
        "record_type": "consumption",
        "event": "settlement",
        "operation": {name: record[name] for name in ("domain_id", "operation_id")},
    }
    with pytest.raises(ValueError, match="native_start_operation_terminal"):
        validate_start_history(record, [decision, fence, settlement])
    revocation = [
        {"record_type": "revocation", "phase": "intent", "seq": 3, "target_jti": "grant-1"},
        {"record_type": "revocation", "phase": "outcome", "intent_seq": 3, "result": "revoked"},
    ]
    with pytest.raises(ValueError, match="native_start_follows_revocation"):
        validate_start_history(record, [decision, fence, *revocation])
    with pytest.raises(ValueError, match="native_start_authority_key_mismatch"):
        validate_start_history(record, [decision, fence], authority_public_key="c" * 64)
