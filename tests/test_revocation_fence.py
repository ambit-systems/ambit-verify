# Copyright (c) 2026 Ambit Systems Pty Ltd. All rights reserved.
# Proprietary and confidential. See LICENSE for terms.

"""Signed fence request and grant cannot change purpose or bound operation."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify.hashing import canonical_json_bytes
from ambit_verify.revocation_fence import (
    FENCE_PROFILE,
    fence_message,
    fence_request_hash,
    verify_fence_token,
)

_KEY = bytes(range(32))
_PUBLIC = Ed25519PrivateKey.from_private_bytes(_KEY).public_key().public_bytes_raw()


def _token(claims: dict[str, object], *, grant: bool) -> str:
    payload = canonical_json_bytes(claims)
    signature = Ed25519PrivateKey.from_private_bytes(_KEY).sign(fence_message(claims, grant=grant))
    return ".".join(
        base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
        for value in (payload, signature)
    )


def _request() -> dict[str, object]:
    return {
        "version": 1,
        "profile": FENCE_PROFILE,
        "a_dispatch": "a.b",
        "b_dispatch_hash": "a" * 64,
        "b_operation_id": "op-1",
        "b_domain_id": "b-domain",
        "b_ledger_id": "b-ledger",
        "b_resource_id": "b-resource",
        "b_resource_binding_hash": "b" * 64,
        "customer_id": "cust-1",
        "payload_hash": "c" * 64,
    }


def test_fence_request_signature_binds_exact_operation_and_context() -> None:
    request = _request()
    token = _token(request, grant=False)
    assert verify_fence_token(token, public_key=_PUBLIC, grant=False) == request
    assert len(fence_request_hash(token)) == 64
    with pytest.raises(ValueError):
        verify_fence_token(token, public_key=_PUBLIC, grant=True)
    changed = dict(request, b_operation_id="op-2")
    changed_payload = base64.urlsafe_b64encode(canonical_json_bytes(changed)).rstrip(b"=").decode()
    with pytest.raises(ValueError):
        verify_fence_token(
            changed_payload + "." + token.split(".")[1], public_key=_PUBLIC, grant=False
        )


def test_fence_grant_cannot_be_read_as_request() -> None:
    request_token = _token(_request(), grant=False)
    grant = {
        "version": 1,
        "profile": FENCE_PROFILE,
        "request_hash": fence_request_hash(request_token),
        "a_dispatch_hash": "d" * 64,
        "b_dispatch_hash": "a" * 64,
        "delegation_jtis": ["parent", "leaf"],
        "revocation_epoch": 4,
        "prepared_at": "2026-10-08T00:00:00Z",
        "trust_root_id": "a-root",
    }
    token = _token(grant, grant=True)
    assert verify_fence_token(token, public_key=_PUBLIC, grant=True) == grant
    with pytest.raises(ValueError):
        verify_fence_token(token, public_key=_PUBLIC, grant=False)
