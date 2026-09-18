# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Public actor-proof enrolment boundary regressions."""

from __future__ import annotations

from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ambit_verify.actor_proof import REFUSAL_UNREGISTERED, verify_actor_proof
from ambit_verify.credential_registration import (
    credential_key_fingerprint,
    verify_credential_registration,
)


def test_present_workload_proof_requires_independent_countersigning_roots() -> None:
    public_key = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        .hex()
    )
    fingerprint = credential_key_fingerprint(public_key)
    registration = {
        "credential_kind": "workload",
        "scheme": "p256",
        "public_key": public_key,
        "key_fingerprint": fingerprint,
        "subject": "actor",
    }
    proof = {
        "scheme": "p256",
        "key_fingerprint": fingerprint,
        "nonce": "0" * 32,
        "issued_at": "2026-01-01T00:00:00Z",
        "audience": "ledger",
        "signature": "p256:invalid",
    }
    result = verify_actor_proof(
        {"actor_id": "actor", "actor_proof": proof},
        {"actor-root": {"scheme": "p256", "public_key": public_key, "registration": registration}},
        request_hash="a" * 64,
        audience="ledger",
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert not result.valid
    assert result.refusal == REFUSAL_UNREGISTERED


def test_actor_proof_and_registration_result_apis_refuse_nonmapping_inputs() -> None:
    proof = {
        "scheme": "p256",
        "key_fingerprint": "a" * 64,
        "nonce": "0" * 32,
    }
    result = verify_actor_proof(
        {"actor_id": "actor", "actor_proof": proof},
        None,  # type: ignore[arg-type]
        request_hash="a" * 64,
        audience="ledger",
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert not result.valid
    assert result.refusal == REFUSAL_UNREGISTERED

    registration = verify_credential_registration(
        None,  # type: ignore[arg-type]
        registration_public_keys={},
        expected_trust_root_id="actor-root",
        expected_public_key="00",
    )

    assert not registration.valid
    assert registration.errors == ["credential registration is not an object"]
