# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Ed25519 verifiers.

With a shared secret, anyone who can verify can also sign. The Ed25519 split
keeps the private key with the writer and verifies with the public key only,
so a party with write access to the ledger but without the private key cannot
produce an attestation the verifier accepts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ambit_verify import (
    Ed25519CountersignVerifier,
    Ed25519HeadVerifier,
    HeadAttestation,
    verify_chain,
)
from ledger_fixtures import (
    Ed25519HeadSigner,
    append,
    attest_head,
    filled,
    generate_keypair,
    score,
    truncate,
)


def _pair(trust_root_id: str = "customer-1") -> tuple[Ed25519HeadSigner, Ed25519HeadVerifier]:
    private_key, public_key = generate_keypair()
    return (
        Ed25519HeadSigner(private_key=private_key, trust_root_id=trust_root_id),
        Ed25519HeadVerifier(public_key=public_key, trust_root_id=trust_root_id),
    )


def test_sign_private_verify_public_intact(tmp_path: Path) -> None:
    signer, verifier = _pair()
    path = filled(tmp_path / "ledger.jsonl", 5)
    attestation = attest_head(path, signer)
    assert attestation.signature.startswith("ed25519:")

    assert verify_chain(path, verifier=verifier) == (True, 5, None)


def test_truncation_detected_with_public_key_only(tmp_path: Path) -> None:
    signer, verifier = _pair()
    path = filled(tmp_path / "ledger.jsonl", 5)
    attest_head(path, signer)
    truncate(path, 4)

    ok, _, error = verify_chain(path, verifier=verifier)
    assert not ok
    assert error is not None and "truncat" in error.lower()


def test_append_after_attestation_fails_as_stale_head(tmp_path: Path) -> None:
    signer, verifier = _pair()
    path = filled(tmp_path / "ledger.jsonl", 3)
    attest_head(path, signer)
    append(path, score(4))

    ok, _, error = verify_chain(path, verifier=verifier)
    assert not ok
    assert error is not None and "stale" in error.lower()


def test_forge_after_truncate_detected(tmp_path: Path) -> None:
    signer, verifier = _pair()
    path = filled(tmp_path / "ledger.jsonl", 5)
    attest_head(path, signer)
    truncate(path, 4)
    append(path, score(99))

    ok, _, error = verify_chain(path, verifier=verifier)
    assert not ok
    assert error is not None and "forg" in error.lower()


def test_attacker_without_private_key_cannot_forge(tmp_path: Path) -> None:
    signer, verifier = _pair()
    path = filled(tmp_path / "ledger.jsonl", 5)
    attest_head(path, signer)

    truncate(path, 4)
    attacker_private, _ = generate_keypair()
    attest_head(path, Ed25519HeadSigner(private_key=attacker_private, trust_root_id="customer-1"))

    ok, _, error = verify_chain(path, verifier=verifier)
    assert not ok
    assert error is not None and "invalid" in error.lower()


def test_wrong_public_key_rejected(tmp_path: Path) -> None:
    signer, _ = _pair()
    _, other_public = generate_keypair()
    verifier = Ed25519HeadVerifier(public_key=other_public, trust_root_id="customer-1")

    path = filled(tmp_path / "ledger.jsonl", 3)
    attest_head(path, signer)

    ok, _, error = verify_chain(path, verifier=verifier)
    assert not ok
    assert error is not None


def test_trust_root_mismatch_detected(tmp_path: Path) -> None:
    private_key, public_key = generate_keypair()
    signer = Ed25519HeadSigner(private_key=private_key, trust_root_id="customer-1")
    verifier = Ed25519HeadVerifier(public_key=public_key, trust_root_id="customer-2")

    path = filled(tmp_path / "ledger.jsonl", 3)
    attest_head(path, signer)

    ok, _, error = verify_chain(path, verifier=verifier)
    assert not ok
    assert error is not None


@pytest.mark.parametrize(
    "signature",
    ["hmac-sha256:00", "ed25519:not-base64!", "ed25519:AAAA", ""],
)
def test_malformed_signature_is_refused_not_raised(signature: str) -> None:
    _, verifier = _pair()
    attestation = HeadAttestation(
        max_seq=1,
        head_record_hash="0" * 64,
        recorded_at="2026-06-15T00:00:00.000Z",
        trust_root_id="customer-1",
        signature=signature,
    )
    assert verifier.verify_head(attestation) is False


def test_head_verifier_requires_a_trust_root_id() -> None:
    _, public_key = generate_keypair()
    with pytest.raises(ValueError, match="trust_root_id"):
        Ed25519HeadVerifier(public_key=public_key, trust_root_id="")


def test_verifiers_reject_a_malformed_public_key() -> None:
    with pytest.raises(ValueError):
        Ed25519HeadVerifier(public_key=b"\x00" * 31, trust_root_id="customer-1")
    with pytest.raises(ValueError):
        Ed25519CountersignVerifier(public_key=b"\x00" * 31)


@pytest.mark.parametrize(
    "signature",
    ["hmac-sha256:00", "ed25519:not-base64!", "ed25519:AAAA", ""],
)
def test_malformed_countersignature_is_refused_not_raised(signature: str) -> None:
    _, public_key = generate_keypair()
    verifier = Ed25519CountersignVerifier(public_key=public_key)
    assert verifier.verify_countersignature(b"payload", signature) is False
