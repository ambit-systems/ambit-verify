# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Ed25519 verifiers for head attestations and checkpoint countersignatures.

The writer, the witness, and the holder each keep a private key. This module
holds only the public-key side. A party with write access to a ledger file but
without the private key cannot produce an attestation these verifiers accept,
so a removed or replaced tail is detected even when the ledger's own sidecar
was rewritten with it.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .head_attestation import HeadAttestation, attestation_payload

_SIGNATURE_PREFIX = "ed25519:"


def _decode(signature: str) -> bytes | None:
    """Return the raw signature bytes, or None when *signature* is malformed."""
    if not signature.startswith(_SIGNATURE_PREFIX):
        return None
    try:
        encoded = signature[len(_SIGNATURE_PREFIX) :].encode("ascii")
        # binascii.Error (malformed base64) subclasses ValueError.
        return base64.b64decode(encoded, validate=True)
    except UnicodeEncodeError, ValueError:
        return None


class Ed25519HeadVerifier:
    """Verifies ``ed25519`` head attestations with a public key.

    Args:
        public_key: Raw 32-byte Ed25519 public key.
        trust_root_id: The trust root id the attestation must name.

    Raises:
        ValueError: If *trust_root_id* is empty or *public_key* is not a valid
            32-byte Ed25519 public key.
    """

    def __init__(self, *, public_key: bytes, trust_root_id: str) -> None:
        if not trust_root_id:
            raise ValueError("trust_root_id must be non-empty")
        self._public = Ed25519PublicKey.from_public_bytes(public_key)
        self.trust_root_id = trust_root_id

    def verify_head(self, attestation: HeadAttestation) -> bool:
        """Return True when *attestation* carries a valid signature for this key.

        Args:
            attestation: The attestation to check.

        Returns:
            True on a matching trust root id and a valid signature. False on a
            mismatch, a malformed signature, or an invalid signature.
        """
        if attestation.trust_root_id != self.trust_root_id:
            return False
        signature = _decode(attestation.signature)
        if signature is None:
            return False
        payload = attestation_payload(
            attestation.max_seq,
            attestation.head_record_hash,
            attestation.recorded_at,
            attestation.trust_root_id,
            attestation.ledger_id,
        )
        try:
            self._public.verify(signature, payload)
        except InvalidSignature:
            return False
        return True


class Ed25519CountersignVerifier:
    """Verifies ``ed25519`` checkpoint countersignatures with a public key.

    The countersignature binds to the key alone; no trust root id is named.

    Args:
        public_key: Raw 32-byte Ed25519 public key.

    Raises:
        ValueError: If *public_key* is not a valid 32-byte Ed25519 public key.
    """

    def __init__(self, *, public_key: bytes) -> None:
        self._public = Ed25519PublicKey.from_public_bytes(public_key)

    def verify_countersignature(self, payload: bytes, signature: str) -> bool:
        """Return True when *signature* over *payload* verifies under this key.

        Args:
            payload: The bytes from ``checkpoint_payload``.
            signature: ``"ed25519:<base64>"``.

        Returns:
            True on a valid signature; False on a malformed or invalid one.
        """
        raw = _decode(signature)
        if raw is None:
            return False
        try:
            self._public.verify(raw, payload)
        except InvalidSignature:
            return False
        return True


__all__ = [
    "Ed25519CountersignVerifier",
    "Ed25519HeadVerifier",
]
