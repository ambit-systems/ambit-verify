# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Head attestations: the signed head a verifier checks the chain against.

A bare hash chain pins only its genesis. A party with write access to the
ledger file can remove the most recent records, or replace them with a new
tail, and ``verify_chain`` still passes. A head attestation is the writer's
signature over the current head (``max_seq`` and ``head_record_hash``). A
verifier that holds the matching verification material detects a removed
tail (the head sits behind the attested seq) and a replaced tail (the record
at the attested seq does not hash to the attested value).

Two signature forms exist. ``ed25519:<base64>`` is verified with the writer's
public key by ``Ed25519HeadVerifier``; the writer keeps the private key. The
``hmac-sha256:<hex>`` form is verified with the shared secret by
``HmacHeadVerifier``; a party that holds the secret can also produce an
attestation, so that form proves nothing against the writer.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .hashing import canonical_json_bytes


@dataclass(frozen=True)
class HeadAttestation:
    """A signed assertion of a ledger head.

    Attributes:
        max_seq: Sequence number of the most recent record when the head was
            attested; 0 for an empty ledger.
        head_record_hash: ``record_hash`` of the record at ``max_seq``, or the
            genesis hash when ``max_seq`` is 0.
        recorded_at: UTC ISO-8601 timestamp of the attestation.
        trust_root_id: Name of the key that signed the attestation.
        signature: ``"ed25519:<base64>"`` or ``"hmac-sha256:<hex>"``.
        ledger_id: Name of the attested ledger. A witness sets it so the
            signed payload names the ledger whose head it saw.
    """

    max_seq: int
    head_record_hash: str
    recorded_at: str
    trust_root_id: str
    signature: str
    ledger_id: str | None = None


def attestation_payload(
    max_seq: int,
    head_record_hash: str,
    recorded_at: str,
    trust_root_id: str,
    ledger_id: str | None = None,
) -> bytes:
    """Build the bytes a head attestation signs over.

    Args:
        max_seq: Sequence number of the attested head.
        head_record_hash: ``record_hash`` of the record at ``max_seq``.
        recorded_at: UTC ISO-8601 timestamp of the attestation.
        trust_root_id: Name of the signing key.
        ledger_id: Name of the attested ledger; omitted from the payload when
            empty or ``None``.

    Returns:
        Canonical JSON bytes of the named fields.
    """
    payload = {
        "head_record_hash": head_record_hash,
        "max_seq": max_seq,
        "recorded_at": recorded_at,
        "trust_root_id": trust_root_id,
    }
    if ledger_id:
        payload["ledger_id"] = ledger_id
    return canonical_json_bytes(payload)


# The six keys a witness record and a checkpoint carry for an attestation.
ATTESTATION_BLOCK_KEYS = frozenset(
    {"max_seq", "head_record_hash", "ledger_id", "recorded_at", "trust_root_id", "signature"}
)


def attestation_block(attestation: HeadAttestation) -> dict[str, Any]:
    """Serialise *attestation* as the six-key block a checkpoint hashes.

    Args:
        attestation: The attestation to serialise.

    Returns:
        A dict with exactly the keys in ``ATTESTATION_BLOCK_KEYS``.
    """
    return {
        "max_seq": attestation.max_seq,
        "head_record_hash": attestation.head_record_hash,
        "ledger_id": attestation.ledger_id,
        "recorded_at": attestation.recorded_at,
        "trust_root_id": attestation.trust_root_id,
        "signature": attestation.signature,
    }


def checkpoint_payload(
    *,
    seq: int,
    record_hash: str,
    attestation_hash: str,
    witness_record_hash: str,
) -> bytes:
    """Build the bytes a checkpoint countersignature signs over.

    The holder signs digests, not the ledger: the head the checkpoint names,
    the hash of the writer's attestation block, and the hash of the witness
    record.

    Args:
        seq: Sequence number of the checkpointed record.
        record_hash: ``record_hash`` of the checkpointed record.
        attestation_hash: ``hash_object`` of the writer's attestation block.
        witness_record_hash: ``record_hash`` of the witness record.

    Returns:
        Canonical JSON bytes of the four fields.
    """
    return canonical_json_bytes(
        {
            "attestation_hash": attestation_hash,
            "record_hash": record_hash,
            "seq": seq,
            "witness_record_hash": witness_record_hash,
        }
    )


@runtime_checkable
class CheckpointVerifier(Protocol):
    """Verifies a checkpoint countersignature."""

    def verify_countersignature(self, payload: bytes, signature: str) -> bool:
        """Return True when *signature* over *payload* is the holder's."""
        ...


@runtime_checkable
class HeadVerifier(Protocol):
    """Verifies a head attestation."""

    def verify_head(self, attestation: HeadAttestation) -> bool:
        """Return True when *attestation* was signed by this trust root."""
        ...


class HmacHeadVerifier:
    """Verifies ``hmac-sha256`` head attestations with the shared secret.

    The secret that verifies also signs, so a pass proves only that the
    attestation was made by a party that holds the secret. Use
    ``Ed25519HeadVerifier`` when the writer must not be able to attest a
    rewritten head.

    Args:
        secret: The shared secret the writer attests with.
        trust_root_id: The trust root id the attestation must name.

    Raises:
        ValueError: If *secret* or *trust_root_id* is empty.
    """

    def __init__(self, *, secret: str, trust_root_id: str) -> None:
        if not secret:
            raise ValueError("secret must be non-empty")
        if not trust_root_id:
            raise ValueError("trust_root_id must be non-empty")
        self._secret = secret
        self.trust_root_id = trust_root_id

    def verify_head(self, attestation: HeadAttestation) -> bool:
        """Return True when *attestation* was made with this secret and trust root.

        Args:
            attestation: The attestation to check.

        Returns:
            True on a matching trust root id and HMAC; False otherwise.
        """
        if attestation.trust_root_id != self.trust_root_id:
            return False
        signature_prefix = "hmac-sha256:"
        encoded = attestation.signature
        if (
            not isinstance(encoded, str)
            or not encoded.startswith(signature_prefix)
            or len(encoded) != len(signature_prefix) + 64
            or any(
                character not in "0123456789abcdef"
                for character in encoded[len(signature_prefix) :]
            )
        ):
            return False
        digest = hmac.new(
            self._secret.encode("utf-8"),
            attestation_payload(
                attestation.max_seq,
                attestation.head_record_hash,
                attestation.recorded_at,
                attestation.trust_root_id,
                attestation.ledger_id,
            ),
            "sha256",
        ).hexdigest()
        return hmac.compare_digest(f"{signature_prefix}{digest}", encoded)


__all__ = [
    "CheckpointVerifier",
    "HeadAttestation",
    "HeadVerifier",
    "HmacHeadVerifier",
    "attestation_block",
    "attestation_payload",
    "checkpoint_payload",
]
