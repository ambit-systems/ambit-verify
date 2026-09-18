# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Revocation status types and the canonical signed-status attestation.

``RevocationStatus`` is the supplied-evidence type a revocation check yields,
with its freshness metadata. This module also holds the canonical bytes a
store's status signature covers and the Ed25519 verification of a retained
status attestation. SQLite storage and status signing stay private; a verifier
only reads and checks the retained artefacts.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .hashing import canonical_iso, canonical_json_bytes

REVOCATION_CONTEXT = "ambit.revocation.status.v1"


@dataclass(frozen=True)
class RevocationStatus:
    """Result of a revocation check with freshness metadata.

    ``revocation_epoch`` is the number of changes the answering store has made
    to its revocation set. It orders two answers from one store, which
    ``checked_at`` alone cannot do: a store restored from a backup states a
    fresh moment over a set it held earlier. Absent means the store keeps no
    counter, which is what every status stated before the field existed.
    """

    is_revoked: bool
    checked_at: datetime
    freshness_bound_ms: int | None = None
    source: str = "in_memory"
    verifiable: bool = False
    attestation: str | None = None
    trust_root_id: str | None = None
    revocation_epoch: int | None = None


# An unreachable store reports this via ``source``; never as staleness.
REVOCATION_SOURCE_UNAVAILABLE_SUFFIX = "_unavailable"


def revocation_source_unavailable(status: RevocationStatus) -> bool:
    """Return whether *status* reports that the backing store was unreachable."""
    return bool(status.source) and status.source.endswith(REVOCATION_SOURCE_UNAVAILABLE_SUFFIX)


def signed_status_bytes(payload: dict[str, object], *, context: str) -> bytes:
    """Return the context-bound canonical bytes for a store status signature."""
    return context.encode("utf-8") + b"." + canonical_json_bytes(payload)


def revocation_attestation_payload(status: RevocationStatus, jti: str) -> dict[str, object]:
    """Return the canonical payload covered by a revocation-status signature.

    ``revocation_epoch`` is stated only when the status states it, the pattern
    the cumulative status' ``scope`` pair already follows. A status from a store
    that predates the counter signs the same six fields it signed before, so
    every retained attestation of that generation still verifies. A status that
    states the epoch signs seven, so its signature covers the version of the set
    that answered: an attestation cannot be moved between the two.
    """
    payload: dict[str, object] = {
        "checked_at": canonical_iso(status.checked_at),
        "freshness_bound_ms": status.freshness_bound_ms,
        "is_revoked": status.is_revoked,
        "jti": jti,
        "source": status.source,
        "trust_root_id": status.trust_root_id,
    }
    if status.revocation_epoch is not None:
        payload["revocation_epoch"] = status.revocation_epoch
    return payload


def verify_revocation_attestation(status: RevocationStatus, jti: str, public_key: bytes) -> bool:
    """Verify the Ed25519 attestation carried by *status*."""
    if status.attestation is None or not status.attestation.startswith("ed25519:"):
        return False
    try:
        signature = base64.b64decode(status.attestation.removeprefix("ed25519:"), validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            signed_status_bytes(
                revocation_attestation_payload(status, jti), context=REVOCATION_CONTEXT
            ),
        )
    except InvalidSignature, ValueError:
        return False
    return True


__all__ = [
    "REVOCATION_CONTEXT",
    "REVOCATION_SOURCE_UNAVAILABLE_SUFFIX",
    "RevocationStatus",
    "revocation_attestation_payload",
    "revocation_source_unavailable",
    "signed_status_bytes",
    "verify_revocation_attestation",
]
