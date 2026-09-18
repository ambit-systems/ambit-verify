# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Retained revocation-status evidence: the artefact, its hash, and its reading.

A ratification binds one signed revocation status per ratifier identifier, and a
revocation outcome retains the status that says a grant is revoked. Both keep
the same artefact: the fields of a ``RevocationStatus`` and the identifier they
answer for. This module builds that artefact, hashes it, reads it back into a
status, resolves the key a status is checked under, and finds the epoch
regression that a store wound back between two reads leaves in a set of them.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .claim_shapes import _parse_dt
from .hashing import canonical_iso, canonical_json_bytes, sha256_hex
from .revocation_types import RevocationStatus, signed_status_bytes

CUMULATIVE_STATUS_CONTEXT = "ambit.cumulative.status.v1"


def verify_cumulative_status_payload(
    payload: Mapping[str, Any],
    attestation: str,
    *,
    public_key: bytes,
) -> bool:
    """Verify one retained cumulative-status payload without rebuilding it.

    The private producer owns the payload grammar.  This verifier deliberately
    signs exactly the retained mapping, so adding a producer field cannot be
    silently omitted by an independently reconstructed public projection.
    """
    if (
        not isinstance(payload, Mapping)
        or not isinstance(attestation, str)
        or not attestation.startswith("ed25519:")
        or not isinstance(public_key, bytes)
        or len(public_key) != 32
    ):
        return False
    try:
        signature = base64.b64decode(attestation.removeprefix("ed25519:"), validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            signed_status_bytes(dict(payload), context=CUMULATIVE_STATUS_CONTEXT),
        )
    except InvalidSignature, TypeError, ValueError, OverflowError:
        return False
    return True


def status_artefact(status: RevocationStatus, jti: str) -> dict[str, Any]:
    """Return the retainable copy of one signed revocation status.

    ``revocation_epoch`` is stated only when the status states it, the same
    rule the signed payload follows. An artefact of the generation before the
    counter therefore keeps the eight keys it always carried, and the hash
    every retained ratification and revocation record binds it by.
    """
    artefact: dict[str, Any] = {
        "jti": jti,
        "is_revoked": status.is_revoked,
        "checked_at": canonical_iso(status.checked_at),
        "freshness_bound_ms": status.freshness_bound_ms,
        "source": status.source,
        "verifiable": status.verifiable,
        "attestation": status.attestation,
        "trust_root_id": status.trust_root_id,
    }
    if status.revocation_epoch is not None:
        artefact["revocation_epoch"] = status.revocation_epoch
    return artefact


def epoch_regression(artefacts: Sequence[Mapping[str, Any]]) -> str | None:
    """Return the identifier whose status states an epoch below one already pinned.

    One set of status evidence is read from one store, in sequence. That store's
    counter never falls, so the epochs across the set never fall either. A later
    status below an earlier one proves the store was wound back between the two
    reads -- a backup restored over a set that had moved on, answering as though
    the revocations since were never made.

    Artefacts that state no epoch are compared with nothing: a store that
    predates the counter states none, and its evidence keeps the meaning it had.
    """
    highest: int | None = None
    for artefact in artefacts:
        epoch = artefact.get("revocation_epoch")
        if not isinstance(epoch, int) or isinstance(epoch, bool):
            continue
        if highest is not None and epoch < highest:
            return str(artefact["jti"])
        highest = epoch
    return None


def status_artefact_hash(artefact: Mapping[str, Any]) -> str:
    """Return the SHA-256 over one status artefact's canonical bytes."""
    return sha256_hex(canonical_json_bytes(dict(artefact)))


def _status_from_evidence(artefact: Mapping[str, Any]) -> RevocationStatus:
    required = {
        "jti",
        "is_revoked",
        "checked_at",
        "freshness_bound_ms",
        "source",
        "verifiable",
        "attestation",
        "trust_root_id",
    }
    if set(artefact) not in (required, required | {"revocation_epoch"}):
        raise ValueError("status evidence has unsupported or missing fields")
    if not isinstance(artefact["jti"], str) or not artefact["jti"]:
        raise ValueError("status evidence jti is invalid")
    if not isinstance(artefact["is_revoked"], bool):
        raise ValueError("status evidence is_revoked is invalid")
    if not isinstance(artefact["checked_at"], str):
        raise ValueError("status evidence checked_at is invalid")
    freshness = artefact["freshness_bound_ms"]
    if not isinstance(freshness, int) or isinstance(freshness, bool) or freshness < 0:
        raise ValueError("status evidence freshness_bound_ms is invalid")
    if not isinstance(artefact["source"], str) or not artefact["source"]:
        raise ValueError("status evidence source is invalid")
    if not isinstance(artefact["verifiable"], bool):
        raise ValueError("status evidence verifiable is invalid")
    if not isinstance(artefact["attestation"], str) or not artefact["attestation"]:
        raise ValueError("status evidence attestation is invalid")
    if not isinstance(artefact["trust_root_id"], str) or not artefact["trust_root_id"]:
        raise ValueError("status evidence trust_root_id is invalid")
    epoch = artefact.get("revocation_epoch")
    if epoch is not None and (not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0):
        raise ValueError("status evidence revocation_epoch is invalid")
    return RevocationStatus(
        is_revoked=artefact["is_revoked"],
        checked_at=_parse_dt(str(artefact["checked_at"])),
        freshness_bound_ms=freshness,
        source=artefact["source"],
        verifiable=artefact["verifiable"],
        attestation=artefact["attestation"],
        trust_root_id=artefact["trust_root_id"],
        revocation_epoch=epoch,
    )


def _status_public_key(roots: Mapping[str, Any], trust_root_id: str | None) -> bytes | None:
    configured = roots.get(trust_root_id) if trust_root_id is not None else None
    if isinstance(configured, Mapping):
        configured = configured.get("public_key")
    try:
        key = bytes.fromhex(configured) if isinstance(configured, str) else configured
    except ValueError:
        return None
    return key if isinstance(key, bytes) and len(key) == 32 else None


__all__ = [
    "CUMULATIVE_STATUS_CONTEXT",
    "_status_from_evidence",
    "_status_public_key",
    "epoch_regression",
    "status_artefact",
    "status_artefact_hash",
    "verify_cumulative_status_payload",
]
