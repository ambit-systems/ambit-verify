# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Verification of the actor's proof that it holds its issued key.

A delegation slip names a subject. The actor proof binds that subject to a
registered P-256 key: the actor signs the request it is about to make, and the
verifier matches the key's registration to the subject the slip names.

The signed message covers four fields under a fixed domain prefix. The request
hash binds the proof to one request body, so a proof captured from one action
cannot be replayed on another. The nonce makes two proofs over the same request
distinguishable in evidence. The issue moment bounds how long a captured proof
stays usable. The audience names the evidence ledger the proof was made for.

The proof carries no authority. It answers "who is acting", never "what may be
done"; the slip still answers the second question, and every rule still runs.
Signing stays private; this module only checks a supplied proof against
configured registrations.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .credential_registration import (
    CREDENTIAL_KIND_WORKLOAD,
    credential_key_fingerprint,
    credential_registration_error,
)
from .hashing import canonical_json_bytes, hash_object
from .tokens_p256 import decode_signature_p256

ACTOR_PROOF_CONTEXT = "ambit-actor-proof/v2"
ACTOR_PROOF_SCHEME = "p256"
#: How long a proof stays usable, in seconds, on either side of the decision moment.
DEFAULT_FRESHNESS_SECONDS = 120

REFUSAL_MISSING = "actor_proof_missing"
REFUSAL_UNREGISTERED = "actor_proof_unregistered"
REFUSAL_SUBJECT_MISMATCH = "actor_proof_subject_mismatch"
REFUSAL_AUDIENCE_MISMATCH = "actor_proof_audience_mismatch"
REFUSAL_STALE = "actor_proof_stale"
REFUSAL_INVALID = "actor_proof_invalid"

_NONCE_LENGTH = 32
_FINGERPRINT_LENGTH = 64
_HEX_DIGITS = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class ActorProofVerification:
    """Result of checking one actor proof against the registrations in force.

    ``valid`` is ``True`` only when a proof was present and every check passed.
    ``present`` says whether the carrier offered a proof at all, so a caller
    can tell "no proof" from "a proof that failed". ``refusal`` is the reason
    string a refusing caller reports; ``detail`` states what would be admitted.
    """

    valid: bool
    present: bool
    refusal: str | None = None
    detail: str | None = None
    key_fingerprint: str | None = None
    nonce: str | None = None
    subject: str | None = None


def actor_proof_request_hash(envelope: Mapping[str, Any]) -> str:
    """Return the request hash for one wire envelope, without the holder proof.

    The hash is SHA-256 in lower-case hexadecimal over canonical JSON. A wire
    envelope carries the proof either as top-level ``actor_proof`` or as
    ``actor.proof``; the proof is removed before hashing.

    A Core ``AuthorityEnvelope`` v1/v2 can carry an outer transport seal that
    deliberately covers the holder proof. To avoid a proof/seal hash cycle,
    only its known outer ``seal`` member is normalized to ``null`` when
    present. Unsealed Core envelopes already carry ``seal: null``, so their
    hash is unchanged. Native HTTP/MCP envelopes, including any member named
    ``seal``, remain fully covered.

    Every other member remains covered. The client hashes the body it sends
    and the verifier hashes the retained body it received; neither reconstructs
    the other's projection.
    """
    payload = {key: value for key, value in envelope.items() if key != "actor_proof"}
    actor = payload.get("actor")
    if isinstance(actor, Mapping) and "proof" in actor:
        payload["actor"] = {key: value for key, value in actor.items() if key != "proof"}
    if payload.get("authority_envelope_version") in {"1", "2"} and "seal" in payload:
        payload["seal"] = None
    return hash_object(payload)


def actor_proof_message(request_hash: str, nonce: str, issued_at: str, audience: str) -> bytes:
    """Return the bytes an actor signs to prove it is making this request.

    The message is the domain prefix, a full stop, and unpadded URL-safe base64
    of the canonical JSON of the four fields — the same construction
    ``possession_message`` uses for an enrolment. Canonical JSON sorts the keys,
    so two parties that hold the same four values always build the same bytes.

    Args:
        request_hash: The hash of the wire envelope, from
            :func:`actor_proof_request_hash`.
        nonce: 32 lower-case hexadecimal characters, fresh per request.
        issued_at: The ISO-8601 UTC moment the actor signed.
        audience: The evidence ledger identifier the proof is made for.
    """
    payload = base64.urlsafe_b64encode(
        canonical_json_bytes(
            {
                "audience": audience,
                "issued_at": issued_at,
                "nonce": nonce,
                "request_hash": request_hash,
            }
        )
    ).rstrip(b"=")
    return ACTOR_PROOF_CONTEXT.encode("ascii") + b"." + payload


def _is_nonce(value: object) -> bool:
    return isinstance(value, str) and len(value) == _NONCE_LENGTH and set(value) <= _HEX_DIGITS


def _is_key_fingerprint(value: object) -> bool:
    return (
        isinstance(value, str) and len(value) == _FINGERPRINT_LENGTH and set(value) <= _HEX_DIGITS
    )


def _parse_moment(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _carried_proof(carrier: Any) -> Mapping[str, Any] | None:
    proof = getattr(carrier, "actor_proof", None)
    if proof is None and isinstance(carrier, Mapping):
        proof = carrier.get("actor_proof")
    return proof if isinstance(proof, Mapping) else None


def _carried_actor_id(carrier: Any) -> str:
    actor_id = getattr(carrier, "actor_id", None)
    if actor_id is None and isinstance(carrier, Mapping):
        actor_id = carrier.get("actor_id")
    return str(actor_id) if isinstance(actor_id, str) else ""


def _matching_registration(
    registrations: object, key_fingerprint: str
) -> tuple[str, Mapping[str, Any]] | None:
    """Return the independently shaped P-256 workload registration for a key."""
    if not isinstance(registrations, Mapping):
        return None
    for trust_root_id, root in registrations.items():
        if not isinstance(trust_root_id, str) or not isinstance(root, Mapping):
            continue
        public_key = root.get("public_key")
        registration = root.get("registration")
        if (
            root.get("scheme") != "p256"
            or not isinstance(public_key, str)
            or not isinstance(registration, Mapping)
            or registration.get("credential_kind") != CREDENTIAL_KIND_WORKLOAD
            or registration.get("scheme") != "p256"
            or registration.get("public_key") != public_key
            or registration.get("key_fingerprint") != key_fingerprint
        ):
            continue
        try:
            if credential_key_fingerprint(public_key) != key_fingerprint:
                continue
        except ValueError:
            continue
        return trust_root_id, registration
    return None


def _refuse(
    reason: str, detail: str, *, key_fingerprint: str | None = None, nonce: str | None = None
) -> ActorProofVerification:
    return ActorProofVerification(
        valid=False,
        present=True,
        refusal=reason,
        detail=detail,
        key_fingerprint=key_fingerprint,
        nonce=nonce,
    )


def _registration_refusal(
    registrations: Mapping[str, Any],
    trust_root_id: str,
    registration_public_keys: Mapping[str, str] | None,
    now: datetime,
    carried_fingerprint: str,
    carried_nonce: str,
) -> ActorProofVerification | None:
    """Refuse unless a configured organisational root countersigns enrolment."""
    registration_error = credential_registration_error(
        registrations,
        trust_root_id,
        registration_public_keys=registration_public_keys,
        evaluation_time=now,
    )
    if registration_error is not None:
        return _refuse(
            REFUSAL_UNREGISTERED,
            f"the workload registration did not verify ({registration_error}); a request "
            "is admitted when the enrolment record is countersigned by a configured "
            "organisational root",
            key_fingerprint=carried_fingerprint,
            nonce=carried_nonce,
        )
    return None


def _issue_moment_refusal(
    proof: Mapping[str, Any],
    now: datetime,
    freshness_seconds: int,
    carried_fingerprint: str,
    carried_nonce: str,
) -> ActorProofVerification | None:
    """Refuse a proof with no timezone-aware issue moment, or one outside the freshness bound."""
    issued_at = _parse_moment(proof.get("issued_at"))
    if issued_at is None:
        return _refuse(
            REFUSAL_INVALID,
            "the proof states no timezone-aware issue moment; a proof carries an ISO-8601 "
            "UTC moment",
            key_fingerprint=carried_fingerprint,
            nonce=carried_nonce,
        )
    if abs((now.astimezone(UTC) - issued_at).total_seconds()) > freshness_seconds:
        return _refuse(
            REFUSAL_STALE,
            f"the proof was signed outside the {freshness_seconds} second freshness bound; a "
            "request is admitted when the actor signs it at the moment it makes it",
            key_fingerprint=carried_fingerprint,
            nonce=carried_nonce,
        )
    return None


def verify_actor_proof(
    envelope_or_input: Any,
    registrations: Mapping[str, Any],
    *,
    request_hash: str,
    audience: str,
    now: datetime,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
    registration_public_keys: Mapping[str, str] | None = None,
) -> ActorProofVerification:
    """Check a hardened workload holder proof against independently enrolled roots.

    ``registration_public_keys`` must contain the organisational countersigning
    roots for every current workload proof. Historical receipt contracts are
    represented by evidence schemas that do not carry a holder proof; a present
    proof is never accepted merely because an unverified registration mapping
    names its fingerprint.
    """
    if not isinstance(registrations, Mapping):
        return _refuse(
            REFUSAL_UNREGISTERED,
            "workload registrations are not an object",
        )
    proof = _carried_proof(envelope_or_input)
    if proof is None:
        return ActorProofVerification(
            valid=False,
            present=False,
            refusal=REFUSAL_MISSING,
            detail=(
                "the actor carried no proof; a request is admitted when the actor signs the "
                "hash of its own request with the registered key its slip was issued to"
            ),
        )

    key_fingerprint = proof.get("key_fingerprint")
    nonce = proof.get("nonce")
    if (
        proof.get("scheme") != ACTOR_PROOF_SCHEME
        or not _is_key_fingerprint(key_fingerprint)
        or not _is_nonce(nonce)
    ):
        return _refuse(
            REFUSAL_INVALID,
            "the proof is malformed; a proof states scheme p256, a 64-hex key fingerprint, "
            "and a 32-hex nonce",
        )
    carried_nonce = str(nonce)
    carried_fingerprint = str(key_fingerprint)

    matched = _matching_registration(registrations, carried_fingerprint)
    if matched is None:
        return _refuse(
            REFUSAL_UNREGISTERED,
            "no workload registration records this key; a request is admitted when the "
            "signing key is enrolled as a workload credential of this deployment",
            key_fingerprint=carried_fingerprint,
            nonce=carried_nonce,
        )
    trust_root_id, registration = matched

    refusal = _registration_refusal(
        registrations,
        trust_root_id,
        registration_public_keys,
        now,
        carried_fingerprint,
        carried_nonce,
    )
    if refusal is not None:
        return refusal

    subject = registration.get("subject")
    actor_id = _carried_actor_id(envelope_or_input)
    if not isinstance(subject, str) or subject != actor_id:
        return _refuse(
            REFUSAL_SUBJECT_MISMATCH,
            f"the key is registered to {subject!r} and the request claims {actor_id!r}; a "
            "request is admitted when the acting key is registered to the actor it acts as",
            key_fingerprint=carried_fingerprint,
            nonce=carried_nonce,
        )

    carried_audience = proof.get("audience")
    if carried_audience != audience:
        return _refuse(
            REFUSAL_AUDIENCE_MISMATCH,
            f"the proof names {carried_audience!r} and this deployment records to "
            f"{audience!r}; a request is admitted when the proof names the evidence ledger "
            "the decision is written to",
            key_fingerprint=carried_fingerprint,
            nonce=carried_nonce,
        )

    refusal = _issue_moment_refusal(
        proof, now, freshness_seconds, carried_fingerprint, carried_nonce
    )
    if refusal is not None:
        return refusal

    if not _signature_holds(
        proof, registration, request_hash, carried_nonce, str(carried_audience)
    ):
        return _refuse(
            REFUSAL_INVALID,
            "the signature does not verify against the registered key over this request; a "
            "request is admitted when the actor signs the hash of the request it sends",
            key_fingerprint=carried_fingerprint,
            nonce=carried_nonce,
        )

    return ActorProofVerification(
        valid=True,
        present=True,
        key_fingerprint=carried_fingerprint,
        nonce=carried_nonce,
        subject=subject,
    )


def _signature_holds(
    proof: Mapping[str, Any],
    registration: Mapping[str, Any],
    request_hash: str,
    nonce: str,
    audience: str,
) -> bool:
    """Return whether the proof's signature verifies under the registration's public key."""
    signature = proof.get("signature")
    public_key_hex = registration.get("public_key")
    if not isinstance(signature, str) or not isinstance(public_key_hex, str):
        return False
    der_signature = decode_signature_p256(signature)
    if der_signature is None:
        return False
    message = actor_proof_message(request_hash, nonce, str(proof.get("issued_at")), audience)
    try:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(public_key_hex)
        )
        public_key.verify(der_signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature, ValueError:
        return False
    return True


__all__ = [
    "ACTOR_PROOF_CONTEXT",
    "ACTOR_PROOF_SCHEME",
    "DEFAULT_FRESHNESS_SECONDS",
    "REFUSAL_AUDIENCE_MISMATCH",
    "REFUSAL_INVALID",
    "REFUSAL_MISSING",
    "REFUSAL_STALE",
    "REFUSAL_SUBJECT_MISMATCH",
    "REFUSAL_UNREGISTERED",
    "ActorProofVerification",
    "actor_proof_message",
    "actor_proof_request_hash",
    "verify_actor_proof",
]
