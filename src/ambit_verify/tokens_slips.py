# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Slip verification and the readers of a slip's signing key and root selector.

A slip is a signed delegation or approval token of the form
``payload.scheme:signature``. These functions check its signature against a
scheme-matched trust root and parse its verified claims. Signing, key
generation, and live status acquisition stay in the issuer's private engine;
this module only *verifies* an explicitly prefixed slip against supplied trust
roots and reads its verified claims.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .claim_shapes import (
    _APPROVAL_CLAIM_KEYS,
    _parse_dt,
    _required_str,
    parse_delegation_claims,
    parse_display_pair,
)
from .hashing import canonical_json_bytes, strict_json_loads
from .models import ApprovalClaims, DelegationClaims
from .tokens_ed25519 import verify_slip_ed25519
from .tokens_p256 import verify_slip_p256


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _normalize_claims(claims: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(claims)
    if "nbf" in normalized:
        normalized["nbf"] = _parse_dt(str(normalized["nbf"]))
    if "exp" in normalized:
        normalized["exp"] = _parse_dt(str(normalized["exp"]))
    return normalized


# Domain-separation contexts: a delegation slip, an approval slip, a ratification, a
# change record, a revocation request, and a ledger-head attestation sign over
# different bytes (the context is part of what is signed), so a signature minted for
# one purpose can never validate as another.
SLIP_CONTEXT_DELEGATION = "ambit.slip.delegation.v1"
SLIP_CONTEXT_APPROVAL = "ambit.slip.approval.v1"
SLIP_CONTEXT_RATIFICATION = "ambit.slip.ratification.v1"
SLIP_CONTEXT_CHANGE = "ambit.slip.change.v1"
SLIP_CONTEXT_REVOCATION = "ambit.slip.revocation.v1"
# An enforcement point signs its own registration record under this context to
# prove it holds the private half of the key that signs its ledger head. The
# separation keeps that signature from validating as any slip, and keeps a slip
# from validating as a proof of possession.
ENFORCEMENT_POINT_REGISTRATION_CONTEXT = "ambit.enforcement_point.registration.v1"

# The portable revocation set (revocation_set.py). Its own context, so a set
# signature can never be read as a status signature, and no signature moves
# between the two.
REVOCATION_SET_CONTEXT = "ambit.revocation.set.v1"
_ED25519_SIGNATURE_PREFIX = "ed25519:"
_P256_SIGNATURE_PREFIX = "p256:"


def _peek_trust_root_id(payload_b64: str) -> str | None:
    """Read the unverified root selector from a payload."""
    try:
        payload = _b64url_decode(payload_b64)
        peeked = strict_json_loads(payload.decode("utf-8"))
    except UnicodeDecodeError, ValueError, RecursionError:
        return None
    if not isinstance(peeked, dict) or canonical_json_bytes(peeked) != payload:
        return None
    trust_root_id = peeked.get("trust_root_id")
    return trust_root_id if isinstance(trust_root_id, str) and trust_root_id else None


def _resolve_trust_root(
    payload_b64: str,
    trust_roots: Mapping[str, Any] | None,
    *,
    scheme: str,
) -> str | None:
    """Resolve a scheme-matched public key from an unverified root selector.

    Reading the unverified payload only *selects* which key to check against; the signature
    verification that follows is authoritative.
    """
    if not trust_roots:
        return None
    trust_root_id = _peek_trust_root_id(payload_b64)
    if trust_root_id is None:
        return None
    record = trust_roots.get(trust_root_id)
    if not isinstance(record, Mapping) or record.get("scheme") != scheme:
        return None
    public_key_hex = record.get("public_key")
    if not isinstance(public_key_hex, str) or not public_key_hex:
        return None
    return public_key_hex


def _resolve_ed25519_public_key(
    payload_b64: str, public_keys: Mapping[str, str] | None
) -> bytes | None:
    """Resolve a raw Ed25519 key for non-slip artefacts such as policy attestations."""
    if not public_keys:
        return None
    trust_root_id = _peek_trust_root_id(payload_b64)
    public_key_hex = public_keys.get(trust_root_id) if trust_root_id is not None else None
    if not isinstance(public_key_hex, str) or not public_key_hex:
        return None
    try:
        return bytes.fromhex(public_key_hex)
    except ValueError:
        return None


def verified_slip_scheme(token: str) -> str | None:
    """Return the explicit scheme of a slip whose signature has already verified."""
    if token.count(".") != 1:
        return None
    signature = token.split(".", 1)[1]
    if signature.startswith(_ED25519_SIGNATURE_PREFIX):
        return "ed25519"
    if signature.startswith(_P256_SIGNATURE_PREFIX):
        return "p256"
    return None


def verified_slip_trust_root_id(token: str) -> str | None:
    """Return the ``trust_root_id`` of an explicitly schemed, verified slip.

    Call only after verification has succeeded: at that point the payload bytes
    are signature-covered, so reading a claim out of them is reading verified
    data rather than attacker-supplied data. The unverified peek in
    :func:`_resolve_ed25519_public_key` selects a key and must never be
    recorded as evidence — a forged slip could name any root it liked.

    Returns ``None`` for unsupported, unprefixed, or malformed slips.
    """
    if token.count(".") != 1:
        return None
    payload_b64, signature = token.split(".", 1)
    if not signature.startswith((_ED25519_SIGNATURE_PREFIX, _P256_SIGNATURE_PREFIX)):
        return None
    return _peek_trust_root_id(payload_b64)


def _canonical_key_identity(
    trust_roots: Mapping[str, Any] | None, trust_root_id: str | None
) -> str | None:
    """Return the canonical identity of the key registered under one trust-root id.

    Two trust-root ids that register the same key, under the same scheme,
    return the same identity -- this is what lets a caller compare keys rather
    than labels. A P-256 key normalises to its compressed point first, so an
    uncompressed and a compressed encoding of the same key agree. Returns
    ``None`` when the id does not resolve to a usable key, so a caller that
    treats ``None`` as "not equal" fails open; one that also refuses on
    ``None`` fails closed.
    """
    if trust_root_id is None or not trust_roots:
        return None
    record = trust_roots.get(trust_root_id)
    if not isinstance(record, Mapping):
        return None
    scheme = record.get("scheme")
    if scheme not in ("ed25519", "p256"):
        return None
    public_key_hex = record.get("public_key")
    if not isinstance(public_key_hex, str):
        return None
    try:
        public_key = bytes.fromhex(public_key_hex)
        if scheme == "p256":
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), public_key
            ).public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.CompressedPoint,
            )
    except ValueError:
        return None
    return f"{scheme}:{public_key.hex()}"


def _verified_slip_signer_id(token: str, trust_roots: Mapping[str, Any] | None) -> str | None:
    """Return a canonical verification-key identity after slip verification."""
    scheme = verified_slip_scheme(token)
    trust_root_id = verified_slip_trust_root_id(token)
    if scheme is None or trust_root_id is None:
        return None
    identity = _canonical_key_identity(trust_roots, trust_root_id)
    if identity is None or not identity.startswith(f"{scheme}:"):
        return None
    return identity


def _verify_slip(
    token: str,
    trust_roots: Mapping[str, Any] | None,
    *,
    context: str,
    allowed_schemes: frozenset[str],
) -> tuple[bool, dict[str, Any] | None]:
    """Verify an explicitly prefixed slip against a scheme-matched trust root."""
    if token.count(".") != 1:
        return False, None
    payload_b64, signature = token.split(".", 1)
    if signature.startswith(_ED25519_SIGNATURE_PREFIX) and "ed25519" in allowed_schemes:
        public_key_hex = _resolve_trust_root(payload_b64, trust_roots, scheme="ed25519")
        if public_key_hex is None:
            return False, None
        try:
            ed25519_public_key = bytes.fromhex(public_key_hex)
        except ValueError:
            return False, None
        return verify_slip_ed25519(token, ed25519_public_key, context=context)
    if signature.startswith(_P256_SIGNATURE_PREFIX) and "p256" in allowed_schemes:
        public_key_hex = _resolve_trust_root(payload_b64, trust_roots, scheme="p256")
        if public_key_hex is None:
            return False, None
        try:
            p256_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), bytes.fromhex(public_key_hex)
            )
        except ValueError:
            return False, None
        return verify_slip_p256(token, p256_public_key, context=context)
    return False, None


def parse_delegation(
    token: str, *, trust_roots: Mapping[str, Any] | None = None
) -> tuple[bool, DelegationClaims | None]:
    """Verify and parse a delegation token into ``DelegationClaims``."""
    ok, claims = _verify_slip(
        token,
        trust_roots,
        context=SLIP_CONTEXT_DELEGATION,
        allowed_schemes=frozenset({"ed25519"}),
    )
    if not ok or claims is None:
        return False, None
    try:
        # One shape definition, shared with prebuilt issuance: see
        # claim_shapes.parse_delegation_claims.
        return True, parse_delegation_claims(claims)
    except KeyError, TypeError, ValueError:
        return False, None


def parse_approval(
    token: str, *, trust_roots: Mapping[str, Any] | None = None
) -> tuple[bool, ApprovalClaims | None]:
    """Verify and parse an approval token into ``ApprovalClaims``."""
    ok, claims = _verify_slip(
        token,
        trust_roots,
        context=SLIP_CONTEXT_APPROVAL,
        allowed_schemes=frozenset({"ed25519", "p256"}),
    )
    if not ok or claims is None:
        return False, None
    try:
        normalized = _normalize_claims(claims)
        unknown = set(normalized) - _APPROVAL_CLAIM_KEYS
        if unknown:
            raise ValueError(f"approval has unsupported top-level keys: {sorted(unknown)}")
        display_digest, display_contract_version = parse_display_pair(normalized)
        approval = ApprovalClaims(
            jti=_required_str(normalized, "jti"),
            approver=_required_str(normalized, "approver"),
            request_fingerprint=_required_str(normalized, "request_fingerprint"),
            escalation_record_hash=_required_str(normalized, "escalation_record_hash"),
            nbf=normalized["nbf"],
            exp=normalized["exp"],
            display_digest=display_digest,
            display_contract_version=display_contract_version,
        )
        if not isinstance(approval.nbf, datetime) or not isinstance(approval.exp, datetime):
            raise ValueError("approval nbf/exp must be datetime")
        return True, approval
    except KeyError, TypeError, ValueError:
        return False, None


__all__ = [
    "ENFORCEMENT_POINT_REGISTRATION_CONTEXT",
    "REVOCATION_SET_CONTEXT",
    "SLIP_CONTEXT_APPROVAL",
    "SLIP_CONTEXT_CHANGE",
    "SLIP_CONTEXT_DELEGATION",
    "SLIP_CONTEXT_RATIFICATION",
    "SLIP_CONTEXT_REVOCATION",
    "parse_approval",
    "parse_delegation",
    "verified_slip_scheme",
    "verified_slip_trust_root_id",
]
