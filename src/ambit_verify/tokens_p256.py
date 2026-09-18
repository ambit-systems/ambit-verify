# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Canonical P-256 approval slips for PIV and other pre-hashed signers.

The wire form is ``payload_b64.p256:<base64(raw_r || raw_s)>``.  The payload
uses the same unpadded URL-safe base64 convention as Ed25519 slips; the
signature uses padded standard base64.  PIV signs a SHA-256 digest, so the
protocol digest is defined here and hardware adapters must pass it with
``Prehashed(SHA256)`` rather than hashing it a second time.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)

from .hashing import canonical_json_bytes, strict_json_loads

SIGNATURE_PREFIX = "p256:"
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_SCALAR_SIZE = 32
_RAW_SIGNATURE_SIZE = _SCALAR_SIZE * 2


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def slip_digest_p256(context: str, payload_b64: str) -> bytes:
    """Return ``SHA256(ASCII(context) || b'.' || ASCII(payload_b64))``."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(context.encode("ascii"))
    digest.update(b".")
    digest.update(payload_b64.encode("ascii"))
    return digest.finalize()


def _canonical_raw_signature(der_signature: bytes) -> bytes:
    """Convert a DER ECDSA signature to fixed-width raw, normalised low-S form."""
    r, s = decode_dss_signature(der_signature)
    if not (1 <= r < P256_ORDER and 1 <= s < P256_ORDER):
        raise ValueError("P-256 signature scalar out of range")
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    return r.to_bytes(_SCALAR_SIZE, "big") + s.to_bytes(_SCALAR_SIZE, "big")


def encode_signature_p256(der_signature: bytes) -> str:
    """Return the canonical wire form of a device-returned DER ECDSA signature.

    The wire form is ``p256:<base64(raw_r || raw_s)>`` in padded standard
    base64 over exactly 64 low-S normalised bytes. It is the one representation
    every P-256 artefact in this package carries.
    """
    raw = _canonical_raw_signature(der_signature)
    return SIGNATURE_PREFIX + base64.b64encode(raw).decode("ascii")


def decode_signature_p256(signature: str) -> bytes | None:
    """Return the DER form of a canonical P-256 wire signature, or ``None``.

    Rejects every representation but the canonical one: the ``p256:`` prefix,
    padded standard base64 that re-encodes to the same string, exactly 64 raw
    bytes, and scalars in range with ``s`` in the low half. A signature that
    only differs from a valid one in its encoding is refused rather than
    normalised, so one signature has one wire form.
    """
    if not signature.startswith(SIGNATURE_PREFIX):
        return None
    signature_b64 = signature[len(SIGNATURE_PREFIX) :]
    try:
        raw = base64.b64decode(signature_b64, validate=True)
    except ValueError:
        return None
    if len(raw) != _RAW_SIGNATURE_SIZE:
        return None
    # Require one wire representation: padded standard base64 over exactly 64 raw bytes.
    if base64.b64encode(raw).decode("ascii") != signature_b64:
        return None
    r = int.from_bytes(raw[:_SCALAR_SIZE], "big")
    s = int.from_bytes(raw[_SCALAR_SIZE:], "big")
    if not (1 <= r < P256_ORDER and 1 <= s <= P256_ORDER // 2):
        return None
    return encode_dss_signature(r, s)


def encode_slip_p256(payload_b64: str, der_signature: bytes) -> str:
    """Build a canonical P-256 slip from a payload and device-returned DER signature."""
    return f"{payload_b64}.{encode_signature_p256(der_signature)}"


def prepare_slip_payload_p256(claims: Mapping[str, Any], *, trust_root_id: str) -> str:
    """Return the canonical payload segment shared by software and hardware signers."""
    if not trust_root_id:
        raise ValueError("trust_root_id must be non-empty")
    return _b64url_encode(canonical_json_bytes({**dict(claims), "trust_root_id": trust_root_id}))


def verify_slip_p256(
    token: str,
    public_key: ec.EllipticCurvePublicKey,
    *,
    context: str,
) -> tuple[bool, dict[str, Any] | None]:
    """Verify a canonical low-S P-256 slip and return its claims."""
    if token.count(".") != 1 or not isinstance(public_key.curve, ec.SECP256R1):
        return False, None
    payload_b64, encoded = token.split(".", 1)
    try:
        payload_bytes = _b64url_decode(payload_b64)
    except ValueError:
        return False, None
    if _b64url_encode(payload_bytes) != payload_b64:
        return False, None
    der_signature = decode_signature_p256(encoded)
    if der_signature is None:
        return False, None
    try:
        public_key.verify(
            der_signature,
            slip_digest_p256(context, payload_b64),
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
    except InvalidSignature, ValueError:
        return False, None
    try:
        payload = _b64url_decode(payload_b64)
        claims = strict_json_loads(payload.decode("utf-8"))
    except UnicodeDecodeError, ValueError, RecursionError:
        return False, None
    if not isinstance(claims, dict) or canonical_json_bytes(claims) != payload:
        return False, None
    return True, claims


__all__ = [
    "P256_ORDER",
    "SIGNATURE_PREFIX",
    "decode_signature_p256",
    "encode_signature_p256",
    "encode_slip_p256",
    "prepare_slip_payload_p256",
    "slip_digest_p256",
    "verify_slip_p256",
]
