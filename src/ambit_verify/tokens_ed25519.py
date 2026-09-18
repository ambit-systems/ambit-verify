# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Ed25519 slip and envelope-seal verification.

The private signing key is held by the issuer; verification needs only the
public key. A verifier holding only the public key can *check* a slip or seal
but cannot *mint* one.

Domain separation is explicit in the signed bytes: each signature is prefixed
by a context naming its purpose. A delegation signature, an approval signature,
a ledger-head attestation, and an envelope seal therefore sign over different
bytes and can never cross-validate.

``cryptography`` is a base dependency because asymmetric verification is
mandatory for every delegation and approval slip.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .hashing import canonical_json_bytes, strict_json_loads

SIGNATURE_PREFIX = "ed25519:"
SEAL_CONTEXT = "ambit.envelope.seal.v1"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _signed_bytes(context: str, payload_b64: str) -> bytes:
    """Return the domain-separated bytes signed for a slip.

    The context prefix is part of what is signed, so a delegation slip, an approval slip, and a
    ledger-head attestation are mutually non-confusable even under the same key.
    """
    return f"{context}.{payload_b64}".encode()


def verify_slip_ed25519(
    token: str, public_key: bytes, *, context: str
) -> tuple[bool, dict[str, Any] | None]:
    """Verify an Ed25519 slip in *context* with *public_key*. Returns ``(valid, claims)``."""
    if token.count(".") != 1:
        return False, None
    payload_b64, signature = token.split(".", 1)
    if not signature.startswith(SIGNATURE_PREFIX):
        return False, None
    try:
        sig_bytes = base64.b64decode(signature[len(SIGNATURE_PREFIX) :], validate=True)
    except ValueError:
        return False, None
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            sig_bytes, _signed_bytes(context, payload_b64)
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


def _seal_signed_bytes(unsigned_bytes: bytes) -> bytes:
    """Return the domain-separated bytes an envelope seal signs.

    The seal signs ``b"ambit.envelope.seal.v1." + unsigned_bytes`` — a context distinct from
    every slip and from ledger-head attestation, so a seal signature and a slip signature are
    mutually non-confusable even under the same key. The seal binds the *envelope bytes*, not
    slip-shaped claims.
    """
    return SEAL_CONTEXT.encode("utf-8") + b"." + unsigned_bytes


def verify_seal_ed25519(unsigned_bytes: bytes, signature_hex: str, public_key: bytes) -> bool:
    """Verify an Ed25519 envelope-seal *signature_hex* over domain-separated *unsigned_bytes*.

    Returns ``False`` on a malformed signature or key rather than raising, so callers fail closed.
    """
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, _seal_signed_bytes(unsigned_bytes)
        )
    except InvalidSignature, ValueError:
        return False
    return True


__all__ = [
    "SEAL_CONTEXT",
    "SIGNATURE_PREFIX",
    "verify_seal_ed25519",
    "verify_slip_ed25519",
]
