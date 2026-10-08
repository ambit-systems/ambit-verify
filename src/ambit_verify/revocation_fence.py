# Copyright (c) 2026 Ambit Systems Pty Ltd. All rights reserved.
# Proprietary and confidential. See LICENSE for terms.

"""Public grammar for one A/B customer-delete revocation fence."""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .hashing import canonical_json_bytes, strict_json_loads

FENCE_PROFILE = "customer-delete-fence/1"
REQUEST_CONTEXT = b"ambit.revocation.fence.request.v1."
GRANT_CONTEXT = b"ambit.revocation.fence.grant.v1."
_HEX = frozenset("0123456789abcdef")
_REQUEST_FIELDS = frozenset(
    {
        "version",
        "profile",
        "a_dispatch",
        "b_dispatch_hash",
        "b_operation_id",
        "b_domain_id",
        "b_ledger_id",
        "b_resource_id",
        "b_resource_binding_hash",
        "customer_id",
        "payload_hash",
    }
)
_GRANT_FIELDS = frozenset(
    {
        "version",
        "profile",
        "request_hash",
        "a_dispatch_hash",
        "b_dispatch_hash",
        "delegation_jtis",
        "revocation_epoch",
        "prepared_at",
        "trust_root_id",
    }
)


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def fence_request_claims(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the exact B-signed request fields."""
    if not isinstance(value, Mapping) or set(value) != _REQUEST_FIELDS:
        raise ValueError("revocation fence request fields are invalid")
    claims = dict(value)
    if claims["version"] != 1 or claims["profile"] != FENCE_PROFILE:
        raise ValueError("revocation fence request version or profile is invalid")
    for field in (
        "a_dispatch",
        "b_operation_id",
        "b_domain_id",
        "b_ledger_id",
        "b_resource_id",
        "customer_id",
    ):
        if (
            not isinstance(claims[field], str)
            or not claims[field]
            or claims[field].strip() != claims[field]
        ):
            raise ValueError(f"revocation fence request {field} is invalid")
    for field in ("b_dispatch_hash", "b_resource_binding_hash", "payload_hash"):
        if not _digest(claims[field]):
            raise ValueError(f"revocation fence request {field} is invalid")
    return claims


def fence_grant_claims(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the exact A-signed grant fields."""
    if not isinstance(value, Mapping) or set(value) != _GRANT_FIELDS:
        raise ValueError("revocation fence grant fields are invalid")
    claims = dict(value)
    if claims["version"] != 1 or claims["profile"] != FENCE_PROFILE:
        raise ValueError("revocation fence grant version or profile is invalid")
    for field in ("request_hash", "a_dispatch_hash", "b_dispatch_hash"):
        if not _digest(claims[field]):
            raise ValueError(f"revocation fence grant {field} is invalid")
    jtis = claims["delegation_jtis"]
    if (
        not isinstance(jtis, list)
        or not jtis
        or len(set(jtis)) != len(jtis)
        or any(not isinstance(jti, str) or not jti or jti.strip() != jti for jti in jtis)
    ):
        raise ValueError("revocation fence grant delegation JTIs are invalid")
    epoch = claims["revocation_epoch"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise ValueError("revocation fence grant epoch is invalid")
    for field in ("prepared_at", "trust_root_id"):
        if not isinstance(claims[field], str) or not claims[field]:
            raise ValueError(f"revocation fence grant {field} is invalid")
    try:
        prepared = datetime.fromisoformat(claims["prepared_at"].replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("revocation fence grant prepared_at is invalid") from error
    if prepared.tzinfo is None or prepared.utcoffset() is None:
        raise ValueError("revocation fence grant prepared_at is invalid")
    return claims


def fence_request_hash(token: str) -> str:
    """Identify the exact compact B request token."""
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def fence_message(claims: Mapping[str, Any], *, grant: bool) -> bytes:
    """Return canonical bytes under the request or grant signature context."""
    parsed = fence_grant_claims(claims) if grant else fence_request_claims(claims)
    return (GRANT_CONTEXT if grant else REQUEST_CONTEXT) + canonical_json_bytes(parsed)


def _decode_segment(value: str) -> bytes:
    if not value or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in value
    ):
        raise ValueError("revocation fence token encoding is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise ValueError("revocation fence token encoding is invalid") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError("revocation fence token encoding is not canonical")
    return decoded


def verify_fence_token(token: str, *, public_key: bytes | str, grant: bool) -> dict[str, Any]:
    """Verify one context-separated compact token under an installed key."""
    if not isinstance(token, str) or token.count(".") != 1:
        raise ValueError("revocation fence token is invalid")
    payload_part, signature_part = token.split(".")
    payload = _decode_segment(payload_part)
    signature = _decode_segment(signature_part)
    if len(signature) != 64:
        raise ValueError("revocation fence token signature is invalid")
    try:
        decoded = strict_json_loads(payload.decode("utf-8"))
        claims = fence_grant_claims(decoded) if grant else fence_request_claims(decoded)
        if canonical_json_bytes(claims) != payload:
            raise ValueError("revocation fence token payload is not canonical")
        key = bytes.fromhex(public_key) if isinstance(public_key, str) else bytes(public_key)
        Ed25519PublicKey.from_public_bytes(key).verify(
            signature, fence_message(claims, grant=grant)
        )
    except (InvalidSignature, TypeError, UnicodeError, ValueError) as error:
        raise ValueError("revocation fence token does not verify") from error
    return claims


def unverified_fence_claims(token: str, *, grant: bool) -> dict[str, Any]:
    """Read only the candidate key selector; the caller must then verify the token."""
    if not isinstance(token, str) or token.count(".") != 1:
        raise ValueError("revocation fence token is invalid")
    payload = _decode_segment(token.split(".")[0])
    decoded = strict_json_loads(payload.decode("utf-8"))
    claims = fence_grant_claims(decoded) if grant else fence_request_claims(decoded)
    if canonical_json_bytes(claims) != payload:
        raise ValueError("revocation fence token payload is not canonical")
    return claims


__all__ = [
    "FENCE_PROFILE",
    "fence_grant_claims",
    "fence_message",
    "fence_request_claims",
    "fence_request_hash",
    "unverified_fence_claims",
    "verify_fence_token",
]
