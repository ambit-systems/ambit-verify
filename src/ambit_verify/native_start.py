# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Verify exact-operation native Start requests, grants, and ledger records."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .hashing import canonical_json_bytes, strict_json_loads
from .resource_protocol import (
    MCP_CALL_PROFILE,
    dispatch_revocation_identity,
    is_terminal_outcome,
    verify_dispatch,
    verify_resource_outcome,
)

PROFILE = "native-start/1"
JOIN_FIELDS = (
    "domain_id",
    "ledger_id",
    "enforcement_point_id",
    "resource_id",
    "resource_binding_hash",
    "operation_id",
    "request_hash",
    "payload_hash",
    "decision_hash",
    "intent_hash",
)
_REQUEST_FIELDS = {
    "version",
    "profile",
    "dispatch_token",
    "resource_binding_hash",
    "nonce",
    "issued_at",
}
_GRANT_FIELDS = {
    "version",
    "profile",
    "challenge_hash",
    "dispatch_hash",
    "start_record_hash",
    "accepted_at",
    "not_after",
    *JOIN_FIELDS,
}
_RECORD_FIELDS = {
    "record_type",
    "version",
    "profile",
    "dispatch_token",
    "dispatch_hash",
    "request_token",
    "authority_public_key",
    "resource_public_key",
    "accepted_at",
    "not_after",
    "revocation_epoch",
    *JOIN_FIELDS,
}
_ENVELOPE_FIELDS = {"seq", "prev_hash", "record_hash", "timestamp_utc"}


def digest(value: str) -> str:
    """Hash the exact compact token bytes."""
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _hex(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= set("0123456789abcdef")


def moment(value: object) -> datetime:
    """Parse a timezone-bearing protocol timestamp."""
    if not isinstance(value, str):
        raise ValueError("native_start_time_invalid")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.utcoffset() is None:
        raise ValueError("native_start_time_invalid")
    return result


def token_claims(value: Mapping[str, Any], *, grant: bool) -> dict[str, Any]:
    """Validate an exact request or grant field set."""
    fields = _GRANT_FIELDS if grant else _REQUEST_FIELDS
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("native_start_fields_invalid")
    claims = dict(value)
    if type(claims["version"]) is not int or claims["version"] != 1 or claims["profile"] != PROFILE:
        raise ValueError("native_start_version_invalid")
    for name, item in claims.items():
        if name != "version" and (not isinstance(item, str) or not item or item != item.strip()):
            raise ValueError("native_start_text_invalid")
    hashes = (
        (
            "challenge_hash",
            "dispatch_hash",
            "start_record_hash",
            "request_hash",
            "payload_hash",
            "decision_hash",
            "intent_hash",
        )
        if grant
        else ("nonce",)
    )
    if any(not _hex(claims[name]) for name in (*hashes, "resource_binding_hash")):
        raise ValueError("native_start_hash_invalid")
    if grant:
        if moment(claims["accepted_at"]) >= moment(claims["not_after"]):
            raise ValueError("native_start_interval_invalid")
    else:
        moment(claims["issued_at"])
    return claims


def message(claims: Mapping[str, Any], *, grant: bool) -> bytes:
    """Return canonical bytes with distinct request and grant signature contexts."""
    context = b"ambit.native-start.grant.v1." if grant else b"ambit.native-start.request.v1."
    return context + canonical_json_bytes(token_claims(claims, grant=grant))


def _decode(segment: str) -> bytes:
    if not segment or any(
        c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in segment
    ):
        raise ValueError("native_start_token_encoding")
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != segment:
        raise ValueError("native_start_token_encoding")
    return raw


def unverified_claims(token: str, *, grant: bool) -> dict[str, Any]:
    """Read a key selector only; this does not authenticate the request."""
    if not isinstance(token, str) or token.count(".") != 1 or len(token) > 65536:
        raise ValueError("native_start_token_invalid")
    raw = _decode(token.split(".")[0])
    claims = token_claims(strict_json_loads(raw.decode()), grant=grant)
    if canonical_json_bytes(claims) != raw:
        raise ValueError("native_start_token_noncanonical")
    return claims


def verify_token(token: str, *, public_key: bytes, grant: bool) -> dict[str, Any]:
    """Verify one native Start token under the caller's installed key."""
    try:
        claims = unverified_claims(token, grant=grant)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _decode(token.split(".")[1]), message(claims, grant=grant)
        )
    except (InvalidSignature, TypeError, UnicodeError, ValueError) as exc:
        raise ValueError("native_start_signature_invalid") from exc
    return claims


def validate_start_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate internal signatures and joins, without admitting the recorded keys.

    A caller must bind both recorded keys to its admitted authority and resource.
    A hash chain alone does not establish either key's authority.
    """
    if (
        set(record) - _ENVELOPE_FIELDS != _RECORD_FIELDS
        or record.get("record_type") != "native_start"
    ):
        raise ValueError("native_start_record_invalid")
    if (
        record.get("profile") != PROFILE
        or type(record.get("version")) is not int
        or record["version"] != 1
    ):
        raise ValueError("native_start_record_invalid")
    if any(
        not _hex(record[name])
        for name in ("authority_public_key", "resource_public_key", "dispatch_hash")
    ):
        raise ValueError("native_start_record_key_invalid")
    epoch = record["revocation_epoch"]
    if type(epoch) is not int or epoch < 0:
        raise ValueError("native_start_epoch_invalid")
    dispatch = verify_dispatch(
        record["dispatch_token"], public_key=bytes.fromhex(record["authority_public_key"])
    )
    request = verify_token(
        record["request_token"],
        public_key=bytes.fromhex(record["resource_public_key"]),
        grant=False,
    )
    if (
        request["dispatch_token"] != record["dispatch_token"]
        or request["resource_binding_hash"] != dispatch["resource_binding_hash"]
        or digest(record["dispatch_token"]) != record["dispatch_hash"]
        or any(record[name] != dispatch[name] for name in JOIN_FIELDS)
        or record["not_after"] != dispatch["not_after"]
        or not moment(dispatch["authorized_at"])
        <= moment(record["accepted_at"])
        < moment(dispatch["not_after"])
    ):
        raise ValueError("native_start_record_join_invalid")
    return dispatch


def validate_start_history(
    record: Mapping[str, Any],
    preceding: Sequence[Mapping[str, Any]],
    *,
    authority_public_key: str | None = None,
) -> None:
    """Join a Start to its sole earlier dispatch and admitted outcome key.

    Public verification additionally supplies the independently registered
    authority key. Internal ledger validation trusts its existing admission.
    """
    dispatch = validate_start_record(record)
    if authority_public_key is not None and record["authority_public_key"] != authority_public_key:
        raise ValueError("native_start_authority_key_mismatch")
    fences = [
        r
        for r in preceding
        if r.get("record_type") == "consumption"
        and r.get("event") == "dispatch_fenced"
        and r.get("dispatch_token") == record["dispatch_token"]
    ]
    decisions = [
        r
        for r in preceding
        if r.get("record_type") == "decision" and r.get("record_hash") == record["decision_hash"]
    ]
    if len(fences) != 1 or len(decisions) != 1:
        raise ValueError("native_start_history_missing")
    if any(
        r.get("record_type") == "native_start"
        and r.get("domain_id") == record["domain_id"]
        and r.get("operation_id") == record["operation_id"]
        for r in preceding
    ):
        raise ValueError("native_start_duplicate_record")
    evidence = decisions[0].get("evidence")
    admission = evidence.get("authority_admission") if isinstance(evidence, Mapping) else None
    binding = admission.get("resource_binding") if isinstance(admission, Mapping) else None
    if (
        not isinstance(binding, Mapping)
        or binding.get("outcome_public_key") != record["resource_public_key"]
    ):
        raise ValueError("native_start_resource_key_mismatch")
    chain = dispatch_revocation_identity(dispatch)
    if chain is None:
        raise ValueError("native_start_chain_missing")
    accepted = moment(record["accepted_at"])
    intents = {
        r.get("seq"): r
        for r in preceding
        if r.get("record_type") == "revocation" and r.get("phase") == "intent"
    }
    for earlier in preceding:
        if earlier.get("record_type") == "consumption" and earlier.get("event") == "settlement":
            operation = earlier.get("operation")
            if isinstance(operation, Mapping) and all(
                operation.get(name) == record[name] for name in ("domain_id", "operation_id")
            ):
                raise ValueError("native_start_operation_terminal")
        if earlier.get("record_type") != "revocation":
            continue
        if earlier.get("phase") == "outcome" and earlier.get("result") == "revoked":
            intent = intents.get(earlier.get("intent_seq"))
            if intent is not None and intent.get("target_jti") in chain[0]:
                raise ValueError("native_start_follows_revocation")
        if earlier.get("phase") == "import":
            for jti, expiry in earlier.get("rows", []):
                if jti in chain[0] and (expiry is None or expiry > accepted.timestamp()):
                    raise ValueError("native_start_follows_revocation")


def validate_terminal_start(
    outcome: Mapping[str, Any], records: Sequence[Mapping[str, Any]]
) -> None:
    """Bind a committed terminal to its retained exact Start and acceptance time.

    Historical operations without a Start keep their existing interval checks.
    Negative and unknown outcomes retain their profile's null acceptance time.
    The caller must verify the outcome signature and the Start history first.
    """
    starts = [
        record
        for record in records
        if record.get("record_type") == "native_start"
        and all(record.get(name) == outcome.get(name) for name in ("domain_id", "operation_id"))
    ]
    if len(starts) > 1:
        raise ValueError("native_start_duplicate_record")
    if not starts or outcome.get("status") != "committed":
        return
    start = starts[0]
    if any(start.get(name) != outcome.get(name) for name in JOIN_FIELDS):
        raise ValueError("native_start_terminal_operation_mismatch")
    if outcome.get("accepted_at") != start.get("accepted_at"):
        raise ValueError("native_start_terminal_acceptance_mismatch")


def validate_terminal_start_record(
    record: Mapping[str, Any], preceding: Sequence[Mapping[str, Any]]
) -> None:
    """Check a terminal record under a canonical append lock or during rebuild."""
    if record.get("record_type") != "consumption" or record.get("event") not in {
        "settlement",
        "counterparty_recovered",
    }:
        return
    operation = record.get("operation")
    if not isinstance(operation, Mapping):
        return  # The consumption grammar rejects this case.
    starts = [
        start
        for start in preceding
        if start.get("record_type") == "native_start"
        and all(start.get(name) == operation.get(name) for name in ("domain_id", "operation_id"))
    ]
    if not starts:
        return
    token = record.get("resource_outcome")
    if not isinstance(token, str):
        raise ValueError("native_start_terminal_outcome_missing")
    outcome = verify_resource_outcome(token, public_key=starts[0]["resource_public_key"])
    if outcome.get("profile") == MCP_CALL_PROFILE and not is_terminal_outcome(outcome):
        raise ValueError("native_start_terminal_outcome_not_terminal")
    if any(outcome.get(name) != operation.get(name) for name in ("domain_id", "operation_id")):
        raise ValueError("native_start_terminal_operation_mismatch")
    validate_terminal_start(outcome, starts)
