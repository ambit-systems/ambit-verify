# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Strict public grammar and Ed25519 verification for resource lifecycle tokens."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .hashing import canonical_json_bytes, hash_object, strict_json_loads

RESOURCE_PROFILE = "record-egress/1"
GIT_PUBLICATION_PROFILE = "git-publication/1"
CUSTOMER_DELETE_PROFILE = "customer-delete/1"
DISPATCH_CONTEXT = b"ambit.resource.dispatch.v1."
OUTCOME_CONTEXT = b"ambit.resource.outcome.v1."
RECONCILIATION_CONTEXT = b"ambit.resource.reconciliation.v1."
_HEX = frozenset("0123456789abcdef")
_OPERATION_ID_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
)


_DISPATCH_FIELDS = frozenset(
    {
        "version",
        "profile",
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
        "action_type",
        "action_boundary",
        "action_domain",
        "action_path",
        "authorized_at",
        "not_after",
    }
)

_RESOURCE_JOIN_FIELDS = frozenset(
    {
        "version",
        "profile",
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
    }
)
_GIT_DISPATCH_FIELDS = _RESOURCE_JOIN_FIELDS | frozenset(
    {
        "actor_id",
        "plan_hash",
        "action_type",
        "action_boundary",
        "action_domain",
        "action_path",
        "authorized_at",
        "not_after",
        "remote",
        "ref",
        "expected_old_oid",
        "new_oid",
        "range",
        "force",
    }
)
_CUSTOMER_DELETE_DISPATCH_FIELDS = _DISPATCH_FIELDS | frozenset({"customer_id"})
# The identity a dispatch's revocation stands on: the delegation jti chain the
# decision validated, nearest grant first, and the revocation epoch the store
# stated at ALLOW. A resource door reads both to re-check revocation at commit
# time. They travel together or not at all; a dispatch signed before the pair
# existed keeps the field set it always had.
_REVOCATION_IDENTITY_FIELDS = frozenset({"delegation_jtis", "revocation_epoch"})
_MAX_DELEGATION_JTIS = 16
_TERMINAL_FIELDS = _RESOURCE_JOIN_FIELDS | frozenset(
    {
        "status",
        "accepted_at",
        "recorded_at",
        "record_count",
        "records_hash",
    }
)
_GIT_TERMINAL_FIELDS = _RESOURCE_JOIN_FIELDS | frozenset(
    {
        "actor_id",
        "plan_hash",
        "remote",
        "ref",
        "expected_old_oid",
        "new_oid",
        "range",
        "force",
        "status",
        "accepted_at",
        "recorded_at",
    }
)
_CUSTOMER_DELETE_TERMINAL_FIELDS = _RESOURCE_JOIN_FIELDS | frozenset(
    {
        "customer_id",
        "status",
        "accepted_at",
        "recorded_at",
        "deleted_count",
        "before_hash",
        "before_state",
        "after_state",
        "reason",
    }
)
_GIT_OUTCOME_REASONS = frozenset(
    {
        "delegation_revoked",
        "static_obligation_failed",
        "compare_and_swap_mismatch",
        "plan_hash_mismatch",
        "dispatch_expired",
    }
)
_RECONCILIATION_FIELDS = _RESOURCE_JOIN_FIELDS | frozenset({"verb", "issued_at", "expires_at"})
_CUSTOMER_DELETE_RECONCILIATION_FIELDS = _RECONCILIATION_FIELDS | frozenset({"customer_id"})
_BINDING_FIELDS = frozenset(
    {
        "adapter_id",
        "downstream_url",
        "downstream_path",
        "receipt_public_key",
        "outcome_profile",
        "outcome_public_key",
    }
)
_GIT_BINDING_FIELDS = _BINDING_FIELDS | frozenset({"git_remote", "git_ref"})


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be nonempty canonical text")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or set(value) - _HEX:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _time(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an ISO-8601 timestamp")
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from error
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError(f"{name} requires an explicit timezone")
    return moment.astimezone(UTC)


def _json_value(value: object) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        raise ValueError("resource payload must not contain floating-point values")
    if isinstance(value, list):
        for item in value:
            _json_value(item)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("resource payload object keys must be strings")
            _json_value(item)
        return
    raise ValueError("resource payload contains a non-JSON value")


def _canonical_object(value: object, *, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    copied = dict(value)
    _json_value(copied)
    try:
        data = canonical_json_bytes(copied)
        parsed = strict_json_loads(data.decode("ascii"))
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(f"{name} is outside canonical JSON") from error
    if not isinstance(parsed, dict):  # defensive: object input must survive canonicalisation
        raise ValueError(f"{name} is outside canonical JSON")
    return copied


def payload_bytes(call: Mapping[str, Any]) -> bytes:
    """Return canonical bytes for the exact public resource call ``{name, arguments}``."""
    value = _canonical_object(call, name="resource call")
    if set(value) != {"name", "arguments"}:
        raise ValueError("resource call fields are invalid")
    _text(value.get("name"), "resource call name")
    if not isinstance(value.get("arguments"), Mapping):
        raise ValueError("resource call arguments must be an object")
    return canonical_json_bytes(value)


def resource_binding_hash(binding: Mapping[str, Any]) -> str:
    """Hash one exact admitted resource binding after profile-specific validation."""
    value = _canonical_object(binding, name="resource binding")
    profile = value.get("outcome_profile")
    expected_fields = _GIT_BINDING_FIELDS if profile == GIT_PUBLICATION_PROFILE else _BINDING_FIELDS
    if set(value) != expected_fields:
        raise ValueError("resource binding fields are invalid")
    for name in ("adapter_id", "downstream_url", "downstream_path"):
        _text(value.get(name), f"resource binding {name}")
    _digest(value.get("receipt_public_key"), "resource binding receipt_public_key")
    public_key = value.get("outcome_public_key")
    if profile is None and public_key is None:
        return hash_object(value)
    if (
        profile not in {RESOURCE_PROFILE, GIT_PUBLICATION_PROFILE, CUSTOMER_DELETE_PROFILE}
        or not isinstance(public_key, str)
        or len(public_key) != 64
        or set(public_key) - _HEX
        or public_key == value["receipt_public_key"]
    ):
        raise ValueError("resource binding outcome attestation pair is invalid")
    if profile == GIT_PUBLICATION_PROFILE:
        if value["adapter_id"] != "code":
            raise ValueError("Git publication requires the code adapter")
        _text(value.get("git_remote"), "resource binding git_remote")
        _git_ref(value.get("git_ref"), "resource binding git_ref")
    elif profile == CUSTOMER_DELETE_PROFILE and value["adapter_id"] != "http":
        raise ValueError("customer-delete requires the HTTP adapter")
    return hash_object(value)


def _claims(
    value: Mapping[str, Any],
    *,
    fields: frozenset[str],
    kind: str,
    profile: str,
    optional: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    copied = _canonical_object(value, name=f"{kind} claims")
    if set(copied) not in (fields, fields | optional):
        raise ValueError(f"{kind} claim fields are invalid")
    if copied.get("version") != 1 or copied.get("profile") != profile:
        raise ValueError(f"{kind} version or profile is invalid")
    for name in ("domain_id", "ledger_id", "enforcement_point_id", "resource_id"):
        _text(copied.get(name), f"{kind} {name}")
    operation_id = copied.get("operation_id")
    if (
        not isinstance(operation_id, str)
        or not 1 <= len(operation_id) <= 128
        or any(character not in _OPERATION_ID_CHARS for character in operation_id)
    ):
        raise ValueError(f"{kind} operation_id is invalid")
    for name in (
        "resource_binding_hash",
        "request_hash",
        "payload_hash",
        "decision_hash",
        "intent_hash",
    ):
        _digest(copied.get(name), f"{kind} {name}")
    return copied


def _git_oid(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) not in {40, 64} or set(value) - _HEX:
        raise ValueError(f"{name} must be a lowercase Git object id")
    return value


def _git_ref(value: object, name: str) -> str:
    ref = _text(value, name)
    if (
        not ref.startswith("refs/heads/")
        or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-"
            for character in ref
        )
        or ".." in ref
        or ref.endswith(".")
        or any(
            not component or component.startswith(".") or component.endswith(".lock")
            for component in ref.split("/")
        )
    ):
        raise ValueError(f"{name} must be a branch ref")
    return ref


def git_ref_is_covered(ref: str, scope_paths: Sequence[str]) -> bool:
    """Check an exact Git ref or a signed slash-delimited branch-prefix scope."""
    _git_ref(ref, "Git ref")
    return any(
        scope == ref
        or (scope.endswith("/*") and ref.startswith(scope[:-1]) and len(ref) > len(scope) - 1)
        for scope in scope_paths
    )


def git_publication_plan_hash(
    *,
    remote_url: str,
    ref: str,
    expected_old_oid: str,
    new_oid: str,
    commit_range: str,
    force: bool = False,
) -> str:
    """Bind one non-forced update of an existing agent branch to its exact range."""
    _text(remote_url, "Git remote")
    _git_ref(ref, "Git ref")
    _git_oid(expected_old_oid, "Git expected_old_oid")
    _git_oid(new_oid, "Git new_oid")
    if (
        force is not False
        or len(expected_old_oid) != len(new_oid)
        or expected_old_oid == "0" * len(expected_old_oid)
        or new_oid == "0" * len(new_oid)
        or expected_old_oid == new_oid
        or commit_range != f"{expected_old_oid}..{new_oid}"
    ):
        raise ValueError("Git publication requires a nonempty, non-forced existing-ref update")
    return hash_object(
        {
            "remote_url": remote_url,
            "ref": ref,
            "expected_old_oid": expected_old_oid,
            "new_oid": new_oid,
            "force": False,
            "range": commit_range,
        }
    )


def _dispatch_claims(value: Mapping[str, Any]) -> dict[str, Any]:
    profile = value.get("profile")
    if profile == RESOURCE_PROFILE:
        claims = _claims(
            value,
            fields=_DISPATCH_FIELDS,
            kind="dispatch",
            profile=profile,
            optional=_REVOCATION_IDENTITY_FIELDS,
        )
    elif profile == CUSTOMER_DELETE_PROFILE:
        claims = _claims(
            value,
            fields=_CUSTOMER_DELETE_DISPATCH_FIELDS,
            kind="dispatch",
            profile=profile,
            optional=_REVOCATION_IDENTITY_FIELDS,
        )
        _text(claims.get("customer_id"), "dispatch customer_id")
        if (
            claims.get("action_type") != "delete"
            or claims.get("action_boundary") != "network_egress"
            or claims.get("action_domain") != "http"
        ):
            raise ValueError("dispatch customer-delete canonical action is invalid")
    elif profile == GIT_PUBLICATION_PROFILE:
        claims = _claims(
            value,
            fields=_GIT_DISPATCH_FIELDS,
            kind="dispatch",
            profile=profile,
            optional=_REVOCATION_IDENTITY_FIELDS,
        )
        _text(claims.get("actor_id"), "dispatch actor_id")
        expected_plan = git_publication_plan_hash(
            remote_url=claims["remote"],
            ref=claims["ref"],
            expected_old_oid=claims["expected_old_oid"],
            new_oid=claims["new_oid"],
            commit_range=claims["range"],
            force=claims["force"],
        )
        if (
            claims.get("plan_hash") != expected_plan
            or claims.get("action_path") != claims["ref"]
            or claims.get("action_type") != "execute"
            or claims.get("action_boundary") != "code_execution"
            or claims.get("action_domain") != "process"
        ):
            raise ValueError("dispatch Git plan or canonical action is invalid")
    else:
        raise ValueError("dispatch profile is invalid")
    for name in ("action_type", "action_boundary", "action_domain", "action_path"):
        _text(claims.get(name), f"dispatch {name}")
    authorized_at = _time(claims.get("authorized_at"), "dispatch authorized_at")
    not_after = _time(claims.get("not_after"), "dispatch not_after")
    if not_after < authorized_at:
        raise ValueError("dispatch not_after precedes authorized_at")
    if "delegation_jtis" in claims:
        _revocation_identity(claims)
    return claims


def _revocation_identity(claims: Mapping[str, Any]) -> None:
    jtis = claims.get("delegation_jtis")
    if (
        not isinstance(jtis, list)
        or not 1 <= len(jtis) <= _MAX_DELEGATION_JTIS
        or any(
            not isinstance(jti, str) or not 1 <= len(jti) <= 256 or jti != jti.strip()
            for jti in jtis
        )
        or len(set(jtis)) != len(jtis)
    ):
        raise ValueError("dispatch delegation_jtis is invalid")
    epoch = claims.get("revocation_epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise ValueError("dispatch revocation_epoch is invalid")


def dispatch_revocation_identity(claims: Mapping[str, Any]) -> tuple[tuple[str, ...], int] | None:
    """Return the delegation jti chain and ALLOW-time epoch a dispatch carries.

    ``None`` when the dispatch predates the pair. A door that requires the
    pair refuses ``None``; the verifier accepts both generations.
    """
    if "delegation_jtis" not in claims:
        return None
    _revocation_identity(claims)
    return tuple(claims["delegation_jtis"]), int(claims["revocation_epoch"])


def _outcome_claims(value: Mapping[str, Any]) -> dict[str, Any]:
    profile = value.get("profile")
    if profile == RESOURCE_PROFILE:
        claims = _claims(value, fields=_TERMINAL_FIELDS, kind="resource outcome", profile=profile)
        status = claims.get("status")
        if status not in {"committed", "not_executed"}:
            raise ValueError("resource outcome status is invalid")
        accepted_at = claims.get("accepted_at")
        if accepted_at is not None:
            _time(accepted_at, "resource outcome accepted_at")
        _time(claims.get("recorded_at"), "resource outcome recorded_at")
        count = claims.get("record_count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("resource outcome record_count is invalid")
        records_hash = claims.get("records_hash")
        if status == "committed":
            if accepted_at is None or count <= 0:
                raise ValueError("committed resource outcome requires accepted_at and records")
            _digest(records_hash, "resource outcome records_hash")
        elif accepted_at is not None or count != 0 or records_hash is not None:
            raise ValueError("not_executed resource outcome must be a zero-record tombstone")
        return claims
    if profile == CUSTOMER_DELETE_PROFILE:
        claims = _claims(
            value,
            fields=_CUSTOMER_DELETE_TERMINAL_FIELDS,
            kind="resource outcome",
            profile=profile,
        )
        _text(claims.get("customer_id"), "resource outcome customer_id")
        status = claims.get("status")
        if status not in {"committed", "not_executed"}:
            raise ValueError("resource outcome status is invalid")
        accepted_at = claims.get("accepted_at")
        if accepted_at is not None:
            _time(accepted_at, "resource outcome accepted_at")
        _time(claims.get("recorded_at"), "resource outcome recorded_at")
        deleted_count = claims.get("deleted_count")
        if not isinstance(deleted_count, int) or isinstance(deleted_count, bool):
            raise ValueError("resource outcome deleted_count is invalid")
        before_hash = claims.get("before_hash")
        before_state = claims.get("before_state")
        after_state = claims.get("after_state")
        reason = claims.get("reason")
        if status == "committed":
            if (
                accepted_at is None
                or deleted_count != 1
                or (before_state, after_state, reason) != ("present", "absent", "deleted")
            ):
                raise ValueError(
                    "committed customer-delete outcome requires one deleted present customer"
                )
            _digest(before_hash, "resource outcome before_hash")
        elif (
            accepted_at is not None
            or deleted_count != 0
            or before_hash is not None
            or (before_state, after_state, reason)
            not in {
                ("absent", "absent", "already_absent"),
                ("unknown", "unknown", "rejected"),
                ("unknown", "unknown", "cancelled"),
                ("unknown", "unknown", "delegation_revoked"),
            }
        ):
            raise ValueError("not_executed customer-delete outcome is invalid")
        return claims
    if profile != GIT_PUBLICATION_PROFILE:
        raise ValueError("resource outcome profile is invalid")
    claims = _claims(
        value,
        fields=_GIT_TERMINAL_FIELDS,
        kind="resource outcome",
        profile=profile,
        optional=frozenset({"reason"}),
    )
    _text(claims.get("actor_id"), "resource outcome actor_id")
    expected_plan = git_publication_plan_hash(
        remote_url=claims["remote"],
        ref=claims["ref"],
        expected_old_oid=claims["expected_old_oid"],
        new_oid=claims["new_oid"],
        commit_range=claims["range"],
        force=claims["force"],
    )
    if claims.get("plan_hash") != expected_plan:
        raise ValueError("resource outcome Git plan is invalid")
    status = claims.get("status")
    if status not in {"committed", "not_executed", "unknown"}:
        raise ValueError("resource outcome status is invalid")
    accepted_at = claims.get("accepted_at")
    if status == "committed":
        _time(accepted_at, "resource outcome accepted_at")
    elif accepted_at is not None:
        raise ValueError("non-committed Git outcome must not claim acceptance")
    reason = claims.get("reason")
    if reason is not None and (status != "not_executed" or reason not in _GIT_OUTCOME_REASONS):
        raise ValueError("resource outcome reason is invalid")
    _time(claims.get("recorded_at"), "resource outcome recorded_at")
    return claims


def _reconciliation_claims(value: Mapping[str, Any]) -> dict[str, Any]:
    profile = value.get("profile")
    if profile not in {RESOURCE_PROFILE, GIT_PUBLICATION_PROFILE, CUSTOMER_DELETE_PROFILE}:
        raise ValueError("reconciliation profile is invalid")
    claims = _claims(
        value,
        fields=(
            _CUSTOMER_DELETE_RECONCILIATION_FIELDS
            if profile == CUSTOMER_DELETE_PROFILE
            else _RECONCILIATION_FIELDS
        ),
        kind="reconciliation",
        profile=profile,
    )
    if profile == CUSTOMER_DELETE_PROFILE:
        _text(claims.get("customer_id"), "reconciliation customer_id")
    if claims.get("verb") not in {"query", "cancel"}:
        raise ValueError("reconciliation verb is invalid")
    issued_at = _time(claims.get("issued_at"), "reconciliation issued_at")
    expires_at = _time(claims.get("expires_at"), "reconciliation expires_at")
    if expires_at < issued_at:
        raise ValueError("reconciliation expiry precedes issue time")
    return claims


def dispatch_message(claims: Mapping[str, Any]) -> bytes:
    """Return strict context-separated dispatch bytes for private signing."""
    return DISPATCH_CONTEXT + canonical_json_bytes(_dispatch_claims(claims))


def outcome_message(claims: Mapping[str, Any]) -> bytes:
    """Return strict context-separated terminal resource outcome bytes."""
    return OUTCOME_CONTEXT + canonical_json_bytes(_outcome_claims(claims))


def reconciliation_message(claims: Mapping[str, Any]) -> bytes:
    """Return strict context-separated reconciliation bytes for private signing."""
    return RECONCILIATION_CONTEXT + canonical_json_bytes(_reconciliation_claims(claims))


def _b64url_decode(value: object, *, name: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError(f"{name} is not unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError(f"{name} is not unpadded base64url") from error
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValueError(f"{name} is not canonical base64url")
    return decoded


def _public_key(value: object) -> Ed25519PublicKey:
    if isinstance(value, str):
        if len(value) != 64 or set(value) - _HEX:
            raise ValueError("resource public key is invalid")
        try:
            value = bytes.fromhex(value)
        except ValueError as error:
            raise ValueError("resource public key is invalid") from error
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("resource public key is invalid")
    try:
        return Ed25519PublicKey.from_public_bytes(value)
    except ValueError as error:
        raise ValueError("resource public key is invalid") from error


def _verify(
    token: str,
    *,
    public_key: bytes | str,
    message: Callable[[Mapping[str, Any]], bytes],
    parser: Callable[[Any], Mapping[str, Any]],
) -> dict[str, Any]:
    if not isinstance(token, str) or token.count(".") != 1:
        raise ValueError("resource token is malformed")
    payload_segment, signature_segment = token.split(".")
    payload = _b64url_decode(payload_segment, name="resource token payload")
    signature = _b64url_decode(signature_segment, name="resource token signature")
    if len(signature) != 64:
        raise ValueError("resource token signature has invalid length")
    try:
        decoded = strict_json_loads(payload.decode("utf-8"))
        claims = parser(decoded)
    except (UnicodeDecodeError, TypeError, ValueError, OverflowError) as error:
        raise ValueError("resource token claims are invalid") from error
    canonical = canonical_json_bytes(claims)
    if payload != canonical:
        raise ValueError("resource token payload is not canonical")
    try:
        _public_key(public_key).verify(signature, message(claims))
    except InvalidSignature as error:
        raise ValueError("resource token signature does not verify") from error
    return dict(claims)


def verify_dispatch(token: str, *, public_key: bytes | str) -> dict[str, Any]:
    """Verify one compact EP-signed dispatch token and return copied claims."""
    return _verify(token, public_key=public_key, message=dispatch_message, parser=_dispatch_claims)


def verify_resource_outcome(token: str, *, public_key: bytes | str) -> dict[str, Any]:
    """Verify one compact independently resource-signed terminal outcome."""
    return _verify(token, public_key=public_key, message=outcome_message, parser=_outcome_claims)


def verify_reconciliation(token: str, *, public_key: bytes | str) -> dict[str, Any]:
    """Verify one compact owner-key-signed reconciliation request."""
    return _verify(
        token, public_key=public_key, message=reconciliation_message, parser=_reconciliation_claims
    )


__all__ = [
    "CUSTOMER_DELETE_PROFILE",
    "DISPATCH_CONTEXT",
    "GIT_PUBLICATION_PROFILE",
    "OUTCOME_CONTEXT",
    "RECONCILIATION_CONTEXT",
    "RESOURCE_PROFILE",
    "dispatch_message",
    "git_publication_plan_hash",
    "git_ref_is_covered",
    "outcome_message",
    "payload_bytes",
    "reconciliation_message",
    "resource_binding_hash",
    "verify_dispatch",
    "verify_reconciliation",
    "verify_resource_outcome",
]
