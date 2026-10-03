# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Strict public grammar and Ed25519 verification for resource lifecycle tokens."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .consumption import operation_descriptor_hash
from .hashing import canonical_json_bytes, hash_object, strict_json_loads
from .tokens_slips import SLIP_CONTEXT_COUNTERPARTY_CONTEXT, parse_counterparty_context

RESOURCE_PROFILE = "record-egress/1"
GIT_PUBLICATION_PROFILE = "git-publication/1"
CUSTOMER_DELETE_PROFILE = "customer-delete/1"
DISPATCH_CONTEXT = b"ambit.resource.dispatch.v1."
OUTCOME_CONTEXT = b"ambit.resource.outcome.v1."
RECONCILIATION_CONTEXT = b"ambit.resource.reconciliation.v1."
COUNTERPARTY_PENDING_ACK_CONTEXT = b"ambit.resource.counterparty-pending-ack.v1."
COUNTERPARTY_PENDING_ACK_PROFILE = "counterparty_pending_ack/1"
COUNTERPARTY_CONTEXT_CONTEXT = SLIP_CONTEXT_COUNTERPARTY_CONTEXT
COUNTERPARTY_CONTEXT_PROFILE = "counterparty_context/1"
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
_COUNTERPARTY_CONSENT_HASH_FIELD = frozenset({"counterparty_consent_hash"})
# The identity a dispatch's revocation stands on: the delegation jti chain the
# decision validated, nearest grant first, and the revocation epoch the store
# stated at ALLOW. A resource door reads both to re-check revocation at commit
# time. They travel together or not at all; a dispatch signed before the pair
# existed keeps the field set it always had. `max_revocation_age_ms` is the
# principal's own bound on revocation-answer age; it is optional and travels
# only alongside the pair, never alone.
_REVOCATION_IDENTITY_FIELDS = frozenset({"delegation_jtis", "revocation_epoch"})
_REVOCATION_IDENTITY_WITH_BOUND_FIELDS = _REVOCATION_IDENTITY_FIELDS | frozenset(
    {"max_revocation_age_ms"}
)
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
_COUNTERPARTY_INGRESS_BINDING_FIELDS = frozenset({"counterparty_ingress_url"})
_COUNTERPARTY_CONSENT_BINDING_FIELDS = frozenset({"counterparty_consent_hash"})
_FOREIGN_REVOCATION_POLICY_HASH_FIELD = frozenset({"foreign_revocation_policy_hash"})
_FOREIGN_DEPENDENCY_FIELD = frozenset({"foreign_dependency"})
_FOREIGN_REVOCATION_EVIDENCE_FIELD = frozenset({"foreign_revocation_evidence"})

_COUNTERPARTY_ACK_BASE_FIELDS = frozenset(
    {
        "version",
        "profile",
        "state",
        "foreign_dispatch_hash",
        "foreign_descriptor_hash",
        "operation_hash",
        "request_body_hash",
        "acknowledged_at",
        "expires_at",
    }
)
_COUNTERPARTY_ACK_APPROVAL_FIELDS = _COUNTERPARTY_ACK_BASE_FIELDS | frozenset(
    {
        "counterparty_context_hash",
        "b_request_fingerprint",
        "b_escalation_record_hash",
    }
)

_COUNTERPARTY_CONTEXT_FIELDS = frozenset(
    {
        "version",
        "trust_root_id",
        "profile",
        "foreign_dispatch_hash",
        "foreign_descriptor_hash",
        "operation_hash",
        "request_body_hash",
        "destination_hash",
        "consent_hash",
        "justification",
        "issued_at",
        "expires_at",
    }
)
_COUNTERPARTY_FOREIGN_DESCRIPTOR_FIELDS = _CUSTOMER_DELETE_DISPATCH_FIELDS


def validate_counterparty_ingress_url(value: object) -> str:
    """Return an unambiguous absolute HTTP(S) transport destination or raise."""
    if not isinstance(value, str):
        raise ValueError(
            "counterparty_ingress_url must be an absolute HTTP(S) URL without userinfo or fragment"
        )
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError(
            "counterparty_ingress_url must be an absolute HTTP(S) URL without userinfo or fragment"
        ) from error
    if (
        value != value.strip()
        or parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (port is not None and not 0 < port <= 65535)
    ):
        raise ValueError(
            "counterparty_ingress_url must be an absolute HTTP(S) URL without userinfo or fragment"
        )
    return value


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
    if "counterparty_ingress_url" in value:
        expected_fields |= _COUNTERPARTY_INGRESS_BINDING_FIELDS
    if "counterparty_consent_hash" in value:
        expected_fields |= _COUNTERPARTY_CONSENT_BINDING_FIELDS
    if "foreign_revocation_policy_hash" in value:
        expected_fields |= _FOREIGN_REVOCATION_POLICY_HASH_FIELD
    if set(value) != expected_fields:
        raise ValueError("resource binding fields are invalid")
    for name in ("adapter_id", "downstream_url", "downstream_path"):
        _text(value.get(name), f"resource binding {name}")
    if "counterparty_ingress_url" in value:
        validate_counterparty_ingress_url(value["counterparty_ingress_url"])
    if "counterparty_consent_hash" in value:
        _digest(value["counterparty_consent_hash"], "resource binding counterparty_consent_hash")
    if "foreign_revocation_policy_hash" in value:
        _digest(
            value["foreign_revocation_policy_hash"],
            "resource binding foreign_revocation_policy_hash",
        )
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
        validate_branch_ref(value.get("git_ref"), "resource binding git_ref")
    elif profile == CUSTOMER_DELETE_PROFILE and value["adapter_id"] != "http":
        raise ValueError("customer-delete requires the HTTP adapter")
    return hash_object(value)


def _claims(
    value: Mapping[str, Any],
    *,
    fields: frozenset[str],
    kind: str,
    profile: str,
    optional: tuple[frozenset[str], ...] = (),
) -> dict[str, Any]:
    copied = _canonical_object(value, name=f"{kind} claims")
    allowed = {fields, *(fields | group for group in optional)}
    if set(copied) not in allowed:
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


def validate_branch_ref(value: object, name: str = "Git ref") -> str:
    """Return ``value`` when it is a well-formed branch ref, else raise.

    A branch ref lives under ``refs/heads/`` and obeys git's ref format: no
    ``..``, no trailing dot, no empty or dot-prefixed component, no ``.lock``
    component, and only the ref charset. Tags and unqualified names are not
    branch refs and are refused here.

    Shape is all this decides. Which branch may be published is the grant's
    scope paths and the operator's admitted ``git_ref``, never this function,
    so every caller in the product must use it rather than restate the rules.
    """
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
    validate_branch_ref(ref, "Git ref")
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
    validate_branch_ref(ref, "Git ref")
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
            optional=(_REVOCATION_IDENTITY_FIELDS, _REVOCATION_IDENTITY_WITH_BOUND_FIELDS),
        )
    elif profile == CUSTOMER_DELETE_PROFILE:
        claims = _claims(
            value,
            fields=_CUSTOMER_DELETE_DISPATCH_FIELDS,
            kind="dispatch",
            profile=profile,
            optional=(
                _REVOCATION_IDENTITY_FIELDS,
                _REVOCATION_IDENTITY_WITH_BOUND_FIELDS,
                _COUNTERPARTY_CONSENT_HASH_FIELD,
                _REVOCATION_IDENTITY_FIELDS | _COUNTERPARTY_CONSENT_HASH_FIELD,
                _REVOCATION_IDENTITY_WITH_BOUND_FIELDS | _COUNTERPARTY_CONSENT_HASH_FIELD,
                _FOREIGN_DEPENDENCY_FIELD,
                _REVOCATION_IDENTITY_FIELDS | _FOREIGN_DEPENDENCY_FIELD,
                _REVOCATION_IDENTITY_WITH_BOUND_FIELDS | _FOREIGN_DEPENDENCY_FIELD,
                _COUNTERPARTY_CONSENT_HASH_FIELD | _FOREIGN_DEPENDENCY_FIELD,
                _REVOCATION_IDENTITY_FIELDS
                | _COUNTERPARTY_CONSENT_HASH_FIELD
                | _FOREIGN_DEPENDENCY_FIELD,
                _REVOCATION_IDENTITY_WITH_BOUND_FIELDS
                | _COUNTERPARTY_CONSENT_HASH_FIELD
                | _FOREIGN_DEPENDENCY_FIELD,
            ),
        )
        _text(claims.get("customer_id"), "dispatch customer_id")
        if "counterparty_consent_hash" in claims:
            _digest(claims["counterparty_consent_hash"], "dispatch counterparty_consent_hash")
        dependency = claims.get("foreign_dependency")
        if dependency is not None:
            if (
                not isinstance(dependency, Mapping)
                or set(dependency) != {"dispatch", "policy_hash"}
                or not isinstance(dependency.get("dispatch"), str)
                or not dependency["dispatch"]
            ):
                raise ValueError("dispatch foreign dependency is invalid")
            _digest(dependency.get("policy_hash"), "dispatch foreign dependency policy_hash")
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
            optional=(_REVOCATION_IDENTITY_FIELDS, _REVOCATION_IDENTITY_WITH_BOUND_FIELDS),
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
    if "max_revocation_age_ms" in claims:
        _dispatch_max_revocation_age(claims)
    return claims


def counterparty_foreign_descriptor(dispatch_claims: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the immutable customer-delete dispatch descriptor for a counterparty ACK."""
    claims = _dispatch_claims(dispatch_claims)
    if claims["profile"] != CUSTOMER_DELETE_PROFILE:
        raise ValueError("counterparty dispatch must use the customer-delete profile")
    return {name: claims[name] for name in _COUNTERPARTY_FOREIGN_DESCRIPTOR_FIELDS}


def counterparty_foreign_descriptor_hash(dispatch_claims: Mapping[str, Any]) -> str:
    """Hash the strict immutable descriptor extracted from one A dispatch."""
    return hash_object(counterparty_foreign_descriptor(dispatch_claims))


def counterparty_operation_hash(operation: object) -> str:
    """Hash one strict frozen A operation descriptor for a counterparty ACK."""
    return operation_descriptor_hash(operation)


def counterparty_destination_hash(
    *,
    domain_id: str,
    ledger_id: str,
    enforcement_point_id: str,
    resource_binding_hash: str,
) -> str:
    """Hash the exact admitted B door identity for one foreign context."""
    return hash_object(
        {
            "domain_id": _text(domain_id, "counterparty destination domain_id"),
            "ledger_id": _text(ledger_id, "counterparty destination ledger_id"),
            "enforcement_point_id": _text(
                enforcement_point_id, "counterparty destination enforcement_point_id"
            ),
            "resource_binding_hash": _digest(
                resource_binding_hash, "counterparty destination resource_binding_hash"
            ),
        }
    )


def counterparty_consent_hash(
    *, delegation_token: str, parent_delegation_tokens: Sequence[str]
) -> str:
    """Hash the exact configured counterparty consent delegation chain."""
    if isinstance(parent_delegation_tokens, (str, bytes)):
        raise ValueError("counterparty consent parent delegation tokens are invalid")
    parents = [
        _text(token, "counterparty consent parent delegation token")
        for token in parent_delegation_tokens
    ]
    return hash_object(
        {
            "delegation_token": _text(delegation_token, "counterparty consent delegation token"),
            "parent_delegation_tokens": parents,
        }
    )


def _counterparty_pending_ack_claims(value: Mapping[str, Any]) -> dict[str, Any]:
    copied = _canonical_object(value, name="counterparty pending acknowledgment claims")
    state = copied.get("state")
    if state == "awaiting_review":
        fields = _COUNTERPARTY_ACK_BASE_FIELDS
    elif state == "awaiting_approval":
        fields = _COUNTERPARTY_ACK_APPROVAL_FIELDS
    else:
        raise ValueError("counterparty pending acknowledgment state is invalid")
    if set(copied) != fields:
        raise ValueError("counterparty pending acknowledgment claim fields are invalid")
    if copied.get("version") != 1 or copied.get("profile") != COUNTERPARTY_PENDING_ACK_PROFILE:
        raise ValueError("counterparty pending acknowledgment version or profile is invalid")
    for name in (
        "foreign_dispatch_hash",
        "foreign_descriptor_hash",
        "operation_hash",
        "request_body_hash",
    ):
        _digest(copied.get(name), f"counterparty pending acknowledgment {name}")
    if state == "awaiting_approval":
        for name in (
            "counterparty_context_hash",
            "b_request_fingerprint",
            "b_escalation_record_hash",
        ):
            _digest(copied.get(name), f"counterparty pending acknowledgment {name}")
    acknowledged_at = _time(
        copied.get("acknowledged_at"), "counterparty pending acknowledgment acknowledged_at"
    )
    expires_at = _time(copied.get("expires_at"), "counterparty pending acknowledgment expires_at")
    if expires_at <= acknowledged_at:
        raise ValueError("counterparty pending acknowledgment expiry is invalid")
    return copied


def counterparty_pending_ack_message(claims: Mapping[str, Any]) -> bytes:
    """Return strict context-separated B outcome-key ACK bytes for private signing."""
    return COUNTERPARTY_PENDING_ACK_CONTEXT + canonical_json_bytes(
        _counterparty_pending_ack_claims(claims)
    )


def verify_counterparty_pending_ack(
    token: str,
    *,
    public_key: bytes | str,
    expected_state: str,
    expected_foreign_dispatch_hash: str,
    expected_foreign_descriptor_hash: str,
    expected_operation_hash: str,
    expected_request_body_hash: str,
    expected_dispatch_not_after: datetime,
    at: datetime,
    expected_counterparty_context_hash: str | None = None,
    expected_b_request_fingerprint: str | None = None,
    expected_b_escalation_record_hash: str | None = None,
) -> dict[str, Any]:
    """Verify one B outcome-key ACK against one frozen A dispatch and lifecycle state."""
    if expected_state not in {"awaiting_review", "awaiting_approval"}:
        raise ValueError("expected counterparty pending acknowledgment state is invalid")
    for value, name in (
        (expected_foreign_dispatch_hash, "expected foreign dispatch hash"),
        (expected_foreign_descriptor_hash, "expected foreign descriptor hash"),
        (expected_operation_hash, "expected operation hash"),
        (expected_request_body_hash, "expected request body hash"),
    ):
        _digest(value, name)
    if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("counterparty pending acknowledgment verification time is invalid")
    if (
        not isinstance(expected_dispatch_not_after, datetime)
        or expected_dispatch_not_after.tzinfo is None
        or expected_dispatch_not_after.utcoffset() is None
    ):
        raise ValueError("counterparty dispatch expiry is invalid")
    approval_values = (
        (expected_counterparty_context_hash, "expected counterparty context hash"),
        (expected_b_request_fingerprint, "expected B request fingerprint"),
        (expected_b_escalation_record_hash, "expected B escalation record hash"),
    )
    if expected_state == "awaiting_review":
        if any(value is not None for value, _ in approval_values):
            raise ValueError("review acknowledgment must not carry approval expectations")
    elif (
        expected_counterparty_context_hash is None
        or expected_b_request_fingerprint is None
        or expected_b_escalation_record_hash is None
    ):
        raise ValueError("approval acknowledgment requires every approval expectation")
    else:
        for approval_value, approval_name in approval_values:
            _digest(approval_value, approval_name)
    claims = _verify(
        token,
        public_key=public_key,
        message=counterparty_pending_ack_message,
        parser=_counterparty_pending_ack_claims,
    )
    if claims["state"] != expected_state:
        raise ValueError("counterparty pending acknowledgment state does not match")
    for name, expected in (
        ("foreign_dispatch_hash", expected_foreign_dispatch_hash),
        ("foreign_descriptor_hash", expected_foreign_descriptor_hash),
        ("operation_hash", expected_operation_hash),
        ("request_body_hash", expected_request_body_hash),
    ):
        if claims[name] != expected:
            raise ValueError(f"counterparty pending acknowledgment {name} does not match")
    if expected_state == "awaiting_approval":
        if claims["counterparty_context_hash"] != expected_counterparty_context_hash:
            raise ValueError("counterparty pending acknowledgment context hash does not match")
        if claims["b_request_fingerprint"] != expected_b_request_fingerprint:
            raise ValueError(
                "counterparty pending acknowledgment request fingerprint does not match"
            )
        if claims["b_escalation_record_hash"] != expected_b_escalation_record_hash:
            raise ValueError(
                "counterparty pending acknowledgment escalation record hash does not match"
            )
    verified_at = at.astimezone(UTC)
    expires_at = _time(claims["expires_at"], "counterparty pending acknowledgment expires_at")
    if (
        not _time(claims["acknowledged_at"], "counterparty pending acknowledgment acknowledged_at")
        <= verified_at
        < expires_at
    ):
        raise ValueError("counterparty pending acknowledgment is not active")
    if expires_at > expected_dispatch_not_after.astimezone(UTC):
        raise ValueError("counterparty pending acknowledgment exceeds dispatch expiry")
    return claims


def counterparty_pending_ack_approval_expectations(
    token: str,
    *,
    public_key: bytes | str,
    expected_foreign_dispatch_hash: str,
    expected_foreign_descriptor_hash: str,
    expected_operation_hash: str,
    expected_request_body_hash: str,
    expected_dispatch_not_after: datetime,
    at: datetime,
) -> dict[str, str]:
    """Return verified B approval-stage joins for independently retained preflight proof."""
    for value, name in (
        (expected_foreign_dispatch_hash, "expected foreign dispatch hash"),
        (expected_foreign_descriptor_hash, "expected foreign descriptor hash"),
        (expected_operation_hash, "expected operation hash"),
        (expected_request_body_hash, "expected request body hash"),
    ):
        _digest(value, name)
    if (
        not isinstance(at, datetime)
        or at.tzinfo is None
        or at.utcoffset() is None
        or not isinstance(expected_dispatch_not_after, datetime)
        or expected_dispatch_not_after.tzinfo is None
        or expected_dispatch_not_after.utcoffset() is None
    ):
        raise ValueError("counterparty pending acknowledgment verification time is invalid")
    claims = _verify(
        token,
        public_key=public_key,
        message=counterparty_pending_ack_message,
        parser=_counterparty_pending_ack_claims,
    )
    if claims["state"] != "awaiting_approval":
        raise ValueError("counterparty pending acknowledgment is not awaiting approval")
    for name, expected in (
        ("foreign_dispatch_hash", expected_foreign_dispatch_hash),
        ("foreign_descriptor_hash", expected_foreign_descriptor_hash),
        ("operation_hash", expected_operation_hash),
        ("request_body_hash", expected_request_body_hash),
    ):
        if claims[name] != expected:
            raise ValueError(f"counterparty pending acknowledgment {name} does not match")
    verified_at = at.astimezone(UTC)
    expires_at = _time(claims["expires_at"], "counterparty pending acknowledgment expires_at")
    if (
        not _time(claims["acknowledged_at"], "counterparty pending acknowledgment acknowledged_at")
        <= verified_at
        < expires_at
    ):
        raise ValueError("counterparty pending acknowledgment is not active")
    if expires_at > expected_dispatch_not_after.astimezone(UTC):
        raise ValueError("counterparty pending acknowledgment exceeds dispatch expiry")
    return {
        name: str(claims[name])
        for name in (
            "counterparty_context_hash",
            "b_request_fingerprint",
            "b_escalation_record_hash",
        )
    }


def _counterparty_context_claims(value: Mapping[str, Any]) -> dict[str, Any]:
    copied = _canonical_object(value, name="counterparty context claims")
    if set(copied) != _COUNTERPARTY_CONTEXT_FIELDS:
        raise ValueError("counterparty context claim fields are invalid")
    if copied.get("version") != 1 or copied.get("profile") != COUNTERPARTY_CONTEXT_PROFILE:
        raise ValueError("counterparty context version or profile is invalid")
    _text(copied.get("trust_root_id"), "counterparty context trust_root_id")
    for name in (
        "foreign_dispatch_hash",
        "foreign_descriptor_hash",
        "operation_hash",
        "request_body_hash",
        "destination_hash",
        "consent_hash",
    ):
        _digest(copied.get(name), f"counterparty context {name}")
    _text(copied.get("justification"), "counterparty context justification")
    issued_at = _time(copied.get("issued_at"), "counterparty context issued_at")
    expires_at = _time(copied.get("expires_at"), "counterparty context expires_at")
    if expires_at <= issued_at:
        raise ValueError("counterparty context expiry is invalid")
    return copied


def verify_counterparty_context(
    token: str,
    *,
    trust_roots: Mapping[str, Any],
    expected_foreign_dispatch_hash: str,
    expected_foreign_descriptor_hash: str,
    expected_operation_hash: str,
    expected_request_body_hash: str,
    expected_destination_hash: str,
    expected_consent_hash: str,
    expected_justification: str,
    expected_dispatch_not_after: datetime,
    at: datetime,
) -> dict[str, Any]:
    """Verify a context-authority artifact using its independently admitted key."""
    expected = {
        "foreign_dispatch_hash": expected_foreign_dispatch_hash,
        "foreign_descriptor_hash": expected_foreign_descriptor_hash,
        "operation_hash": expected_operation_hash,
        "request_body_hash": expected_request_body_hash,
        "destination_hash": expected_destination_hash,
        "consent_hash": expected_consent_hash,
    }
    for value in expected.values():
        _digest(value, "expected counterparty context digest")
    _text(expected_justification, "expected counterparty context justification")
    if (
        not isinstance(at, datetime)
        or at.tzinfo is None
        or at.utcoffset() is None
        or not isinstance(expected_dispatch_not_after, datetime)
        or expected_dispatch_not_after.tzinfo is None
        or expected_dispatch_not_after.utcoffset() is None
    ):
        raise ValueError("counterparty context verification time is invalid")
    if not isinstance(trust_roots, Mapping) or len(trust_roots) != 1:
        raise ValueError("counterparty context authority must be one explicitly admitted root")
    valid, raw_claims = parse_counterparty_context(token, trust_roots=trust_roots)
    if not valid or raw_claims is None:
        raise ValueError("counterparty context signature does not verify")
    claims = _counterparty_context_claims(raw_claims)
    if any(claims[name] != value for name, value in expected.items()):
        raise ValueError("counterparty context does not match the frozen operation")
    if claims["justification"] != expected_justification:
        raise ValueError("counterparty context justification does not match")
    issued_at = _time(claims["issued_at"], "counterparty context issued_at")
    expires_at = _time(claims["expires_at"], "counterparty context expires_at")
    if not issued_at <= at.astimezone(UTC) < expires_at:
        raise ValueError("counterparty context is not active")
    if expires_at > expected_dispatch_not_after.astimezone(UTC):
        raise ValueError("counterparty context exceeds dispatch expiry")
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


def _dispatch_max_revocation_age(claims: Mapping[str, Any]) -> None:
    bound = claims.get("max_revocation_age_ms")
    if not isinstance(bound, int) or isinstance(bound, bool) or bound <= 0:
        raise ValueError("dispatch max_revocation_age_ms is invalid")


def dispatch_revocation_identity(claims: Mapping[str, Any]) -> tuple[tuple[str, ...], int] | None:
    """Return the delegation jti chain and ALLOW-time epoch a dispatch carries.

    ``None`` when the dispatch predates the pair. A door that requires the
    pair refuses ``None``; the verifier accepts both generations.
    """
    if "delegation_jtis" not in claims:
        return None
    _revocation_identity(claims)
    return tuple(claims["delegation_jtis"]), int(claims["revocation_epoch"])


def dispatch_max_revocation_age_ms(claims: Mapping[str, Any]) -> int | None:
    """Return the principal's bound on revocation-answer age a dispatch carries.

    ``None`` when the key is absent: a dispatch that predates the bound, or
    whose leaf grant stated none. Present only alongside
    :func:`dispatch_revocation_identity`'s pair, never alone; a resource door
    reads it to apply the stricter of the principal's bound and its own freshness bound.
    """
    if "max_revocation_age_ms" not in claims:
        return None
    _dispatch_max_revocation_age(claims)
    return int(claims["max_revocation_age_ms"])


def _foreign_revocation_evidence(value: object) -> None:
    """Validate the closed terminal syntax for B's final foreign clearance."""
    if not isinstance(value, Mapping) or set(value) != {
        "foreign_dispatch_hash",
        "policy_hash",
        "statuses",
        "checked_at",
    }:
        raise ValueError("resource outcome foreign revocation evidence is invalid")
    _digest(
        value.get("foreign_dispatch_hash"),
        "resource outcome foreign revocation evidence dispatch hash",
    )
    _digest(
        value.get("policy_hash"),
        "resource outcome foreign revocation evidence policy hash",
    )
    statuses = value.get("statuses")
    if not isinstance(statuses, list) or any(
        not isinstance(status, Mapping) for status in statuses
    ):
        raise ValueError("resource outcome foreign revocation evidence statuses are invalid")
    _time(
        value.get("checked_at"),
        "resource outcome foreign revocation evidence checked_at",
    )


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
            optional=(_FOREIGN_REVOCATION_EVIDENCE_FIELD,),
        )
        _text(claims.get("customer_id"), "resource outcome customer_id")
        if "foreign_revocation_evidence" in claims:
            _foreign_revocation_evidence(claims["foreign_revocation_evidence"])
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
        optional=(frozenset({"reason"}),),
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
    "COUNTERPARTY_CONTEXT_CONTEXT",
    "COUNTERPARTY_CONTEXT_PROFILE",
    "COUNTERPARTY_PENDING_ACK_CONTEXT",
    "COUNTERPARTY_PENDING_ACK_PROFILE",
    "CUSTOMER_DELETE_PROFILE",
    "DISPATCH_CONTEXT",
    "GIT_PUBLICATION_PROFILE",
    "OUTCOME_CONTEXT",
    "RECONCILIATION_CONTEXT",
    "RESOURCE_PROFILE",
    "counterparty_consent_hash",
    "counterparty_destination_hash",
    "counterparty_foreign_descriptor",
    "counterparty_foreign_descriptor_hash",
    "counterparty_operation_hash",
    "counterparty_pending_ack_approval_expectations",
    "counterparty_pending_ack_message",
    "dispatch_message",
    "git_publication_plan_hash",
    "git_ref_is_covered",
    "outcome_message",
    "payload_bytes",
    "reconciliation_message",
    "resource_binding_hash",
    "validate_counterparty_ingress_url",
    "verify_counterparty_context",
    "verify_counterparty_pending_ack",
    "verify_dispatch",
    "verify_reconciliation",
    "verify_resource_outcome",
]
