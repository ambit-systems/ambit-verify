# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Public verification for a foreign customer-delete revocation clearance.

The policy here is a projection of B's admitted counterparty configuration.  It
contains only public, signed inputs and can therefore bind B's dispatch and
terminal evidence without trusting either a caller-provided URL or a live
reader configuration.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from types import MappingProxyType
from typing import Any

from .hashing import hash_object, sha256_hex
from .resource_protocol import (
    CUSTOMER_DELETE_PROFILE,
    counterparty_consent_hash,
    dispatch_max_revocation_age_ms,
    dispatch_revocation_identity,
    validate_counterparty_ingress_url,
    verify_dispatch,
)
from .revocation_types import revocation_source_unavailable, verify_revocation_attestation
from .status_evidence import _status_from_evidence, _status_public_key
from .tokens_slips import parse_delegation

_POLICY_PROFILE = "counterparty-revocation-policy/1"
_HEX = frozenset("0123456789abcdef")
_POINT_SOURCE_FIELDS = frozenset(
    {
        "domain_id",
        "ledger_id",
        "resource_id",
        "resource_binding_hash",
        "profile",
        "public_key",
        "revocation_status_url",
        "revocation_trust_roots",
        "max_revocation_age_ms",
        "consent_delegation_token",
        "consent_parent_delegation_tokens",
    }
)
_POINT_POLICY_FIELDS = frozenset(
    {
        "domain_id",
        "ledger_id",
        "resource_id",
        "resource_binding_hash",
        "profile",
        "public_key",
        "revocation_status_url",
        "revocation_trust_roots",
        "max_revocation_age_ms",
        "consent_hash",
        "consent_delegation_jtis",
    }
)
_STATUS_FIELDS = frozenset(
    {
        "jti",
        "is_revoked",
        "checked_at",
        "freshness_bound_ms",
        "source",
        "verifiable",
        "attestation",
        "trust_root_id",
    }
)


class ForeignRevocationRevokedError(ValueError):
    """Every foreign status verified and at least one fresh answer is revoked."""


@dataclass(frozen=True, slots=True)
class VerifiedForeignDependency:
    """The immutable A dispatch selected by one exact B consent vector."""

    raw_dispatch: str
    dispatch_hash: str
    dispatch_claims: Mapping[str, Any]
    point_id: str
    point_policy: Mapping[str, Any]
    foreign_delegation_jtis: tuple[str, ...]
    foreign_revocation_epoch: int
    effective_max_revocation_age_ms: int


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} is invalid")
    return value


def _digest(value: object, name: str, *, size: int = 64) -> str:
    if not isinstance(value, str) or len(value) != size or set(value) - _HEX:
        raise ValueError(f"{name} is invalid")
    return value


def _positive(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} is invalid")
    return value


def _time(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} is invalid")
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} is invalid") from error
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError(f"{name} is invalid")
    return moment.astimezone(UTC)


def _root_map(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError(f"{name} is invalid")
    copied = dict(value)
    for root_id, root in copied.items():
        _text(root_id, f"{name} identifier")
        if isinstance(root, Mapping):
            _digest(root.get("public_key"), f"{name} public key")
        else:
            _digest(root, f"{name} public key")
    return copied


def _consent_jtis(point: Mapping[str, Any], credential_trust_roots: Mapping[str, Any]) -> list[str]:
    leaf_token = _text(point.get("consent_delegation_token"), "consent delegation token")
    raw_parents = point.get("consent_parent_delegation_tokens")
    if not isinstance(raw_parents, list):
        raise ValueError("consent delegation ancestry is invalid")
    parents = [_text(token, "consent parent delegation token") for token in raw_parents]
    leaf_ok, leaf = parse_delegation(leaf_token, trust_roots=credential_trust_roots)
    if not leaf_ok or leaf is None:
        raise ValueError("consent delegation token does not verify under credential roots")
    claims = [leaf]
    for token in parents:
        parent_ok, parent = parse_delegation(token, trust_roots=credential_trust_roots)
        if not parent_ok or parent is None:
            raise ValueError(
                "consent parent delegation token does not verify under credential roots"
            )
        claims.append(parent)
    if len(parents) != leaf.chain_depth:
        raise ValueError("consent delegation ancestry length differs from signed depth")
    for child, parent in pairwise(claims):
        if child.parent_jti != parent.jti or child.chain_depth != parent.chain_depth + 1:
            raise ValueError("consent delegation ancestry does not form an exact chain")
    if claims[-1].parent_jti is not None or claims[-1].chain_depth != 0:
        raise ValueError("consent delegation ancestry does not terminate at a root")
    jtis = [claim.jti for claim in claims]
    if len(set(jtis)) != len(jtis):
        raise ValueError("consent delegation ancestry has duplicate JTIs")
    return jtis


def _source_point_policy(
    point_id: object,
    point: object,
    credential_trust_roots: Mapping[str, Any],
) -> dict[str, Any]:
    _digest(point_id, "counterparty point id", size=16)
    if not isinstance(point, Mapping) or set(point) not in (
        _POINT_SOURCE_FIELDS,
        _POINT_SOURCE_FIELDS | {"counterparty_context_approval_trust_root_id"},
    ):
        raise ValueError("trusted counterparty point fields are invalid")
    for name in ("domain_id", "ledger_id", "resource_id"):
        _text(point.get(name), f"counterparty point {name}")
    _digest(point.get("resource_binding_hash"), "counterparty point resource binding hash")
    if point.get("profile") != CUSTOMER_DELETE_PROFILE:
        raise ValueError("counterparty point profile is invalid")
    _digest(point.get("public_key"), "counterparty point public key")
    try:
        status_url = validate_counterparty_ingress_url(point.get("revocation_status_url"))
    except ValueError as error:
        raise ValueError("counterparty point revocation status URL is invalid") from error
    roots = _root_map(point.get("revocation_trust_roots"), "counterparty point revocation roots")
    bound = _positive(point.get("max_revocation_age_ms"), "counterparty point max revocation age")
    jtis = _consent_jtis(point, credential_trust_roots)
    return {
        "domain_id": point["domain_id"],
        "ledger_id": point["ledger_id"],
        "resource_id": point["resource_id"],
        "resource_binding_hash": point["resource_binding_hash"],
        "profile": point["profile"],
        "public_key": point["public_key"],
        "revocation_status_url": status_url,
        "revocation_trust_roots": roots,
        "max_revocation_age_ms": bound,
        "consent_hash": counterparty_consent_hash(
            delegation_token=point["consent_delegation_token"],
            parent_delegation_tokens=point["consent_parent_delegation_tokens"],
        ),
        "consent_delegation_jtis": jtis,
    }


def project_foreign_revocation_policy(
    trusted_counterparty_points: Mapping[str, Any], credential_trust_roots: Mapping[str, Any]
) -> dict[str, Any]:
    """Project signed B point configuration into a deterministic public policy.

    The configured consent slips are re-verified under B's admitted credential
    roots.  Their leaf-first JTI vectors, rather than untrusted configuration
    metadata, select foreign B dispatches.
    """
    if not isinstance(trusted_counterparty_points, Mapping):
        raise ValueError("trusted counterparty points are invalid")
    if not isinstance(credential_trust_roots, Mapping) or not credential_trust_roots:
        raise ValueError("credential trust roots are invalid")
    points: dict[str, dict[str, Any]] = {}
    leaves: set[str] = set()
    if any(not isinstance(point_id, str) for point_id in trusted_counterparty_points):
        raise ValueError("trusted counterparty point id is invalid")
    for point_id in sorted(trusted_counterparty_points):
        point_policy = _source_point_policy(
            point_id, trusted_counterparty_points[point_id], credential_trust_roots
        )
        leaf = point_policy["consent_delegation_jtis"][0]
        if leaf in leaves:
            raise ValueError("foreign consent leaves must be unique")
        leaves.add(leaf)
        points[point_id] = point_policy
    return {"profile": _POLICY_PROFILE, "points": points}


def foreign_revocation_policy_points(policy: object) -> dict[str, dict[str, Any]]:
    """Return the validated point map from one closed foreign revocation policy."""
    if not isinstance(policy, Mapping) or set(policy) != {"profile", "points"}:
        raise ValueError("foreign revocation policy fields are invalid")
    if policy.get("profile") != _POLICY_PROFILE or not isinstance(policy.get("points"), Mapping):
        raise ValueError("foreign revocation policy is invalid")
    points: dict[str, dict[str, Any]] = {}
    leaves: set[str] = set()
    if any(not isinstance(point_id, str) for point_id in policy["points"]):
        raise ValueError("foreign policy point id is invalid")
    for point_id in sorted(policy["points"]):
        _digest(point_id, "foreign policy point id", size=16)
        point = policy["points"][point_id]
        if not isinstance(point, Mapping) or set(point) != _POINT_POLICY_FIELDS:
            raise ValueError("foreign policy point fields are invalid")
        copied = dict(point)
        for name in ("domain_id", "ledger_id", "resource_id"):
            _text(copied.get(name), f"foreign policy point {name}")
        _digest(copied.get("resource_binding_hash"), "foreign policy resource binding hash")
        if copied.get("profile") != CUSTOMER_DELETE_PROFILE:
            raise ValueError("foreign policy point profile is invalid")
        _digest(copied.get("public_key"), "foreign policy public key")
        url = _text(copied.get("revocation_status_url"), "foreign policy revocation status URL")
        try:
            validate_counterparty_ingress_url(url)
        except ValueError as error:
            raise ValueError("foreign policy revocation status URL is invalid") from error
        copied["revocation_trust_roots"] = _root_map(
            copied.get("revocation_trust_roots"), "foreign policy revocation roots"
        )
        copied["max_revocation_age_ms"] = _positive(
            copied.get("max_revocation_age_ms"), "foreign policy max revocation age"
        )
        _digest(copied.get("consent_hash"), "foreign policy consent hash")
        jtis = copied.get("consent_delegation_jtis")
        if (
            not isinstance(jtis, list)
            or not jtis
            or any(not isinstance(jti, str) or not jti or jti != jti.strip() for jti in jtis)
            or len(set(jtis)) != len(jtis)
        ):
            raise ValueError("foreign policy consent delegation JTIs are invalid")
        if jtis[0] in leaves:
            raise ValueError("foreign policy consent leaves must be unique")
        leaves.add(jtis[0])
        points[point_id] = copied
    return points


def _dispatch_times(claims: Mapping[str, Any], name: str) -> tuple[datetime, datetime]:
    authorized_at = _time(claims.get("authorized_at"), f"{name} authorized_at")
    not_after = _time(claims.get("not_after"), f"{name} not_after")
    if not_after < authorized_at:
        raise ValueError(f"{name} validity interval is invalid")
    return authorized_at, not_after


def _foreign_dependency(native_dispatch_claims: Mapping[str, Any]) -> Mapping[str, Any] | None:
    value = native_dispatch_claims.get("foreign_dependency")
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != {"dispatch", "policy_hash"}:
        raise ValueError("foreign dependency fields are invalid")
    _text(value.get("dispatch"), "foreign dependency dispatch")
    _digest(value.get("policy_hash"), "foreign dependency policy hash")
    return value


def _verify_foreign_claims(
    raw_dispatch: str,
    point_id: str,
    point: Mapping[str, Any],
    native_dispatch_claims: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        claims = verify_dispatch(raw_dispatch, public_key=point["public_key"])
    except (TypeError, ValueError) as error:
        raise ValueError("foreign dependency dispatch does not verify") from error
    if claims.get("foreign_dependency") is not None:
        raise ValueError("foreign dependency must not nest")
    expected_identity = {
        "enforcement_point_id": point_id,
        "domain_id": point["domain_id"],
        "ledger_id": point["ledger_id"],
        "resource_id": point["resource_id"],
        "resource_binding_hash": point["resource_binding_hash"],
        "profile": CUSTOMER_DELETE_PROFILE,
    }
    if any(claims.get(name) != value for name, value in expected_identity.items()):
        raise ValueError("foreign dependency dispatch point identity differs from policy")
    if claims.get("counterparty_consent_hash") != point["consent_hash"]:
        raise ValueError("foreign dependency consent hash differs from policy")
    if native_dispatch_claims.get("profile") != CUSTOMER_DELETE_PROFILE:
        raise ValueError("native foreign dependency requires customer-delete dispatch")
    for name in (
        "customer_id",
        "payload_hash",
        "action_type",
        "action_boundary",
        "action_domain",
        "action_path",
    ):
        if claims.get(name) != native_dispatch_claims.get(name):
            raise ValueError(
                "foreign dependency dispatch body or action differs from native dispatch"
            )
    foreign_authorized_at, foreign_not_after = _dispatch_times(claims, "foreign dispatch")
    native_authorized_at, _native_not_after = _dispatch_times(
        native_dispatch_claims, "native dispatch"
    )
    if not foreign_authorized_at <= native_authorized_at <= foreign_not_after:
        raise ValueError("native dispatch authorization is outside foreign dispatch interval")
    return claims


def verify_foreign_dependency(
    native_dispatch_claims: Mapping[str, Any], policy: Mapping[str, Any]
) -> VerifiedForeignDependency | None:
    """Select and verify a B dispatch's exact foreign A dependency.

    ``None`` is returned only when no configured foreign consent leaf occurs in
    the B JTI vector and the B dispatch does not carry a dependency.
    """
    if not isinstance(native_dispatch_claims, Mapping):
        raise ValueError("native dispatch claims are invalid")
    points = foreign_revocation_policy_points(policy)
    dependency = _foreign_dependency(native_dispatch_claims)
    try:
        native_identity = dispatch_revocation_identity(native_dispatch_claims)
    except (TypeError, ValueError) as error:
        raise ValueError("native dispatch revocation identity is invalid") from error
    if native_identity is None:
        if dependency is None:
            return None
        raise ValueError("foreign dependency requires native dispatch revocation identity")
    native_jtis = native_identity[0]
    leaf_matches = [
        point_id
        for point_id, point in points.items()
        if point["consent_delegation_jtis"][0] in native_jtis
    ]
    exact_matches = [
        point_id
        for point_id, point in points.items()
        if tuple(point["consent_delegation_jtis"]) == native_jtis
    ]
    if dependency is None:
        if leaf_matches:
            raise ValueError("foreign consent chain requires a foreign dependency")
        return None
    if len(exact_matches) != 1:
        raise ValueError("foreign dependency consent chain does not identify one policy point")
    if dependency["policy_hash"] != hash_object(policy):
        raise ValueError("foreign dependency policy hash differs from installed policy")
    point_id = exact_matches[0]
    point = points[point_id]
    raw_dispatch = dependency["dispatch"]
    claims = _verify_foreign_claims(raw_dispatch, point_id, point, native_dispatch_claims)
    try:
        foreign_identity = dispatch_revocation_identity(claims)
        foreign_bound = dispatch_max_revocation_age_ms(claims)
        native_bound = dispatch_max_revocation_age_ms(native_dispatch_claims)
    except (TypeError, ValueError) as error:
        raise ValueError("foreign dependency dispatch revocation identity is invalid") from error
    if foreign_identity is None:
        raise ValueError("foreign dependency requires signed A revocation identity")
    foreign_jtis, foreign_epoch = foreign_identity
    effective_bounds = [point["max_revocation_age_ms"]]
    if foreign_bound is not None:
        effective_bounds.append(foreign_bound)
    if native_bound is not None:
        effective_bounds.append(native_bound)
    return VerifiedForeignDependency(
        raw_dispatch=raw_dispatch,
        dispatch_hash=sha256_hex(raw_dispatch.encode("utf-8")),
        dispatch_claims=MappingProxyType(dict(claims)),
        point_id=point_id,
        point_policy=MappingProxyType(dict(point)),
        foreign_delegation_jtis=foreign_jtis,
        foreign_revocation_epoch=foreign_epoch,
        effective_max_revocation_age_ms=min(effective_bounds),
    )


def _evidence_time(value: object, name: str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{name} is invalid")
        return value.astimezone(UTC)
    return _time(value, name)


def _verify_statuses(
    statuses: object,
    dependency: VerifiedForeignDependency,
    checked_at: datetime,
) -> None:
    foreign_jtis = dependency.foreign_delegation_jtis
    foreign_epoch = dependency.foreign_revocation_epoch
    if not isinstance(statuses, list) or len(statuses) != len(foreign_jtis):
        raise ValueError("foreign revocation statuses are missing or incomplete")
    bound = dependency.effective_max_revocation_age_ms
    roots = dependency.point_policy["revocation_trust_roots"]
    store_epoch: int | None = None
    revoked = False
    for jti, raw in zip(foreign_jtis, statuses, strict=True):
        if not isinstance(raw, Mapping) or set(raw) not in {
            _STATUS_FIELDS,
            _STATUS_FIELDS | {"revocation_epoch"},
        }:
            raise ValueError("foreign revocation status is malformed")
        try:
            status = _status_from_evidence(raw)
        except (KeyError, TypeError, ValueError, OverflowError) as error:
            raise ValueError("foreign revocation status is malformed") from error
        if raw.get("jti") != jti:
            raise ValueError("foreign revocation status JTI differs from foreign dispatch")
        if not status.verifiable or revocation_source_unavailable(status):
            raise ValueError("foreign revocation status is unavailable")
        public_key = _status_public_key(roots, status.trust_root_id)
        if public_key is None or not verify_revocation_attestation(status, jti, public_key):
            raise ValueError("foreign revocation status attestation does not verify")
        if status.revocation_epoch is None or status.revocation_epoch < foreign_epoch:
            raise ValueError("foreign revocation status is below the A epoch floor")
        if status.checked_at > checked_at or checked_at - status.checked_at > timedelta(
            milliseconds=bound
        ):
            raise ValueError("foreign revocation status is not fresh at gate time")
        if store_epoch is None:
            store_epoch = status.revocation_epoch
        elif status.revocation_epoch != store_epoch:
            raise ValueError("foreign revocation status epochs differ within the A status chain")
        revoked = revoked or status.is_revoked
    if revoked:
        raise ForeignRevocationRevokedError("foreign delegation is revoked")


def verify_foreign_revocation_evidence(
    evidence: Mapping[str, Any] | None,
    *,
    native_dispatch_claims: Mapping[str, Any],
    policy: Mapping[str, Any],
    terminal_recorded_at: datetime | str,
) -> None:
    """Independently validate B's retained final A-clearance evidence.

    This routine validates clearance only.  A verified revocation is distinctly
    reported as :class:`ForeignRevocationRevokedError`; all malformed, stale,
    unavailable, or untrusted answers are ordinary ``ValueError`` failures.
    """
    dependency = verify_foreign_dependency(native_dispatch_claims, policy)
    if dependency is None:
        if evidence is not None:
            raise ValueError("ordinary dispatch must not carry foreign revocation evidence")
        return
    if not isinstance(evidence, Mapping) or set(evidence) != {
        "foreign_dispatch_hash",
        "policy_hash",
        "statuses",
        "checked_at",
    }:
        raise ValueError("foreign revocation evidence fields are invalid")
    _digest(evidence.get("foreign_dispatch_hash"), "foreign revocation evidence dispatch hash")
    _digest(evidence.get("policy_hash"), "foreign revocation evidence policy hash")
    if evidence["foreign_dispatch_hash"] != dependency.dispatch_hash:
        raise ValueError("foreign revocation evidence dispatch hash differs from dependency")
    policy_hash = hash_object(policy)
    if evidence["policy_hash"] != policy_hash:
        raise ValueError("foreign revocation evidence policy hash differs from installed policy")
    checked_at = _time(evidence.get("checked_at"), "foreign revocation evidence checked_at")
    recorded_at = _evidence_time(terminal_recorded_at, "terminal recorded_at")
    foreign_authorized_at, foreign_not_after = _dispatch_times(
        dependency.dispatch_claims, "foreign dispatch"
    )
    native_authorized_at, native_not_after = _dispatch_times(
        native_dispatch_claims, "native dispatch"
    )
    if not (
        foreign_authorized_at <= checked_at < foreign_not_after
        and native_authorized_at <= checked_at < native_not_after
    ):
        raise ValueError("foreign revocation gate time is outside strict dispatch validity")
    if recorded_at < checked_at:
        raise ValueError("terminal was recorded before foreign revocation gate time")
    if recorded_at >= foreign_not_after or recorded_at >= native_not_after:
        raise ValueError("terminal was recorded outside strict dispatch validity")
    _verify_statuses(evidence["statuses"], dependency, checked_at)


__all__ = [
    "ForeignRevocationRevokedError",
    "VerifiedForeignDependency",
    "foreign_revocation_policy_points",
    "project_foreign_revocation_policy",
    "verify_foreign_dependency",
    "verify_foreign_revocation_evidence",
]
