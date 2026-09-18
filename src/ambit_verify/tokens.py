# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Shared delegation-chain semantics for live and historical verification.

This checks signatures, ancestry, attenuation, time and delegation rights.
It does not acquire revocation state. A live caller may supply a parent-status
check at the original per-parent boundary; an offline caller must separately
verify retained status evidence before claiming historical freshness.

The verifier resource profile caps a single retained ancestry at
:data:`MAX_VERIFICATION_CHAIN_DEPTH` entries. This is independent of each
signed grant's ``max_depth`` authority bound and is not part of claim grammar.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .attenuation import _holds_right, _scope_widening_axis
from .models import DelegationClaims
from .tokens_slips import parse_delegation

MAX_VERIFICATION_CHAIN_DEPTH = 64
ParentStatusCheck = Callable[[int, DelegationClaims], tuple[dict[str, Any] | None, str | None]]
CHAIN_RULE_VERSION = "2"
_LEGACY_CHAIN_RULE_VERSION = "1"
_SUPPORTED_CHAIN_RULE_VERSIONS = frozenset({_LEGACY_CHAIN_RULE_VERSION, CHAIN_RULE_VERSION})


@dataclass(frozen=True)
class ChainValidationResult:
    """Result of delegation chain validation."""

    valid: bool
    depth: int
    depth_exceeded: bool
    reason: str = ""
    parent_claims: tuple[DelegationClaims, ...] = ()
    parent_revocation_statuses: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class ChainReplayResult:
    """Result of :func:`replay_delegation_chain`: the chain result plus which rule ran.

    Carries every :class:`ChainValidationResult` field, plus ``rule_version_applied``
    and ``supported``. ``supported`` is ``False`` when the caller named a rule this
    build does not implement -- no rule ran, ``valid`` is ``False``, and
    ``rule_version_applied`` is ``None``, so a caller can never mistake an
    unsupported version for a rule that ran and passed.
    """

    valid: bool
    depth: int
    depth_exceeded: bool
    reason: str
    parent_claims: tuple[DelegationClaims, ...]
    parent_revocation_statuses: tuple[dict[str, Any], ...]
    rule_version_applied: str | None
    supported: bool


def _parent_holds_delegate(
    parent_claims: DelegationClaims, at: datetime, *, rule_version: str
) -> bool:
    """Return whether *parent_claims* holds the right to delegate at *at*, under *rule_version*."""
    if rule_version == _LEGACY_CHAIN_RULE_VERSION:
        return "delegate" in set(parent_claims.scope_actions)
    return _holds_right(parent_claims, "delegate", at)


def _parent_ancestry_failure(
    i: int,
    child_claims: DelegationClaims,
    current: DelegationClaims,
    parent_claims: DelegationClaims,
    check_time: datetime,
) -> tuple[str, int] | None:
    """Return the refusal reason and depth when a verified parent does not continue the chain.

    The parent must be inside its validity window at *check_time*, carry the jti
    that *current* names, and sit exactly one level above *current*. *i* is the
    parent's position in the supplied ancestry, and *child_claims* is the leaf,
    whose depth a discontinuity reports.
    """
    if check_time < parent_claims.nbf or check_time > parent_claims.exp:
        return (
            f"parent token {i} (jti={parent_claims.jti}) is outside its validity window",
            current.chain_depth,
        )
    if current.parent_jti is not None and current.parent_jti != parent_claims.jti:
        return (
            f"parent_jti mismatch at depth {i}: expected {current.parent_jti}, "
            f"got {parent_claims.jti}",
            current.chain_depth,
        )
    expected_parent_depth = current.chain_depth - 1
    if parent_claims.chain_depth != expected_parent_depth:
        return (
            f"chain depth discontinuity at depth {i}: expected parent depth "
            f"{expected_parent_depth}, got {parent_claims.chain_depth}",
            child_claims.chain_depth,
        )
    return None


def _walk_delegation_chain(
    child_claims: DelegationClaims,
    parent_tokens: list[str],
    *,
    evaluation_time: datetime | None = None,
    trust_roots: Mapping[str, Any] | None = None,
    rule_version: str,
    parent_status_check: ParentStatusCheck | None = None,
) -> ChainValidationResult:
    """Walk the delegation chain verifying signatures, scope narrowing, and depth.

    Each parent token is parsed and verified. The chain must satisfy:
    1. Every parent signature is valid
    2. Scope narrows monotonically in space and time (child ⊆ parent; child exp <= parent grant)
    3. chain_depth does not exceed max_depth
    4. parent_jti links match the actual parent JTI
    5. No parent in the chain is revoked
    6. Every parent is within its own validity window (an expired parent invalidates the chain)
    7. The supplied ancestry is complete, nearest-parent-first, and agrees with signed depths
    8. Every parent holds the right to delegate at the evaluation moment, under *rule_version*
       (:func:`_parent_holds_delegate`) -- the verb that permits a child to exist

    ``parent_claims`` carries every parent that passed signature, window, link,
    and depth verification, on a refused result as well as an accepted one.

    Shared by :func:`validate_delegation_chain` (always *rule_version*
    :data:`CHAIN_RULE_VERSION`) and :func:`replay_delegation_chain` (a caller-
    selected rule); neither is public, so a rule this build does not
    implement can never reach the walk.
    """
    verified_parents: list[DelegationClaims] = []
    parent_revocation_statuses: list[dict[str, Any]] = []

    def refused(reason: str, depth: int) -> ChainValidationResult:
        """Refuse, carrying every parent whose signature already verified."""
        return ChainValidationResult(
            valid=False,
            depth=depth,
            depth_exceeded=False,
            reason=reason,
            parent_claims=tuple(verified_parents),
            parent_revocation_statuses=tuple(parent_revocation_statuses),
        )

    if child_claims.chain_depth > MAX_VERIFICATION_CHAIN_DEPTH:
        return refused(
            f"delegation chain exceeds verifier resource limit {MAX_VERIFICATION_CHAIN_DEPTH}",
            child_claims.chain_depth,
        )
    if len(parent_tokens) > MAX_VERIFICATION_CHAIN_DEPTH:
        return refused(
            f"supplied delegation ancestry exceeds verifier resource limit "
            f"{MAX_VERIFICATION_CHAIN_DEPTH}",
            child_claims.chain_depth,
        )
    if not parent_tokens:
        if child_claims.parent_jti is not None or child_claims.chain_depth != 0:
            return refused(
                "incomplete chain: non-root delegation requires its complete parent token ancestry",
                child_claims.chain_depth,
            )
        return ChainValidationResult(
            valid=True, depth=child_claims.chain_depth, depth_exceeded=False
        )
    if len(parent_tokens) != child_claims.chain_depth:
        return refused(
            f"chain depth mismatch: leaf declares depth {child_claims.chain_depth}, "
            f"but {len(parent_tokens)} parent token(s) were supplied",
            child_claims.chain_depth,
        )
    current = child_claims
    for i, parent_token in enumerate(parent_tokens):
        if current.parent_jti is None:
            return refused(
                f"unexpected parent token {i}: current delegation already declares a root",
                child_claims.chain_depth,
            )
        ok, parent_claims = parse_delegation(parent_token, trust_roots=trust_roots)
        if not ok or parent_claims is None:
            return refused(f"parent token {i} signature invalid", current.chain_depth)
        check_time = evaluation_time or datetime.now(UTC)
        ancestry_failure = _parent_ancestry_failure(
            i, child_claims, current, parent_claims, check_time
        )
        if ancestry_failure is not None:
            reason, depth = ancestry_failure
            return refused(reason, depth)
        verified_parents.append(parent_claims)
        widening_axis = _scope_widening_axis(current, parent_claims)
        if widening_axis is not None:
            return refused(
                f"scope widening at depth {i}: {widening_axis}; child scope is "
                f"not a subset of parent",
                current.chain_depth,
            )
        if parent_status_check is not None:
            status_record, revocation_refusal = parent_status_check(i, parent_claims)
            if status_record is not None:
                parent_revocation_statuses.append(status_record)
            if revocation_refusal is not None:
                return refused(revocation_refusal, current.chain_depth)
        if not _parent_holds_delegate(parent_claims, check_time, rule_version=rule_version):
            return refused(
                f"parent_lacks_delegate: parent token {i} "
                f"(jti={parent_claims.jti}) has a child but does not carry delegate",
                current.chain_depth,
            )
        current = parent_claims
    if current.parent_jti is not None or current.chain_depth != 0:
        return refused(
            (
                "incomplete chain: supplied ancestry does not terminate at a root "
                "with chain_depth=0 and no parent_jti"
            ),
            child_claims.chain_depth,
        )
    depth = child_claims.chain_depth
    depth_exceeded = depth > child_claims.max_depth
    return ChainValidationResult(
        valid=True,
        depth=depth,
        depth_exceeded=depth_exceeded,
        parent_claims=tuple(verified_parents),
        parent_revocation_statuses=tuple(parent_revocation_statuses),
    )


def validate_delegation_chain(
    child_claims: DelegationClaims,
    parent_tokens: list[str],
    *,
    evaluation_time: datetime | None = None,
    trust_roots: Mapping[str, Any] | None = None,
    parent_status_check: ParentStatusCheck | None = None,
) -> ChainValidationResult:
    """Walk the delegation chain under :data:`CHAIN_RULE_VERSION`, the current rule.

    Every live caller uses this function; it selects no rule and always applies
    today's. A caller re-checking a chain against the rule a past decision
    record actually used calls :func:`replay_delegation_chain` instead. See
    :func:`_walk_delegation_chain` for what the walk checks.
    """
    return _walk_delegation_chain(
        child_claims,
        parent_tokens,
        evaluation_time=evaluation_time,
        trust_roots=trust_roots,
        rule_version=CHAIN_RULE_VERSION,
        parent_status_check=parent_status_check,
    )


def replay_delegation_chain(
    child_claims: DelegationClaims,
    parent_tokens: list[str],
    *,
    recorded_rule_version: str | None,
    evaluation_time: datetime | None = None,
    trust_roots: Mapping[str, Any] | None = None,
    parent_status_check: ParentStatusCheck | None = None,
) -> ChainReplayResult:
    """Re-walk a chain under the rule a past decision recorded, never today's.

    *recorded_rule_version* is the value a receipt's
    ``delegation.chain_rule_version`` carried: ``None`` for a receipt from
    before that key existed, which read :data:`_LEGACY_CHAIN_RULE_VERSION`;
    a stated value selects that rule by name. A version this build does not
    implement returns ``supported=False`` and ``valid=False`` with reason
    ``"unsupported_chain_rule_version"``, and runs no rule at all -- never a
    silent pass under a rule nobody chose.

    Offline and historical only: this is how a stranger holding a retained
    receipt (:func:`~ambit_verify.credential_evidence.verify_receipt_credentials`)
    re-verifies its chain evidence under the rule that actually decided it.
    Nothing in the live decision path calls this function.
    """
    if recorded_rule_version is None:
        rule_version = _LEGACY_CHAIN_RULE_VERSION
    elif recorded_rule_version in _SUPPORTED_CHAIN_RULE_VERSIONS:
        rule_version = recorded_rule_version
    else:
        return ChainReplayResult(
            valid=False,
            depth=child_claims.chain_depth,
            depth_exceeded=False,
            reason="unsupported_chain_rule_version",
            parent_claims=(),
            parent_revocation_statuses=(),
            rule_version_applied=None,
            supported=False,
        )
    result = _walk_delegation_chain(
        child_claims,
        parent_tokens,
        evaluation_time=evaluation_time,
        trust_roots=trust_roots,
        rule_version=rule_version,
        parent_status_check=parent_status_check,
    )
    return ChainReplayResult(
        valid=result.valid,
        depth=result.depth,
        depth_exceeded=result.depth_exceeded,
        reason=result.reason,
        parent_claims=result.parent_claims,
        parent_revocation_statuses=result.parent_revocation_statuses,
        rule_version_applied=rule_version,
        supported=True,
    )
