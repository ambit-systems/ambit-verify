# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Ratification verification: the pure claims, candidate and evidence kernel.

A ratification approves one authority entry's candidate grant. This module
holds the verification-only closure: parse a ratification slip, hash its
claims, rebuild the exact candidate it approved, and re-verify every authority
and status fact the ratification claims against caller-supplied trust roots and
retained status evidence.

Three rules hold the design together:

- the candidate is never an input of trust. It is rebuilt from ``(entry,
  attempt)`` and compared byte for byte, so a candidate edited by hand is
  refused even when its entry fingerprint is right;
- the ratifier's reach is checked with the engine's own attenuation rule, turned
  one level up. Everything in the candidate must fit inside the ratifier's grant
  on every axis, not only the action and the domain;
- revocation state at the ratification moment cannot be re-derived later from a
  live store, so the store's signed status for the leaf and every ancestor is
  copied, hashed into the ratification, and kept beside it.

Trust roots always come from the caller, never from an artefact under
verification. Signing, issuance, ledger admission and live-store acquisition
stay private; the producer imports this exact kernel for its own checks.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from .attenuation import (
    ATTENUATION_RULE_VERSION,
    _holds_right,
    _scope_widening_axis,
    attenuation_rule_hash,
)
from .authority_entry import AuthorityEntry, authority_entry_hash
from .claim_shapes import (
    _LINEAGE_KEYS,
    _parse_dt,
    delegation_content_hash,
    parse_delegation_claims,
)
from .hashing import canonical_iso, canonical_json_bytes, hash_object, sha256_hex
from .models import DelegationClaims
from .revocation_types import verify_revocation_attestation
from .status_evidence import (
    _status_from_evidence as _status_from_evidence,
)
from .status_evidence import (
    _status_public_key as _status_public_key,
)
from .status_evidence import epoch_regression, status_artefact_hash
from .tokens import validate_delegation_chain
from .tokens_slips import (
    SLIP_CONTEXT_RATIFICATION,
    _canonical_key_identity,
    _verify_slip,
    parse_delegation,
)

RATIFICATION_CONTEXT = SLIP_CONTEXT_RATIFICATION

_HISTORICAL_RATIFICATION_RULE_VERSION = f"authority_entry/1;attenuation/{ATTENUATION_RULE_VERSION}"
RATIFICATION_RULE_VERSION = (
    f"authority_entry/1;attenuation/{ATTENUATION_RULE_VERSION};ratifier_reach/2"
)
# A ratifier may hold its key in software or in hardware. The trust root's own
# scheme decides which key verifies one slip, so admitting both here never lets
# a root be checked under a scheme it does not declare.
_RATIFICATION_SCHEMES = frozenset({"ed25519", "p256"})

_RATIFICATION_CLAIM_KEYS = frozenset(
    {
        "ratification_id",
        "entry_id",
        "revision",
        "attempt",
        "authority_entry_hash",
        "candidate_core_hash",
        "rule_version",
        "attenuation_rule_hash",
        "effective_at",
        "ratified_at",
        "nbf",
        "exp",
        "issuer_trust_root_id",
        "ratifier_jti",
        "ratifier_sub",
        "ratifier_trust_root_id",
        "ratifier_leaf_content_hash",
        "ratifier_parents_content_hash",
        "status_evidence_hashes",
        # Injected by the signer so a verifier can resolve which public key to
        # check the slip against; on parse it must equal ratifier_trust_root_id.
        "trust_root_id",
    }
)
_REQUIRED_RATIFICATION_KEYS = _RATIFICATION_CLAIM_KEYS - {"trust_root_id"}
_HEX_DIGITS = frozenset("0123456789abcdef")


# --------------------------------------------------------------------------
# Claims
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RatificationClaims:
    """The verified content of one ratification slip."""

    ratification_id: str
    entry_id: str
    revision: int
    attempt: int
    authority_entry_hash: str
    candidate_core_hash: str
    rule_version: str
    attenuation_rule_hash: str
    effective_at: datetime
    ratified_at: datetime
    nbf: datetime
    exp: datetime
    issuer_trust_root_id: str
    ratifier_jti: str
    ratifier_sub: str
    ratifier_trust_root_id: str
    ratifier_leaf_content_hash: str
    ratifier_parents_content_hash: str
    status_evidence_hashes: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        """Return the canonical projection that is signed and hashed."""
        return {
            "attempt": self.attempt,
            "attenuation_rule_hash": self.attenuation_rule_hash,
            "authority_entry_hash": self.authority_entry_hash,
            "candidate_core_hash": self.candidate_core_hash,
            "effective_at": canonical_iso(self.effective_at),
            "entry_id": self.entry_id,
            "exp": canonical_iso(self.exp),
            "issuer_trust_root_id": self.issuer_trust_root_id,
            "nbf": canonical_iso(self.nbf),
            "ratification_id": self.ratification_id,
            "ratified_at": canonical_iso(self.ratified_at),
            "ratifier_jti": self.ratifier_jti,
            "ratifier_leaf_content_hash": self.ratifier_leaf_content_hash,
            "ratifier_parents_content_hash": self.ratifier_parents_content_hash,
            "ratifier_sub": self.ratifier_sub,
            "ratifier_trust_root_id": self.ratifier_trust_root_id,
            "revision": self.revision,
            "rule_version": self.rule_version,
            "status_evidence_hashes": [dict(entry) for entry in self.status_evidence_hashes],
        }


def _text(claims: Mapping[str, Any], key: str) -> str:
    value = claims.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"ratification {key} must be a non-empty string")
    return value


def _count(claims: Mapping[str, Any], key: str) -> int:
    value = claims.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"ratification {key} must be an integer of at least 1")
    return value


def _digest(claims: Mapping[str, Any], key: str) -> str:
    value = claims.get(key)
    if not isinstance(value, str) or len(value) != 64 or not set(value) <= _HEX_DIGITS:
        raise ValueError(f"ratification {key} must be 64 lower-case hexadecimal characters")
    return value


def _moment(claims: Mapping[str, Any], key: str) -> datetime:
    value = claims.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"ratification {key} must be an ISO-8601 datetime")
    return _parse_dt(value)


def _status_hashes(claims: Mapping[str, Any]) -> list[dict[str, str]]:
    value = claims.get("status_evidence_hashes")
    if not isinstance(value, list):
        raise ValueError("ratification status_evidence_hashes must be a list")
    bound: list[dict[str, str]] = []
    for entry in value:
        if not isinstance(entry, Mapping) or set(entry) != {"jti", "hash"}:
            raise ValueError("each status evidence entry carries only jti and hash")
        jti = entry["jti"]
        digest = entry["hash"]
        if not isinstance(jti, str) or not jti:
            raise ValueError("status evidence jti must be a non-empty string")
        if not isinstance(digest, str) or len(digest) != 64 or not set(digest) <= _HEX_DIGITS:
            raise ValueError("status evidence hash must be 64 hexadecimal characters")
        bound.append({"jti": jti, "hash": digest})
    return bound


def _parse_ratification_claims(claims: Mapping[str, Any]) -> RatificationClaims:
    """Validate a ratification claim set's shape, fail-closed."""
    unknown = set(claims) - _RATIFICATION_CLAIM_KEYS
    if unknown:
        raise ValueError(f"ratification has unsupported top-level keys: {sorted(unknown)}")
    missing = _REQUIRED_RATIFICATION_KEYS - set(claims)
    if missing:
        raise ValueError(f"ratification is missing fields: {sorted(missing)}")
    return RatificationClaims(
        ratification_id=_text(claims, "ratification_id"),
        entry_id=_text(claims, "entry_id"),
        revision=_count(claims, "revision"),
        attempt=_count(claims, "attempt"),
        authority_entry_hash=_digest(claims, "authority_entry_hash"),
        candidate_core_hash=_digest(claims, "candidate_core_hash"),
        rule_version=_text(claims, "rule_version"),
        attenuation_rule_hash=_digest(claims, "attenuation_rule_hash"),
        effective_at=_moment(claims, "effective_at"),
        ratified_at=_moment(claims, "ratified_at"),
        nbf=_moment(claims, "nbf"),
        exp=_moment(claims, "exp"),
        issuer_trust_root_id=_text(claims, "issuer_trust_root_id"),
        ratifier_jti=_text(claims, "ratifier_jti"),
        ratifier_sub=_text(claims, "ratifier_sub"),
        ratifier_trust_root_id=_text(claims, "ratifier_trust_root_id"),
        ratifier_leaf_content_hash=_digest(claims, "ratifier_leaf_content_hash"),
        ratifier_parents_content_hash=_digest(claims, "ratifier_parents_content_hash"),
        status_evidence_hashes=_status_hashes(claims),
    )


def _verified_ratification(token: str, trust_roots: Mapping[str, Any]) -> RatificationClaims:
    """Verify one ratification slip, naming which of the two failures occurred."""
    ok, raw = _verify_slip(
        token, trust_roots, context=RATIFICATION_CONTEXT, allowed_schemes=_RATIFICATION_SCHEMES
    )
    if not ok or raw is None:
        raise ValueError("ratification does not verify")
    try:
        claims = _parse_ratification_claims(raw)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("ratification does not verify") from error
    if raw.get("trust_root_id") != claims.ratifier_trust_root_id:
        raise ValueError("ratification root mismatch")
    return claims


def parse_ratification(
    token: str, *, trust_roots: Mapping[str, Any]
) -> tuple[bool, RatificationClaims | None]:
    """Verify and parse a ratification slip into ``RatificationClaims``.

    The signing root the slip carries must equal the ``ratifier_trust_root_id``
    the claims bind, so a slip signed by one key while naming another is not a
    ratification at all.

    This is the signature-level primitive. It does not check the ratifier's
    credential registration; the producer's issuance path and the bundle
    verifier do.
    """
    try:
        return True, _verified_ratification(token, trust_roots)
    except ValueError:
        return False, None


def ratification_hash(claims: RatificationClaims) -> str:
    """Return the SHA-256 over the verified ratification claims.

    Over the parsed claims, not the token bytes: a stranger recomputes claims,
    not encodings.
    """
    return hash_object(claims.to_dict())


# --------------------------------------------------------------------------
# Candidate, ancestry, and status evidence
# --------------------------------------------------------------------------


def candidate_grant_jti(entry_id: str, revision: int, attempt: int) -> str:
    """Return the identifier the grant for one entry revision and attempt carries.

    Derived, never generated. The ratifier signs it inside the candidate, and
    the activation pointer recomputes it to decide which grant a ratification
    names, so the format lives here alone.
    """
    return f"entry:{entry_id}:r{revision}:a{attempt}"


def build_candidate_core(
    entry: AuthorityEntry, *, attempt: int
) -> tuple[dict[str, Any], bytes, str]:
    """Build the complete authority-bearing claims the grant will carry.

    Deterministic and the only source of a candidate: no generated identifier,
    no clock. Two builds from the same entry and attempt give identical bytes,
    which is what lets the ratifier sign content the issuer can prove it minted.

    Excludes ``ratification_hash``, added at issue, and ``trust_root_id``,
    injected by the signer. Axes an entry cannot state -- capabilities, a named
    set, a quorum -- are absent, so a candidate can never widen on them.

    An entry that permits onward delegation gives the candidate two actions, its
    own action then ``delegate``, in that order. An entry that names enforcement
    points gives the candidate their ``aud``. An entry that states a shared
    ceiling gives the candidate a second bounds entry, the grant's own ceiling
    first and the shared one after it. All three keys are absent when the entry
    states nothing, so the candidate of a v1 entry keeps its bytes.

    The ratifier's own checks then judge both with no new rule: the ratifier
    grant must cover ``delegate`` and the action, and a candidate cannot widen
    the ratifier's audience.
    """
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise ValueError("attempt must be an integer of at least 1")
    core: dict[str, Any] = {
        "jti": candidate_grant_jti(entry.entry_id, entry.revision, attempt),
        "sub": entry.subject,
        "iss": entry.principal,
        "scope_actions": list(entry.scope_actions),
        "scope_domains": list(entry.scope_domains),
        "scope_paths": list(entry.scope_paths),
        "scope_tools": [],
        "nbf": canonical_iso(max(entry.nbf, entry.effective_at)),
        "exp": canonical_iso(entry.exp),
        "parent_jti": None,
        "chain_depth": 0,
        "max_depth": entry.max_depth,
        "bounds": [dict(entry.bound)],
        "authority_entry_hash": authority_entry_hash(entry),
    }
    if entry.onward_delegation:
        core["scope_actions"] = [entry.scope_actions[0], "delegate"]
    if entry.enforcement_points is not None:
        core["aud"] = list(entry.enforcement_points)
    if entry.aggregate_bound is not None:
        core["bounds"] = [dict(entry.bound), dict(entry.aggregate_bound)]
    core_bytes = canonical_json_bytes(core)
    return core, core_bytes, sha256_hex(core_bytes)


def _candidate_claims(core: Mapping[str, Any]) -> DelegationClaims:
    """Parse the candidate core as delegation claims, for the attenuation check.

    The candidate carries its entry hash but not the ratification hash, which
    exists only after signing. The signed-grant rule -- both lineage keys or
    neither -- is applied at issue, when both are present. Here the entry hash
    is set after parsing, so the attenuation axes see exactly what the grant
    will carry.

    ``lineage_pending`` is set for the same reason the keys are stripped: a
    candidate carrying an aggregate bound states a lineage pair it cannot hold
    yet. The issued grant holds both keys and is parsed again with the check
    on, so nothing is waived, only deferred.
    """
    claims = parse_delegation_claims(
        {key: value for key, value in core.items() if key not in _LINEAGE_KEYS},
        lineage_pending=True,
    )
    entry_hash = core.get("authority_entry_hash")
    if not isinstance(entry_hash, str):
        raise ValueError("candidate core carries no authority_entry_hash")
    claims.authority_entry_hash = entry_hash
    return claims


def parents_content_hash(parents: Sequence[DelegationClaims]) -> str:
    """Hash the verified ancestry, nearest parent first, excluding the leaf.

    Distinct from the ledger's ``ancestry_content_hash``, which includes the
    child: a ratification binds what the ratifier held, not what it produced.
    """
    return sha256_hex(canonical_json_bytes([delegation_content_hash(p) for p in parents]))


def ratifier_reach_widening_axis(
    candidate: DelegationClaims,
    parent: DelegationClaims,
    *,
    rule_version: str,
) -> str | None:
    """Return the ratifier-reach widening axis under its signed rule version."""
    if rule_version == _HISTORICAL_RATIFICATION_RULE_VERSION:
        return _scope_widening_axis(candidate, parent)
    if rule_version != RATIFICATION_RULE_VERSION:
        return "ratification_rule_version"
    aggregate_bounds = [bound for bound in candidate.bounds if bound.get("aggregation") is not None]
    parent_aggregate = [bound for bound in parent.bounds if bound.get("aggregation") is not None]
    if not aggregate_bounds or parent_aggregate:
        return _scope_widening_axis(candidate, parent)
    if parent.authority_entry_hash is not None or parent.ratification_hash is not None:
        return "lineage"
    ordinary_candidate_bounds = [
        bound for bound in candidate.bounds if bound.get("aggregation") is None
    ]
    ordinary_axis = _scope_widening_axis(
        replace(candidate, bounds=ordinary_candidate_bounds),
        parent,
    )
    if ordinary_axis is not None:
        return ordinary_axis
    parent_ordinary_by_kind = {
        bound["kind"]: bound for bound in parent.bounds if bound.get("aggregation") is None
    }
    for aggregate_bound in aggregate_bounds:
        kind = aggregate_bound["kind"]
        if kind not in parent_ordinary_by_kind:
            return "aggregate_bound"
        converted_bound = dict(aggregate_bound)
        converted_bound.pop("aggregation", None)
        comparison_bounds = [
            bound for bound in ordinary_candidate_bounds if bound.get("kind") != kind
        ]
        comparison_bounds.append(converted_bound)
        axis = _scope_widening_axis(replace(candidate, bounds=comparison_bounds), parent)
        if axis is not None:
            return axis
    return None


def _verify_ratification_contract(
    claims: RatificationClaims,
    candidate: DelegationClaims,
    leaf: DelegationClaims,
) -> None:
    """Require a supported signed rule identity and validity derivation."""
    if claims.rule_version not in {
        _HISTORICAL_RATIFICATION_RULE_VERSION,
        RATIFICATION_RULE_VERSION,
    }:
        raise ValueError("ratification rule_version is not supported")
    if claims.attenuation_rule_hash != attenuation_rule_hash():
        raise ValueError("ratification attenuation_rule_hash is not supported")
    if not leaf.nbf <= claims.ratified_at <= leaf.exp:
        raise ValueError("ratifier grant is outside its validity window at ratified_at")
    if claims.effective_at != candidate.nbf:
        raise ValueError("ratification effective_at differs from the candidate")
    if claims.nbf != max(candidate.nbf, claims.ratified_at):
        raise ValueError("ratification nbf is not derived from the candidate and ratified_at")
    if claims.exp != min(candidate.exp, leaf.exp):
        raise ValueError("ratification exp is not derived from the candidate and ratifier grant")
    if claims.nbf > claims.exp:
        raise ValueError("ratification validity window is empty")


def verify_ratification_evidence(
    claims: RatificationClaims,
    candidate: DelegationClaims,
    *,
    ratifier_grant_tokens: Sequence[str],
    status_evidence: Sequence[Mapping[str, Any]],
    credential_trust_roots: Mapping[str, Any],
    revocation_trust_roots: Mapping[str, Any],
) -> tuple[DelegationClaims, tuple[DelegationClaims, ...]]:
    """Re-verify every authority and status fact a ratification claims."""
    credential_keys = {
        key
        for value in credential_trust_roots.values()
        if isinstance(value, Mapping)
        and value.get("scheme") == "ed25519"
        and (key := _status_public_key({"root": value}, "root")) is not None
    }
    revocation_keys = {
        key
        for root_id in revocation_trust_roots
        if (key := _status_public_key(revocation_trust_roots, str(root_id))) is not None
    }
    if credential_keys & revocation_keys:
        raise ValueError("credential and revocation trust roots overlap")
    if not ratifier_grant_tokens:
        raise ValueError("no ratifier grant was supplied")
    leaf, parents = _verified_ratifier_binding(
        claims, candidate, ratifier_grant_tokens, credential_trust_roots
    )
    _verify_status_evidence(claims, (leaf, *parents), status_evidence, revocation_trust_roots)
    return leaf, parents


def _verified_ratifier_binding(
    claims: RatificationClaims,
    candidate: DelegationClaims,
    ratifier_grant_tokens: Sequence[str],
    credential_trust_roots: Mapping[str, Any],
) -> tuple[DelegationClaims, tuple[DelegationClaims, ...]]:
    """Re-verify the ratifier's grant, its chain at ``ratified_at``, and every fact bound to it.

    The claims bind the grant's identifier, subject, and content, its ancestry,
    its reach over the candidate, and a key other than the issuer's. Returns the
    grant and its verified parents, nearest parent first.
    """
    leaf_ok, leaf = parse_delegation(ratifier_grant_tokens[0], trust_roots=credential_trust_roots)
    if not leaf_ok or leaf is None:
        raise ValueError("ratifier grant does not verify")
    _verify_ratification_contract(claims, candidate, leaf)
    chain = validate_delegation_chain(
        leaf,
        list(ratifier_grant_tokens[1:]),
        trust_roots=credential_trust_roots,
        evaluation_time=claims.ratified_at,
    )
    if not chain.valid or chain.depth_exceeded:
        raise ValueError(f"ratifier chain invalid: {chain.reason or 'depth exceeded'}")
    if leaf.jti != claims.ratifier_jti or leaf.sub != claims.ratifier_sub:
        raise ValueError("ratifier grant is not the one the ratification names")
    if leaf.sub != claims.ratifier_trust_root_id:
        raise ValueError("ratification key is not the ratifier grant subject")
    if delegation_content_hash(leaf) != claims.ratifier_leaf_content_hash:
        raise ValueError("ratifier grant content differs from the bound hash")
    if parents_content_hash(chain.parent_claims) != claims.ratifier_parents_content_hash:
        raise ValueError("ratifier ancestry differs from the bound hash")
    if not _holds_right(leaf, "delegate", claims.ratified_at):
        raise ValueError("ratifier grant lacks delegate")
    axis = ratifier_reach_widening_axis(candidate, leaf, rule_version=claims.rule_version)
    if axis is not None:
        raise ValueError(f"candidate widens ratifier grant on {axis}")
    if candidate.sub == leaf.sub:
        raise ValueError("ratifier is the candidate subject")
    issuer_key_identity = _canonical_key_identity(
        credential_trust_roots, claims.issuer_trust_root_id
    )
    ratifier_key_identity = _canonical_key_identity(
        credential_trust_roots, claims.ratifier_trust_root_id
    )
    if (
        issuer_key_identity is None
        or ratifier_key_identity is None
        or issuer_key_identity == ratifier_key_identity
    ):
        raise ValueError("issuer key is the ratifier key")
    return leaf, tuple(chain.parent_claims)


def _verify_status_evidence(
    claims: RatificationClaims,
    ratifier_claims: Sequence[DelegationClaims],
    status_evidence: Sequence[Mapping[str, Any]],
    revocation_trust_roots: Mapping[str, Any],
) -> None:
    """Re-verify one bound, signed, fresh status per ratifier identifier, leaf first."""
    if len(status_evidence) != len(ratifier_claims) or len(claims.status_evidence_hashes) != len(
        ratifier_claims
    ):
        raise ValueError("status evidence count does not match the ratifier chain")
    checked: list[Mapping[str, Any]] = []
    for index, (grant, artefact) in enumerate(zip(ratifier_claims, status_evidence, strict=True)):
        if artefact.get("jti") != grant.jti:
            raise ValueError(f"status evidence {index} names another grant")
        bound = claims.status_evidence_hashes[index]
        if bound["jti"] != grant.jti or status_artefact_hash(artefact) != bound["hash"]:
            raise ValueError(f"status evidence for {grant.jti} differs from the bound hash")
        status = _status_from_evidence(artefact)
        freshness_bound_ms = status.freshness_bound_ms
        if (
            not isinstance(freshness_bound_ms, int)
            or isinstance(freshness_bound_ms, bool)
            or freshness_bound_ms < 0
        ):
            raise ValueError(f"status evidence for {grant.jti} has no freshness bound")
        key = _status_public_key(revocation_trust_roots, status.trust_root_id)
        if (
            status.is_revoked
            or not status.verifiable
            or key is None
            or not verify_revocation_attestation(status, grant.jti, key)
        ):
            raise ValueError(f"status evidence for {grant.jti} does not verify")
        horizon = status.checked_at + timedelta(milliseconds=freshness_bound_ms)
        if not status.checked_at <= claims.ratified_at <= horizon:
            raise ValueError(f"status evidence for {grant.jti} is not fresh at ratification")
        checked.append(artefact)
    regressed = epoch_regression(checked)
    if regressed is not None:
        raise ValueError(f"revocation_epoch_regressed for {regressed}")


__all__ = [
    "RATIFICATION_CONTEXT",
    "RatificationClaims",
    "build_candidate_core",
    "candidate_grant_jti",
    "parents_content_hash",
    "parse_ratification",
    "ratification_hash",
    "verify_ratification_evidence",
]
