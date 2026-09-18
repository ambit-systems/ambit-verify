# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Claim models shared by the authority engine and the standalone verifier.

The parsed, signature-verified claim sets a delegation or approval slip
carries, plus the deterministic JSON helpers their projections are built from.
Nothing here reads a policy, a store, or the ontology: these are the
verification-only claim shapes the engine's own models also consume.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import UTC, datetime
from typing import Any


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def _to_jsonable_dict(obj: Any) -> dict[str, Any]:
    """Return a JSON-serialisable dict for a dataclass instance."""
    return {str(k): _jsonable(v) for k, v in asdict(obj).items()}


@dataclass(slots=True)
class Capability:
    """A per-action capability with its own non-extendable TTL.

    Per-action capability TTL with slip-level resource constraints — NOT full per-capability
    resource-tuple TTL: ``paths``/``tools``/``domains`` stay slip-level on the parent
    :class:`DelegationClaims`. ``actions`` must be a subset of the slip's signed ``scope_actions``
    and the window must sit within the slip window (``slip.nbf <= nbf <= exp <= slip.exp``).
    Validated at parse time; a malformed capability makes the whole delegation invalid
    (fail-closed), never silently ignored.
    """

    actions: list[str]
    nbf: datetime
    exp: datetime

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict for this object."""
        return _to_jsonable_dict(self)


@dataclass(slots=True)
class DelegationClaims:
    """Parsed and verified delegation token claims.

    Chain fields (``iss``, ``parent_jti``, ``chain_depth``, ``max_depth``)
    default to root-delegation values for backward compatibility with
    tokens that predate delegation chains.
    """

    jti: str
    sub: str
    scope_actions: list[str]
    scope_paths: list[str]
    nbf: datetime
    exp: datetime
    scope_tools: list[str] = field(default_factory=list)
    scope_domains: list[str] = field(default_factory=list)
    iss: str = ""
    parent_jti: str | None = None
    chain_depth: int = 0
    max_depth: int = 1
    capabilities: list[Capability] = field(default_factory=list)
    # {"name": str, "content_hash": str, "version": int} -- membership against
    # an operator-configured named set (e.g. approved counterparties). The
    # content_hash pins which version of the set this grant was issued
    # against; a later edit to the set's members must not silently widen it
    # (HARNESS.md §4.2). See policy/rules_delegation.py for how the hash is
    # re-verified at decision time, never trusted from the claim alone.
    named_set_ref: dict[str, Any] | None = None
    # list[{"kind": str, "unit": str, "amount_scaled": str,
    #        "applies_to"?: {"actions"?: [str], "boundaries"?: [str]}}] --
    # a bounded quantity per kind (never money-shaped as a field; currency
    # is one instance among many). amount_scaled is a canonical digit
    # string, same representation as a magnitude's own amount_scaled --
    # never a float. applies_to declares where the bound is checked;
    # absence of applies_to, or of one of its sub-keys, means the bound
    # applies everywhere the grant reaches on that axis (fail-closed: a
    # bound with no admissible magnitude where it applies denies, it is
    # never silently inert). Unit-registry membership, and applies_to
    # membership against the ontology's live action/boundary sets, are NOT
    # verified here; the verifier has no ontology dependency at parse time. See
    # rules_magnitude.py's bound-admissible rule for the decision-time
    # comparison against a resolved magnitude.
    bounds: list[dict[str, Any]] = field(default_factory=list)
    # {"signer_set_ref": {"name", "content_hash", "version"}, "threshold": int}
    # -- an approval requiring N distinct signatures from an authorised
    # signer set, all over the SAME request fingerprint, rather than a
    # single approver. Additive: the existing single-approval path (a plain
    # approval_token) is untouched for every grant that does not declare
    # this. See rule_approval_quorum for the decision-time check.
    approval_quorum: dict[str, Any] | None = None
    # Lineage: the authority entry this grant was authored from, and the
    # ratification that approved it. Both or neither, 64 lower-case hexadecimal
    # characters each (claim_shapes._validate_lineage). Present only on a grant
    # minted through ratification.py; every other grant carries neither, so
    # existing receipts stay byte-identical. A child may not change or drop a
    # parent's pair (attenuation.py's ``lineage`` axis).
    authority_entry_hash: str | None = None
    ratification_hash: str | None = None
    # Audience: the enforcement points allowed to consume this grant, each a
    # derived enforcement-point id of sixteen lower-case hexadecimal characters
    # (claim_shapes._validate_audience). Absent means any point, which is what
    # every grant stated before the claim existed, so existing receipts stay
    # byte-identical. A child may neither widen nor drop a parent's audience
    # (attenuation.py's ``aud`` axis).
    aud: list[str] | None = None
    # Staleness: how old a signed revocation answer may be for this grant, in
    # milliseconds. The operator's own bound lives on the status the store
    # returns (``RevocationStatus.freshness_bound_ms``); this one belongs to the
    # principal who delegated, and the stricter of the two decides
    # (tokens._revocation_failure). Absent means the operator's bound alone,
    # which is what every grant stated before the claim existed, so existing
    # receipts stay byte-identical. A child may tighten it but may neither
    # loosen nor drop it (attenuation.py's ``revocation_age`` axis).
    max_revocation_age_ms: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict for this object.

        A grant carrying no lineage emits neither lineage key, so its dict --
        and ``delegation_content_hash`` over it -- matches what this claim set
        produced before lineage existed. A grant carrying either key emits
        both, so no two distinct claim sets share one dict. A grant with no
        audience emits no ``aud`` key, and one with no staleness bound emits no
        ``max_revocation_age_ms`` key, for the same reason.
        """
        payload = _to_jsonable_dict(self)
        if self.authority_entry_hash is None and self.ratification_hash is None:
            for key in ("authority_entry_hash", "ratification_hash"):
                payload.pop(key, None)
        if self.aud is None:
            payload.pop("aud", None)
        if self.max_revocation_age_ms is None:
            payload.pop("max_revocation_age_ms", None)
        return payload


@dataclass(slots=True)
class ApprovalClaims:
    """Parsed and verified approval token claims."""

    jti: str
    approver: str
    request_fingerprint: str
    escalation_record_hash: str
    nbf: datetime
    exp: datetime
    # The display digest: the SHA-256 of the canonical rendering of the request
    # the approver was shown (see display.py). Optional -- an approval that
    # states no digest is today's approval, and its dict stays byte-identical.
    # The pair is both-or-neither (parse_approval enforces it), so a stated
    # digest always carries the version whose rendering spec produced it.
    display_digest: str | None = None
    display_contract_version: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict for this object.

        An approval with no display digest emits neither display key, so its
        dict -- and any hash over it -- matches what this claim set produced
        before the display contract existed.
        """
        payload = _to_jsonable_dict(self)
        if self.display_digest is None:
            payload.pop("display_digest", None)
        if self.display_contract_version is None:
            payload.pop("display_contract_version", None)
        return payload


__all__ = [
    "ApprovalClaims",
    "Capability",
    "DelegationClaims",
    "_jsonable",
    "_to_jsonable_dict",
]
