# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""The authority entry: the buyer's own statement of one delegated authority.

One principal, one subject, one bounded action on one domain, from one moment.
The entry is the source of a grant; the rendered document is a projection of the
entry and is never an input.

Parsing is fail-closed, for the same reason ``claim_shapes`` closes the slip key
sets: a field this parser does not recognise, or a bound that reaches an action
the entry never granted, would otherwise become authority nobody stated. The
hash fixes the parsed content, so key order and surrounding whitespace in the
source file cannot change what was authorised.

Document rendering and revision-authoring helpers (diffing and next-revision
validation) stay private to the producer; a verifier only needs the parsed
entry, its canonical projection and its hash.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .claim_shapes import (
    AGGREGATION_ENTRY,
    PRIVILEGE_TIERS,
    _parse_dt,
    _validate_audience,
    _validate_bounds,
)
from .hashing import canonical_iso, hash_object

_ENTRY_KEYS = frozenset(
    {
        "entry_id",
        "schema_version",
        "revision",
        "prior_revision_hash",
        "principal",
        "issuer_trust_root_id",
        "subject",
        "scope_actions",
        "scope_domains",
        "scope_paths",
        "bound",
        "aggregate_bound",
        "nbf",
        "exp",
        "max_depth",
        "effective_at",
        "onward_delegation",
        "enforcement_points",
    }
)
# Keys an entry may leave out. Revision 1 has no predecessor, so its hash is
# absent; the other two state authority no entry is obliged to state, and an
# entry that leaves them out grants exactly what it granted before they existed.
_OPTIONAL_ENTRY_KEYS = frozenset(
    {"prior_revision_hash", "onward_delegation", "enforcement_points", "aggregate_bound"}
)
_REQUIRED_ENTRY_KEYS = _ENTRY_KEYS - _OPTIONAL_ENTRY_KEYS
_TEXT_KEYS = ("entry_id", "schema_version", "principal", "issuer_trust_root_id", "subject")
_HEX_DIGITS = frozenset("0123456789abcdef")
# The one schema label an entry may carry. The key set does not branch on the
# value, so a second label would be a second meaning nothing here reads.
_SCHEMA_VERSIONS = frozenset({"1"})


@dataclass(frozen=True, slots=True)
class AuthorityEntry:
    """One parsed, validated authority entry.

    Every field is the parsed form: strings are stripped, datetimes are UTC, and
    ``bound`` carries the shape ``claim_shapes._validate_bounds`` accepts.

    ``aggregate_bound`` is that same shape with the window pair required and
    ``aggregation`` set to ``"entry"``: a period ceiling that holds across
    every grant minted from this entry revision, not per grant. It is present
    only when the entry states it.
    """

    entry_id: str
    schema_version: str
    revision: int
    principal: str
    issuer_trust_root_id: str
    subject: str
    scope_actions: list[str]
    scope_domains: list[str]
    scope_paths: list[str]
    bound: dict[str, Any]
    nbf: datetime
    exp: datetime
    max_depth: int
    effective_at: datetime
    prior_revision_hash: str | None = None
    onward_delegation: bool = False
    enforcement_points: list[str] | None = None
    aggregate_bound: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the canonical projection this entry is hashed and diffed over.

        The three optional keys are emitted only when the entry states them, the
        pattern the slip claim's ``aud`` follows, so an entry that states none
        of them keeps the bytes and the hash it had before they existed.
        """
        projection: dict[str, Any] = {
            "entry_id": self.entry_id,
            "schema_version": self.schema_version,
            "revision": self.revision,
            "prior_revision_hash": self.prior_revision_hash,
            "principal": self.principal,
            "issuer_trust_root_id": self.issuer_trust_root_id,
            "subject": self.subject,
            "scope_actions": list(self.scope_actions),
            "scope_domains": list(self.scope_domains),
            "scope_paths": list(self.scope_paths),
            "bound": dict(self.bound),
            "nbf": canonical_iso(self.nbf),
            "exp": canonical_iso(self.exp),
            "max_depth": self.max_depth,
            "effective_at": canonical_iso(self.effective_at),
        }
        if self.onward_delegation:
            projection["onward_delegation"] = True
        if self.enforcement_points is not None:
            projection["enforcement_points"] = list(self.enforcement_points)
        if self.aggregate_bound is not None:
            projection["aggregate_bound"] = dict(self.aggregate_bound)
        return projection


def _text(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"authority entry {key} must be a non-empty string")
    return value.strip()


def _moment(mapping: Mapping[str, Any], key: str) -> datetime:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"authority entry {key} must be an ISO-8601 datetime")
    try:
        return _parse_dt(value.strip())
    except ValueError as error:
        raise ValueError(f"authority entry {key} must be an ISO-8601 datetime") from error


def _exactly_one(mapping: Mapping[str, Any], key: str, noun: str) -> list[str]:
    value = mapping.get(key)
    if not isinstance(value, list) or len(value) != 1:
        raise ValueError(f"authority entry {key} must name exactly one {noun}")
    entry = value[0]
    if not isinstance(entry, str) or not entry.strip():
        raise ValueError(f"authority entry {key} must name exactly one {noun}")
    return [entry.strip()]


def _revision(mapping: Mapping[str, Any]) -> int:
    value = mapping.get("revision")
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("authority entry revision must be an integer of at least 1")
    return value


def _prior_revision_hash(mapping: Mapping[str, Any], revision: int) -> str | None:
    value = mapping.get("prior_revision_hash")
    if revision == 1:
        if value is not None:
            raise ValueError("authority entry revision 1 must not carry prior_revision_hash")
        return None
    if value is None:
        raise ValueError("authority entry revision above 1 requires prior_revision_hash")
    if not isinstance(value, str) or len(value) != 64 or not set(value).issubset(_HEX_DIGITS):
        raise ValueError("authority entry prior_revision_hash must be 64 hexadecimal characters")
    return value


def _onward_delegation(mapping: Mapping[str, Any]) -> bool:
    """Read the optional onward-delegation flag, or refuse a value that is not a bool.

    An absent key is ``False``: the entry grants its one action and nothing
    onward, which is what every entry granted before the key existed.
    """
    if "onward_delegation" not in mapping:
        return False
    value = mapping["onward_delegation"]
    if not isinstance(value, bool):
        raise ValueError("authority entry onward_delegation must be true or false")
    return value


def _enforcement_points(mapping: Mapping[str, Any]) -> list[str] | None:
    """Read the optional enforcement points, under the rule the slip claim applies.

    ``claim_shapes._validate_audience`` is the rule, reused rather than copied:
    the entry states the points the grants it mints will be addressed to, so a
    value the claim would refuse must be refused here, one step earlier.
    """
    value = mapping.get("enforcement_points")
    if value is None:
        return None
    try:
        return _validate_audience(value)
    except ValueError as error:
        raise ValueError(f"authority entry enforcement_points is not valid: {error}") from error


def _aggregate_bound(
    mapping: Mapping[str, Any], *, scope_actions: list[str]
) -> dict[str, Any] | None:
    """Parse the optional shared ceiling, or return None when the entry states none.

    The entry names the scope by the key it uses, so the bound itself must not
    restate ``aggregation``: one fact, one place. The marker is added here, and
    ``_validate_bounds`` then requires the window pair a shared ceiling needs.
    """
    value = mapping.get("aggregate_bound")
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("authority entry aggregate_bound must state exactly one bound")
    if "aggregation" in value:
        raise ValueError(
            "authority entry aggregate_bound must not state aggregation: the key names the scope"
        )
    try:
        return _validate_bounds(
            [{**value, "aggregation": AGGREGATION_ENTRY}], scope_actions=scope_actions
        )[0]
    except ValueError as error:
        raise ValueError(f"authority entry aggregate_bound is not valid: {error}") from error


def parse_authority_entry(mapping: Mapping[str, Any]) -> AuthorityEntry:
    """Parse and validate one authority entry, or raise ``ValueError``.

    Refuses an unknown key, a missing field, a privilege-tier literal in
    ``scope_actions``, a bound whose ``applies_to.actions`` reaches outside
    ``scope_actions``, a revision below 1, a revision above 1 with no
    ``prior_revision_hash``, a first revision that carries one, and any entry
    that does not state exactly one action, exactly one domain, and exactly one
    bound.

    An entry with ``max_depth`` of one or more must either state ``delegate`` as
    its one action or set ``onward_delegation``. The verb permits onward
    delegation of nothing else; the flag permits onward delegation of the one
    action the entry grants; the depth bounds both. Stating the flag with the
    verb says one thing twice and is refused, and the flag without a depth
    states a reach nobody bounded.

    An entry may state one ``aggregate_bound`` beside its ``bound``: a period
    ceiling that holds across every grant minted from this entry revision. It
    requires the window pair, and it must not restate ``aggregation``, which
    the key already names. The per-grant ``bound`` must not state
    ``aggregation`` at all -- an entry states a shared ceiling under its own
    key or not at all.

    ``schema_version`` must be ``"1"``. No module here branches its key set on
    the value, so a second label would name a meaning nothing reads.
    """
    if not isinstance(mapping, Mapping):
        raise ValueError("authority entry must be an object")
    unknown = set(mapping) - _ENTRY_KEYS
    if unknown:
        raise ValueError(f"authority entry has unsupported keys: {sorted(unknown)}")
    missing = _REQUIRED_ENTRY_KEYS - set(mapping)
    if missing:
        raise ValueError(f"authority entry is missing fields: {sorted(missing)}")

    revision = _revision(mapping)
    prior_revision_hash = _prior_revision_hash(mapping, revision)
    text = {key: _text(mapping, key) for key in _TEXT_KEYS}
    schema_version = text["schema_version"]
    if schema_version not in _SCHEMA_VERSIONS:
        raise ValueError(f"authority entry schema_version is not supported: {schema_version}")
    onward_delegation = _onward_delegation(mapping)
    enforcement_points = _enforcement_points(mapping)

    scope_actions = _exactly_one(mapping, "scope_actions", "action")
    privilege_tier_literals = sorted(set(scope_actions) & PRIVILEGE_TIERS)
    if privilege_tier_literals:
        # Same rule as build_delegation_claims: a tier name is not an action
        # type, so it would grant a phantom identifier nothing ever requests.
        raise ValueError(
            "authority entry scope_actions contains privilege-tier names, not action "
            f"types: {privilege_tier_literals}"
        )
    scope_domains = _exactly_one(mapping, "scope_domains", "domain")

    raw_paths = mapping.get("scope_paths")
    if not isinstance(raw_paths, list):
        raise ValueError("authority entry scope_paths must be a list of strings")
    scope_paths: list[str] = []
    for path in raw_paths:
        if not isinstance(path, str) or not path.strip():
            raise ValueError("authority entry scope_paths must be a list of strings")
        scope_paths.append(path.strip())

    raw_bound = mapping.get("bound")
    if not isinstance(raw_bound, Mapping):
        raise ValueError("authority entry bound must state exactly one bound")
    if "aggregation" in raw_bound:
        raise ValueError(
            "authority entry bound must not state aggregation: state a shared ceiling "
            "under aggregate_bound"
        )
    bound = _validate_bounds([dict(raw_bound)], scope_actions=scope_actions)[0]
    aggregate_bound = _aggregate_bound(mapping, scope_actions=scope_actions)

    nbf = _moment(mapping, "nbf")
    exp = _moment(mapping, "exp")
    effective_at = _moment(mapping, "effective_at")
    if exp <= nbf:
        raise ValueError("authority entry exp must be after nbf")
    if effective_at >= exp:
        # The candidate's window starts at max(nbf, effective_at); an
        # effective_at at or after exp would mint an empty window.
        raise ValueError("authority entry effective_at must be before exp")

    max_depth = mapping.get("max_depth")
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 0:
        raise ValueError("authority entry max_depth must not be negative")
    if onward_delegation and scope_actions[0] == "delegate":
        raise ValueError(
            "authority entry onward_delegation must not be stated with the delegate action"
        )
    if onward_delegation and max_depth < 1:
        raise ValueError("authority entry onward_delegation requires max_depth of at least 1")
    if max_depth >= 1 and scope_actions[0] != "delegate" and not onward_delegation:
        raise ValueError(
            f"entry states max_depth {max_depth} but an entry grants one action "
            "and cannot carry delegate"
        )

    return AuthorityEntry(
        entry_id=text["entry_id"],
        schema_version=text["schema_version"],
        revision=revision,
        principal=text["principal"],
        issuer_trust_root_id=text["issuer_trust_root_id"],
        subject=text["subject"],
        scope_actions=scope_actions,
        scope_domains=scope_domains,
        scope_paths=scope_paths,
        bound=bound,
        nbf=nbf,
        exp=exp,
        max_depth=max_depth,
        effective_at=effective_at,
        prior_revision_hash=prior_revision_hash,
        onward_delegation=onward_delegation,
        enforcement_points=enforcement_points,
        aggregate_bound=aggregate_bound,
    )


def authority_entry_hash(entry: AuthorityEntry) -> str:
    """Return the SHA-256 over the entry's canonical projection."""
    return hash_object(entry.to_dict())


__all__ = ["AuthorityEntry", "authority_entry_hash", "parse_authority_entry"]
