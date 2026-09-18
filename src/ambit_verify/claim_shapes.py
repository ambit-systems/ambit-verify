# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Claim-shape validation for delegation and approval slips.

Given a raw, already signature-verified claims dict, these functions extract
and validate the fields DelegationClaims/ApprovalClaims are built from. This
is the verification-only grammar: it owns "what shape is a claim", the
signature helpers own "is this slip's signature valid", and the chain walk
owns "does this chain narrow correctly".
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast

from .hashing import hash_object, parse_nonnegative_amount_scaled
from .models import Capability, DelegationClaims

# The repeating-window vocabulary, moved here so the public verifier never
# imports the engine's cumulative-window arithmetic. ``cumulative_window``
# still owns the derivation; this is only the token's spelling.
WINDOW_KIND_REPEATING = "repeating"
WINDOW_KINDS = frozenset({WINDOW_KIND_REPEATING})

# The complete privilege vocabulary. ``unknown`` is a legitimate member: an
# action type with no mapping resolves to it and the access rule denies.
PRIVILEGE_TIERS = frozenset({"safe", "privileged", "destructive", "unknown"})


def _parse_dt(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _required_str(claims: dict[str, Any], key: str) -> str:
    value = claims.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _required_str_list(claims: dict[str, Any], key: str) -> list[str]:
    value = claims.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be a list of strings")
    return value


def _optional_str_list(claims: dict[str, Any], key: str) -> list[str]:
    value = claims.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be a list of strings")
    return value


def _required_nonempty_str_list(claims: dict[str, Any], key: str) -> list[str]:
    value = claims.get(key)
    if not isinstance(value, list) or not value:
        raise ValueError(f"{key} must be a non-empty list of strings")
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{key} must be a non-empty list of strings")
        normalized_item = item.strip()
        if normalized_item in seen:
            raise ValueError(f"{key} must not repeat a value")
        seen.add(normalized_item)
        cleaned.append(normalized_item)
    return cleaned


# A capability carries ONLY these keys. Resource constraints (paths/tools/domains) stay slip-level
# in this increment, so a capability that signs an apparent narrower constraint is rejected rather
# than silently ignored — a signed constraint the verifier drops would be an over-grant.
_CAPABILITY_KEYS = frozenset({"actions", "nbf", "exp"})

# Closed top-level key sets. Without this, a signed claim this verifier does
# not recognise is silently dropped rather than rejected — the same shape as
# the bug _CAPABILITY_KEYS already closes one level down, but at the top
# level it is worse: a grant minted WITH a constraint (e.g. a bound) and
# verified by an engine that predates it would be enforced WITHOUT that
# constraint, and nothing would say so. Widening by version skew, the
# inverse of "absence grants nothing". trust_root_id is not part of either
# dataclass — it is injected by the signer (sign_slip_ed25519,
# tokens_ed25519.py:76; prepare_slip_payload_p256, tokens_p256.py:74) so a
# verifier can resolve which public key to check against — and must be
# allowed here or every legitimately signed slip would fail this check.
_DELEGATION_CLAIM_KEYS = frozenset(
    {
        "jti",
        "sub",
        "scope_actions",
        "scope_paths",
        "nbf",
        "exp",
        "scope_tools",
        "scope_domains",
        "iss",
        "parent_jti",
        "chain_depth",
        "max_depth",
        "capabilities",
        "trust_root_id",
        "named_set_ref",
        "bounds",
        "approval_quorum",
        "authority_entry_hash",
        "ratification_hash",
        "aud",
        "max_revocation_age_ms",
    }
)

# The lineage pair: which authority entry a grant was authored from, and which
# ratification approved it. Both or neither -- a grant that names its entry but
# not the approval, or the reverse, states half a provenance nobody can follow.
_LINEAGE_KEYS = ("authority_entry_hash", "ratification_hash")
_HEX_DIGITS = frozenset("0123456789abcdef")


def _validate_lineage(claims: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """Validate the lineage pair's shape: both keys or neither, 64 hex each."""
    present = [key for key in _LINEAGE_KEYS if key in claims]
    if not present:
        return None, None
    if len(present) != len(_LINEAGE_KEYS):
        missing = sorted(set(_LINEAGE_KEYS) - set(present))
        raise ValueError(f"lineage is incomplete: {missing} must be present too")
    values: list[str] = []
    for key in _LINEAGE_KEYS:
        value = claims[key]
        if not isinstance(value, str) or len(value) != 64 or not set(value) <= _HEX_DIGITS:
            raise ValueError(f"{key} must be 64 lower-case hexadecimal characters")
        values.append(value)
    return values[0], values[1]


# An audience entry is a derived enforcement-point id: sixteen lower-case
# hexadecimal characters, the value
# credential_registration.derive_enforcement_point_id returns.
_ENFORCEMENT_POINT_ID_LENGTH = 16


def _validate_max_revocation_age(value: Any) -> int | None:
    """Validate the principal's bound on the age of a revocation answer.

    Absence (None) is valid -- the operator's own bound decides alone, which is
    what every grant stated before the claim existed. Presence means a whole
    number of milliseconds above zero: a bound of zero would admit no answer at
    all, since every answer has some age by the time a rule reads it, and a
    grant that admits nothing is a defect rather than a policy.

    ``bool`` is refused explicitly. It is a subclass of ``int``, so ``True``
    would otherwise pass as a one-millisecond bound.
    """
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError("max_revocation_age_ms must be a whole number of milliseconds above zero")
    return value


def _validate_audience(value: Any) -> list[str] | None:
    """Validate the delegation's audience: which enforcement points may consume it.

    Absence (None) is valid -- a grant with no audience may be consumed at any
    point, which is what every grant stated before the claim existed. Presence
    means a non-empty list (the same convention as bounds and capabilities) of
    distinct enforcement-point ids.
    Does NOT resolve an id against a registration record -- the verifier reads
    no registration store at parse time. See rule_delegation_subject_match for
    the decision-time check against the point that evaluates the request, which
    refuses an addressed grant at a point with no identity.
    """
    if value is None:
        return None
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ValueError("aud must be a non-empty list of non-empty strings when present")
    seen: set[str] = set()
    for item in value:
        if len(item) != _ENFORCEMENT_POINT_ID_LENGTH or not set(item) <= _HEX_DIGITS:
            raise ValueError(
                f"aud entries must be {_ENFORCEMENT_POINT_ID_LENGTH} lower-case "
                "hexadecimal characters"
            )
        if item in seen:
            raise ValueError("aud must not repeat an enforcement point id")
        seen.add(item)
    return list(value)


# A named-set reference carries ONLY these keys, mirroring _CAPABILITY_KEYS'
# fail-closed shape one level down.
_NAMED_SET_REF_KEYS = frozenset({"name", "content_hash", "version"})


def _validate_named_set_ref(value: Any) -> dict[str, Any] | None:
    """Validate a named-set reference's shape.

    Absence (None) is valid -- most grants carry no set constraint. Presence
    means all three fields, exactly.

    Does NOT verify the content_hash against a configured set -- that needs
    policy_config, which is not reachable here (the verifier has no deployment
    config at parse time). See rule_delegation_named_set_scope, which
    re-verifies the hash against the currently configured set at decision
    time, and never trusts this claim's hash alone.
    """
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("named_set_ref must be an object")
    unknown = set(value) - _NAMED_SET_REF_KEYS
    if unknown:
        raise ValueError(f"named_set_ref has unsupported keys: {sorted(unknown)}")
    missing = _NAMED_SET_REF_KEYS - set(value)
    if missing:
        raise ValueError(f"named_set_ref missing fields: {sorted(missing)}")
    name = value["name"]
    if not isinstance(name, str) or not name.strip():
        raise ValueError("named_set_ref.name must be a non-empty string")
    content_hash = value["content_hash"]
    if not isinstance(content_hash, str) or not content_hash.strip():
        raise ValueError("named_set_ref.content_hash must be a non-empty string")
    version = value["version"]
    if not isinstance(version, int) or isinstance(version, bool) or version < 0:
        raise ValueError("named_set_ref.version must be a non-negative integer")
    return {"name": name.strip(), "content_hash": content_hash.strip(), "version": version}


# A bound entry carries only these keys, mirroring _CAPABILITY_KEYS' shape.
# window_epoch/window_duration_ms are optional and validated together -- a
# bound with neither is a plain (non-resetting) ceiling; a bound with both is
# a cumulative bound scoped to one signed accounting period. One present
# without the other is malformed, never defaulted. window_kind is optional and
# says whether that period repeats -- see _validate_bound_window_kind.
# applies_to is optional and declares where the bound is checked -- see
# _validate_bound_applies_to.
_BOUND_REQUIRED_KEYS = frozenset({"kind", "unit", "amount_scaled"})
_BOUND_WINDOW_KEYS = frozenset({"window_epoch", "window_duration_ms"})
_BOUND_APPLIES_TO_KEYS = frozenset({"actions", "boundaries"})
_BOUND_KEYS = (
    _BOUND_REQUIRED_KEYS
    | _BOUND_WINDOW_KEYS
    | frozenset({"applies_to", "aggregation", "window_kind"})
)

# The one scope a bound may accumulate under besides its own grant: the
# authority entry the grant was minted from. Every grant of one entry revision
# carries the same authority_entry_hash, so an aggregate bound makes the
# siblings spend one shared ceiling. A bound that states no aggregation
# accumulates per grant, which is what every bound stated before this key
# existed, and its validated form carries no new key.
AGGREGATION_ENTRY = "entry"
_BOUND_AGGREGATIONS = frozenset({AGGREGATION_ENTRY})


def _validate_bound_aggregation(value: Any) -> str | None:
    """Validate a bound's ``aggregation`` scope.

    Absence (None) is valid and is the per-grant scope. ``"entry"`` is the only
    other scope: an aggregate bound whose running total is shared by every
    grant minted from one entry revision.

    Does NOT check the window pair or the grant's lineage -- see
    :func:`_validate_bounds` for the window and
    :func:`parse_delegation_claims` for the lineage pair the shared scope
    needs to name its sibling set.
    """
    if value is None:
        return None
    if not isinstance(value, str) or value not in _BOUND_AGGREGATIONS:
        raise ValueError(f"bound entry aggregation must be one of: {sorted(_BOUND_AGGREGATIONS)}")
    return value


def _validate_bound_window_kind(value: Any) -> str | None:
    """Validate a bound's ``window_kind``, or return None when it states none.

    Absence is the fixed window: one accounting period, opening at
    ``window_epoch`` and closing ``window_duration_ms`` later, which is what
    every windowed bound stated before this key existed. ``"repeating"`` is
    the only value: the same period length repeats from the epoch onward, and
    the engine's cumulative-window arithmetic derives the one containing the
    decision.

    ``"fixed"`` is refused rather than accepted as a synonym for absence. Two
    encodings of one fact would make two grants with identical authority hash
    differently, and the retained shape is the one with no key at all.

    Does NOT check the window pair -- see :func:`_validate_bounds`, which
    refuses a repeating bound that names no period to repeat.
    """
    if value is None:
        return None
    if value == "fixed":
        raise ValueError(
            "bound entry window_kind must not be 'fixed': a bound that states no "
            "window_kind already states the fixed window"
        )
    if not isinstance(value, str) or value not in WINDOW_KINDS:
        raise ValueError(f"bound entry window_kind must be {WINDOW_KIND_REPEATING!r}")
    return value


def _validate_applies_to_list(value: Any, *, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"bound entry applies_to.{field} must be a non-empty list of strings")
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"bound entry applies_to.{field} must be a non-empty list of strings")
        normalized_item = item.strip()
        if normalized_item in seen:
            raise ValueError(f"bound entry applies_to.{field} must not repeat a value")
        seen.add(normalized_item)
        cleaned.append(normalized_item)
    return cleaned


def _validate_bound_applies_to(
    value: Any, *, scope_actions: list[str]
) -> dict[str, list[str]] | None:
    """Validate a bound's ``applies_to`` sub-object.

    Absence (None) is valid -- the bound applies everywhere the grant
    reaches. Presence means an object carrying only ``actions``/
    ``boundaries``, each -- when present -- a non-empty list of unique,
    non-empty strings.

    ``actions`` values must be a subset of this SAME grant's own signed
    ``scope_actions`` -- the grant cannot reach an action it never granted,
    so a bound naming one is only a mistake (fail-closed, mirroring
    e9b92f0's shape). A privilege-tier literal (safe/privileged/destructive/
    unknown) is rejected outright, same rationale as scope_actions itself:
    it is not an action type and would silently match nothing.

    ``boundaries`` values are NOT checked against anything here -- there is
    no per-grant declared boundary scope to subset against, and no ontology
    dependency at parse time. See rules_magnitude.py's evaluation-time
    check against the ontology's live action and boundary sets (fail-closed
    there too, under a distinct code: ``bound_applicability_invalid``).
    """
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("bound entry applies_to must be an object")
    unknown = set(value) - _BOUND_APPLIES_TO_KEYS
    if unknown:
        raise ValueError(f"bound entry applies_to has unsupported keys: {sorted(unknown)}")
    result: dict[str, list[str]] = {}
    if "actions" in value:
        actions = _validate_applies_to_list(value["actions"], field="actions")
        privilege_tier_literals = sorted(set(actions) & PRIVILEGE_TIERS)
        if privilege_tier_literals:
            raise ValueError(
                f"bound entry applies_to.actions contains privilege-tier names, not action "
                f"types: {privilege_tier_literals}"
            )
        outside_scope = sorted(a for a in actions if a not in set(scope_actions))
        if outside_scope:
            raise ValueError(
                "bound entry applies_to.actions is not a subset of this grant's own "
                f"scope_actions: {outside_scope}"
            )
        result["actions"] = actions
    if "boundaries" in value:
        result["boundaries"] = _validate_applies_to_list(value["boundaries"], field="boundaries")
    if not result:
        raise ValueError("bound entry applies_to must declare at least one of actions/boundaries")
    return result


def _bound_scope(entry: Any) -> tuple[str, str | None]:
    """Check one bound entry's keys and kind, and return its kind and aggregation scope."""
    if not isinstance(entry, Mapping):
        raise ValueError("each bound entry must be an object")
    unknown = set(entry) - _BOUND_KEYS
    if unknown:
        raise ValueError(f"bound entry has unsupported keys: {sorted(unknown)}")
    missing = _BOUND_REQUIRED_KEYS - set(entry)
    if missing:
        raise ValueError(f"bound entry missing fields: {sorted(missing)}")
    kind = entry["kind"]
    if not isinstance(kind, str) or not kind.strip():
        raise ValueError("bound entry kind must be a non-empty string")
    kind = kind.strip()
    aggregation = _validate_bound_aggregation(entry.get("aggregation"))
    return kind, aggregation


def _bound_window(entry: Mapping[str, Any]) -> tuple[str, int] | None:
    """Validate the window pair of one bound entry; return None when it states neither key."""
    has_window_epoch = "window_epoch" in entry
    has_window_duration = "window_duration_ms" in entry
    if has_window_epoch != has_window_duration:
        raise ValueError(
            "bound entry window_epoch and window_duration_ms must be declared together"
        )
    if not has_window_epoch:
        return None
    window_epoch = entry["window_epoch"]
    if not isinstance(window_epoch, str) or not window_epoch.strip():
        raise ValueError("bound entry window_epoch must be a non-empty ISO-8601 string")
    try:
        _parse_dt(window_epoch)
    except ValueError as exc:
        raise ValueError("bound entry window_epoch must be a valid ISO-8601 datetime") from exc
    window_duration_ms = entry["window_duration_ms"]
    if (
        not isinstance(window_duration_ms, int)
        or isinstance(window_duration_ms, bool)
        or window_duration_ms <= 0
    ):
        raise ValueError("bound entry window_duration_ms must be a positive integer")
    return window_epoch.strip(), window_duration_ms


def _validated_bound(
    entry: Mapping[str, Any], kind: str, aggregation: str | None, *, scope_actions: list[str]
) -> dict[str, Any]:
    """Validate one bound entry after its kind, and return its validated form in key order."""
    unit = entry["unit"]
    if not isinstance(unit, str) or not unit.strip():
        raise ValueError("bound entry unit must be a non-empty string")
    amount_scaled = entry["amount_scaled"]
    if parse_nonnegative_amount_scaled(amount_scaled) is None:
        raise ValueError("bound entry amount_scaled must be a non-negative-integer digit string")
    validated_entry: dict[str, Any] = {
        "kind": kind,
        "unit": unit.strip(),
        "amount_scaled": amount_scaled,
    }
    window = _bound_window(entry)
    if window is not None:
        validated_entry["window_epoch"] = window[0]
        validated_entry["window_duration_ms"] = window[1]
    window_kind = _validate_bound_window_kind(entry.get("window_kind"))
    if window_kind is not None:
        if window is None:
            # A repeating period with no period to repeat states nothing.
            # The pair is what the derivation divides by.
            raise ValueError("bound entry window_kind requires window_epoch and window_duration_ms")
        validated_entry["window_kind"] = window_kind
    if aggregation is not None:
        if window is None:
            # A shared ceiling with no accounting period would never reset,
            # so the first sibling to reach it would close the entry for
            # good. The period is what makes the ceiling a rate.
            raise ValueError("bound entry aggregation requires window_epoch and window_duration_ms")
        validated_entry["aggregation"] = aggregation
    applies_to = _validate_bound_applies_to(entry.get("applies_to"), scope_actions=scope_actions)
    if applies_to is not None:
        validated_entry["applies_to"] = applies_to
    return validated_entry


def _validate_bounds(value: Any, *, scope_actions: list[str]) -> list[dict[str, Any]]:
    """Validate the delegation's bounded-quantity list.

    Absence (None) is valid -- most grants carry no quantity bound. Presence
    means a non-empty list (matching capabilities' "present means non-empty"
    convention); each entry carries kind/unit/amount_scaled, exactly, plus an
    optional window_epoch/window_duration_ms pair for a cumulative bound that
    resets on a signed accounting period, an optional applies_to naming where
    the bound is checked (absent means everywhere the grant reaches), and an
    optional aggregation naming which scope the running total accumulates
    under (absent means this grant alone).

    A kind may appear once per scope. One per-grant bound and one aggregate
    bound of the same kind may therefore coexist, and both are checked: the
    grant's own ceiling and the ceiling it shares with its siblings are two
    different limits on the same quantity.

    ``scope_actions`` is this same grant's own signed action scope --
    needed to validate a bound's ``applies_to.actions`` against it.

    amount_scaled must be a canonical non-negative-integer digit string --
    the same representation a magnitude's own amount_scaled uses, never a
    float (hash_object serialises a float through repr, which is not
    byte-identical across independent verifiers). Unit-registry membership
    is NOT verified here -- the verifier has no ontology dependency at parse
    time; see rules_magnitude.py's bound-admissible rule and
    rules_cumulative.py's cumulative-bound-admissible rule.
    """
    if value is None:
        return []
    if not isinstance(value, list) or not value:
        raise ValueError("bounds must be a non-empty list when present")
    validated: list[dict[str, Any]] = []
    # One kind per scope, not one kind per grant: a per-grant ceiling and a
    # shared ceiling of the same kind are two different accounts, and both are
    # checked. Two bounds of one kind in ONE scope are still a contradiction.
    seen_kinds: set[tuple[str, str | None]] = set()
    for entry in value:
        kind, aggregation = _bound_scope(entry)
        if (kind, aggregation) in seen_kinds:
            raise ValueError(f"bound entry kind {kind!r} is declared more than once")
        seen_kinds.add((kind, aggregation))
        validated.append(_validated_bound(entry, kind, aggregation, scope_actions=scope_actions))
    return validated


# An approval-quorum requirement carries ONLY these keys.
_APPROVAL_QUORUM_KEYS = frozenset({"signer_set_ref", "threshold"})


def _validate_approval_quorum(value: Any) -> dict[str, Any] | None:
    """Validate an approval-quorum requirement's shape.

    Absence (None) is valid -- most grants use the existing single-approval
    path unchanged. Presence means both fields, exactly: signer_set_ref
    (validated by the same shape rules as a named-set reference -- a signer
    set IS a named set, just one whose members are trust_root_id strings
    instead of counterparty ids) and a positive integer threshold.

    Does NOT verify the signer set against a configured one, and does NOT
    check any presented quorum bundle against it -- both need policy_config
    and the request fingerprint, neither reachable here. See
    rule_approval_quorum for the decision-time check.
    """
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("approval_quorum must be an object")
    unknown = set(value) - _APPROVAL_QUORUM_KEYS
    if unknown:
        raise ValueError(f"approval_quorum has unsupported keys: {sorted(unknown)}")
    missing = _APPROVAL_QUORUM_KEYS - set(value)
    if missing:
        raise ValueError(f"approval_quorum missing fields: {sorted(missing)}")
    signer_set_ref = _validate_named_set_ref(value["signer_set_ref"])
    if signer_set_ref is None:
        raise ValueError("approval_quorum.signer_set_ref must be an object")
    threshold = value["threshold"]
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError("approval_quorum.threshold must be a positive integer")
    return {"signer_set_ref": signer_set_ref, "threshold": threshold}


_APPROVAL_CLAIM_KEYS = frozenset(
    {
        "jti",
        "approver",
        "request_fingerprint",
        "escalation_record_hash",
        "nbf",
        "exp",
        "trust_root_id",
        # The display contract's pair: the digest of the rendering the approver
        # was shown, and the rendering-spec version that produced it. Both or
        # neither -- a digest with no version cannot be recomputed, and a version
        # with no digest binds nothing. Absent on every approval minted before
        # the display contract, so those verify and hash exactly as before.
        "display_digest",
        "display_contract_version",
    }
)


def parse_display_pair(claims: Mapping[str, Any]) -> tuple[str | None, int | None]:
    """Validate the approval's display pair: both keys or neither.

    Absence (neither key) is valid and is today's approval. Presence means a
    64-character lower-case hexadecimal digest and a whole-number version above
    zero. ``bool`` is refused for the version: it is an ``int`` subclass, so
    ``True`` would otherwise pass as version one.
    """
    present = [key for key in ("display_digest", "display_contract_version") if key in claims]
    if not present:
        return None, None
    if len(present) != 2:
        missing = sorted({"display_digest", "display_contract_version"} - set(present))
        raise ValueError(f"display pair is incomplete: {missing} must be present too")
    digest = claims["display_digest"]
    if not isinstance(digest, str) or len(digest) != 64 or not set(digest) <= _HEX_DIGITS:
        raise ValueError("display_digest must be 64 lower-case hexadecimal characters")
    version = claims["display_contract_version"]
    if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
        raise ValueError("display_contract_version must be a whole number above zero")
    return digest, version


def _parse_capabilities(
    claims: dict[str, Any],
    *,
    scope_actions: list[str],
    slip_nbf: datetime,
    slip_exp: datetime,
) -> list[Capability]:
    """Parse optional structured capabilities — per-action capability TTL.

    Backward-compatible only when the key is *absent*: a missing ``capabilities`` yields ``[]``
    (the slip behaves exactly as a flat-scope slip). A *present* value (including ``null`` or a
    non-list) is validated, and every capability is gated; a violation raises ``ValueError`` so the
    whole delegation is rejected (fail-closed — never silently ignored):

    - the value is a non-empty list (``null`` / non-list is malformed, not "absent");
    - each capability is an object carrying *only* ``actions``/``nbf``/``exp`` — an unknown key
      (e.g. a ``paths`` that looks like a resource constraint) is rejected, so a signed capability
      can never carry an apparent constraint this verifier would ignore;
    - ``actions`` is a non-empty list of non-empty strings, each a subset of the signed
      ``scope_actions`` (a capability can never introduce a new action — no action smuggling);
    - ``exp`` is a required ISO string; ``nbf`` defaults to the slip ``nbf`` when absent;
    - ``slip_nbf <= cap.nbf <= cap.exp <= slip_exp`` (a capability cannot outlive its slip).
    """
    if "capabilities" not in claims:
        return []
    raw = claims["capabilities"]
    if not isinstance(raw, list) or not raw:
        raise ValueError("capabilities must be a non-empty list when present")
    allowed = set(scope_actions)
    capabilities: list[Capability] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError("each capability must be an object")
        unknown = set(entry) - _CAPABILITY_KEYS
        if unknown:
            raise ValueError(f"capability has unsupported keys: {sorted(unknown)}")
        actions = _required_str_list(entry, "actions")
        if not actions or not all(a.strip() for a in actions):
            raise ValueError("capability actions must be non-empty strings")
        if not set(actions).issubset(allowed):
            raise ValueError("capability actions must be a subset of scope_actions")
        if "exp" not in entry or not isinstance(entry["exp"], str):
            raise ValueError("capability exp must be a required ISO datetime string")
        cap_exp = _parse_dt(entry["exp"])
        if "nbf" in entry:
            if not isinstance(entry["nbf"], str):
                raise ValueError("capability nbf must be an ISO datetime string")
            cap_nbf = _parse_dt(entry["nbf"])
        else:
            cap_nbf = slip_nbf
        if not (slip_nbf <= cap_nbf <= cap_exp <= slip_exp):
            raise ValueError("capability window must satisfy slip_nbf <= nbf <= exp <= slip_exp")
        capabilities.append(Capability(actions=actions, nbf=cap_nbf, exp=cap_exp))
    return capabilities


def delegation_content_hash(claims: DelegationClaims) -> str:
    """Hash the canonical verified claims, excluding no signed content.

    Defined here rather than beside the issuance ledger that first needed it:
    the ratification bundle verifier recomputes this hash and must never import
    the ledger.
    """
    return hash_object(claims.to_dict())


def _claim_dt(claims: Mapping[str, Any], key: str) -> datetime:
    """Return *key* as a UTC datetime, refusing anything that is not one."""
    value = claims.get(key)
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value:
        raise ValueError(f"delegation {key} must be an ISO datetime string")
    return _parse_dt(value)


def _require_action_types(delegation: DelegationClaims) -> None:
    """Refuse a delegation whose scope_actions name a privilege tier instead of an action type."""
    privilege_tier_literals = sorted(set(delegation.scope_actions) & PRIVILEGE_TIERS)
    if privilege_tier_literals:
        # Defence in depth: build_delegation_claims already rejects this at
        # mint time, but a hand-crafted slip bypasses the issuer entirely.
        # See issuance.py's build_delegation_claims for why this checks
        # privilege-tier names specifically, not any non-atomic string -- a
        # genuine compound action id (e.g. export_sensitive_data_externally)
        # must still pass through.
        raise ValueError(
            f"delegation scope_actions contains privilege-tier names, not action "
            f"types: {privilege_tier_literals}"
        )


def _require_lineage_for_aggregate_bounds(delegation: DelegationClaims) -> None:
    """Refuse an aggregate bound on a delegation that carries no lineage pair."""
    if delegation.authority_entry_hash is None and any(
        bound.get("aggregation") == AGGREGATION_ENTRY for bound in delegation.bounds
    ):
        # An aggregate bound names its sibling set by the entry hash every
        # grant of one entry revision carries. A grant with no lineage has no
        # sibling set, so the ceiling it states would bind nothing but itself
        # while reading as a shared limit.
        raise ValueError(
            "bound entry aggregation requires the lineage pair: authority_entry_hash "
            "and ratification_hash"
        )


def _optional_chain_string(claims: Mapping[str, Any], name: str, default: str | None) -> str | None:
    """Return one legacy-optional chain string, refusing malformed assertions."""
    if name not in claims:
        return default
    value = claims[name]
    if value is None and name == "parent_jti":
        return None
    if not isinstance(value, str):
        raise ValueError(f"delegation {name} must be a string")
    return value


def _optional_chain_depth(claims: Mapping[str, Any], name: str, default: int) -> int:
    """Return one legacy-optional non-negative chain depth."""
    if name not in claims:
        return default
    value = claims[name]
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"delegation {name} must be a non-negative integer")
    return value


def parse_delegation_claims(
    claims: Mapping[str, Any], *, lineage_pending: bool = False
) -> DelegationClaims:
    """Validate a delegation claim set's shape and return the parsed model.

    One definition of the delegation claim shape, for two callers: the signed
    path (after signature verification) and prebuilt issuance, which signs a
    claim set the caller assembled and must apply the same rules before it
    reserves anything.

    ``lineage_pending`` suppresses one check, and one only: the lineage pair an
    aggregate bound needs. Set it solely for a ratification candidate, whose
    entry hash is attached after parsing and whose ratification hash does not
    exist until the grant is signed. The issued grant carries both keys and is
    parsed again, with the check on.

    Raises ``ValueError`` (or ``KeyError``/``TypeError`` on a malformed value)
    on every refusal; ``parse_delegation`` catches those and reports an invalid
    slip, so an unrecognised or malformed claim never yields a usable grant.
    """
    normalized = dict(claims)
    unknown = set(normalized) - _DELEGATION_CLAIM_KEYS
    if unknown:
        raise ValueError(f"delegation has unsupported top-level keys: {sorted(unknown)}")
    nbf = _claim_dt(normalized, "nbf")
    exp = _claim_dt(normalized, "exp")
    scope_actions = _required_str_list(normalized, "scope_actions")
    authority_entry_hash, ratification_hash = _validate_lineage(normalized)
    delegation = DelegationClaims(
        jti=_required_str(normalized, "jti"),
        sub=_required_str(normalized, "sub"),
        scope_actions=scope_actions,
        scope_paths=_required_str_list(normalized, "scope_paths"),
        nbf=nbf,
        exp=exp,
        scope_tools=_optional_str_list(normalized, "scope_tools"),
        scope_domains=_required_nonempty_str_list(normalized, "scope_domains"),
        iss=cast(str, _optional_chain_string(normalized, "iss", "")),
        parent_jti=_optional_chain_string(normalized, "parent_jti", None),
        chain_depth=_optional_chain_depth(normalized, "chain_depth", 0),
        max_depth=_optional_chain_depth(normalized, "max_depth", 1),
        named_set_ref=_validate_named_set_ref(normalized.get("named_set_ref")),
        bounds=_validate_bounds(normalized.get("bounds"), scope_actions=scope_actions),
        approval_quorum=_validate_approval_quorum(normalized.get("approval_quorum")),
        authority_entry_hash=authority_entry_hash,
        ratification_hash=ratification_hash,
        aud=_validate_audience(normalized.get("aud")),
        max_revocation_age_ms=_validate_max_revocation_age(normalized.get("max_revocation_age_ms")),
    )
    _require_action_types(delegation)
    if not lineage_pending:
        _require_lineage_for_aggregate_bounds(delegation)
    delegation.capabilities = _parse_capabilities(
        normalized,
        scope_actions=delegation.scope_actions,
        slip_nbf=nbf,
        slip_exp=exp,
    )
    return delegation


__all__ = [
    "AGGREGATION_ENTRY",
    "PRIVILEGE_TIERS",
    "WINDOW_KINDS",
    "WINDOW_KIND_REPEATING",
    "delegation_content_hash",
    "parse_delegation_claims",
    "parse_display_pair",
]
