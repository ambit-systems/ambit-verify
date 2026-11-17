# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Pure verification of a signed revocation request and its retained authority."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .admission import _moment, _verify_revocation_status
from .attenuation import _holds_right, _scope_widening_axis
from .claim_shapes import delegation_content_hash
from .credential_registration import credential_registration_error
from .hashing import canonical_iso, hash_object
from .tokens import validate_delegation_chain
from .tokens_slips import SLIP_CONTEXT_REVOCATION, _verify_slip, parse_delegation


def verify_revocation_request(
    record: Mapping[str, Any], roots: Mapping[str, Any]
) -> dict[str, Any]:
    """Verify request signature, exact shape, identity and duplicated record fields."""
    token = record["retained"]["request"]
    valid, raw = _verify_slip(
        token,
        roots,
        context=SLIP_CONTEXT_REVOCATION,
        allowed_schemes=frozenset({"ed25519", "p256"}),
    )
    fields = {
        "revocation_id",
        "jti",
        "target_content_hash",
        "revoker_jti",
        "revoker_sub",
        "revoker_trust_root_id",
        "requested_at",
        "nbf",
        "exp",
        "trust_root_id",
    }
    if (
        not valid
        or not isinstance(raw, Mapping)
        or set(raw) != fields
        or any(not isinstance(v, str) or not v for v in raw.values())
    ):
        raise ValueError("revocation request signature or shape is invalid")
    if (
        raw["trust_root_id"] != raw["revoker_trust_root_id"]
        or raw["revocation_id"] != f"revocation:{raw['jti']}:{raw['revoker_jti']}"
    ):
        raise ValueError("revocation request signer or identity differs")
    claims = {name: value for name, value in raw.items() if name != "trust_root_id"}
    for name in ("requested_at", "nbf", "exp"):
        claims[name] = canonical_iso(_moment(claims[name]))
    if not _moment(claims["nbf"]) <= _moment(claims["requested_at"]) <= _moment(claims["exp"]):
        raise ValueError("revocation request time is outside its signed window")
    if hash_object(claims) != record.get("revocation_request_hash"):
        raise ValueError("revocation record changes the signed request hash")
    duplicate = {
        "target_jti": "jti",
        "revoker_jti": "revoker_jti",
        "revoker_trust_root_id": "revoker_trust_root_id",
        "requested_at": "requested_at",
    }
    if record.get("phase") == "intent":
        duplicate.update(revocation_id="revocation_id", target_content_hash="target_content_hash")
    if any(record.get(name) != claims[key] for name, key in duplicate.items()):
        raise ValueError("revocation record changes the signed request identity")
    return claims


def verify_revocation_intent(record: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    """Verify full authority, or return false for an explicit historical evidence gap."""
    roots = policy["revoker_trust_roots"]
    request = verify_revocation_request(record, roots)
    retained = record["retained"]
    evidence = retained.get("authority_evidence")
    if evidence is None:
        return False
    if (
        not isinstance(evidence, Mapping)
        or set(evidence) != {"profile", "statuses"}
        or evidence["profile"] != "revocation-authority/1"
    ):
        raise ValueError("revocation authority evidence profile is invalid")
    target_ok, target = parse_delegation(
        retained["target"], trust_roots=policy["credential_trust_roots"]
    )
    tokens = retained["revoker"]
    if not isinstance(tokens, list) or not tokens:
        raise ValueError("revocation intent lacks the revoker ancestry")
    leaf_ok, leaf = parse_delegation(tokens[0], trust_roots=roots)
    if not target_ok or target is None or not leaf_ok or leaf is None:
        raise ValueError("revocation target or revoker grant signature is invalid")
    if (
        target.jti != request["jti"]
        or delegation_content_hash(target) != request["target_content_hash"]
    ):
        raise ValueError("revocation request does not bind the exact target")
    if (
        leaf.jti != request["revoker_jti"]
        or leaf.sub != request["revoker_sub"]
        or leaf.sub != request["revoker_trust_root_id"]
    ):
        raise ValueError("revocation request does not bind its exact holder")
    error = credential_registration_error(
        roots,
        request["revoker_trust_root_id"],
        registration_public_keys=policy["credential_registration_public_keys"],
        evaluation_time=_moment(request["requested_at"]),
    )
    if error:
        raise ValueError(error)
    at, recorded = _moment(record["authorised_at"]), _moment(record["recorded_at"])
    if not _moment(request["nbf"]) <= at <= _moment(request["exp"]) or at > recorded:
        raise ValueError("revocation authorization time or append order is invalid")
    chain = validate_delegation_chain(leaf, tokens[1:], trust_roots=roots, evaluation_time=at)
    if not chain.valid or chain.depth_exceeded or not leaf.nbf <= at <= leaf.exp:
        raise ValueError("revoker ancestry or validity window is invalid")
    if (
        not _holds_right(leaf, "delegate", at)
        or set(target.scope_actions) - set(leaf.scope_actions)
        or _scope_widening_axis(target, leaf) is not None
    ):
        raise ValueError("revoker grant does not authorize the exact target revocation")
    grants = (leaf, *chain.parent_claims)
    statuses = evidence["statuses"]
    if not isinstance(statuses, list) or len(statuses) != len(grants):
        raise ValueError("revocation authority omits a required grant status")
    epoch = 0
    previous_comparison = at
    for grant, status in zip(grants, statuses, strict=True):
        comparison = _moment(status["freshness_evaluated_at"])
        if comparison < previous_comparison or comparison > recorded:
            raise ValueError("revocation status comparison is outside authorization order")
        cap = status["freshness_bound_ms"]
        if type(cap) is not int or cap <= 0:
            raise ValueError("revoker status freshness bound is invalid")
        error = _verify_revocation_status(
            status,
            jti=grant.jti,
            roots=policy["revocation_attestation_public_keys"],
            at=comparison,
            admission_age_limit_ms=cap,
            grant_age_limit_ms=grant.max_revocation_age_ms,
            epoch_floor=epoch,
        )
        if error:
            raise ValueError(error)
        epoch = status["revocation_epoch"]
        previous_comparison = comparison
    return True
