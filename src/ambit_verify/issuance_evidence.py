# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Independent authority checks for retained admitted child issuance inputs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .admission import (
    AuthorityAdmission,
    _moment,
    _verify_revocation_status,
    verify_admitted_path,
    verify_authority_admission,
)
from .claim_shapes import delegation_content_hash, parse_delegation_claims
from .hashing import hash_object
from .models import DelegationClaims
from .tokens import validate_delegation_chain

ISSUANCE_EVIDENCE_PROFILE = "admitted-child-issuance/1"


@dataclass(frozen=True)
class IssuanceAuthority:
    """Verified child, parents and admission for one reserved issuance."""

    child: DelegationClaims
    parents: tuple[DelegationClaims, ...]
    admission: AuthorityAdmission
    parent_tokens: tuple[str, ...]
    authentication_hash: str


def _match_request(child: DelegationClaims, parent: DelegationClaims, request: Any) -> None:
    if not isinstance(request, Mapping):
        raise ValueError("issuance request has no exact child claims")
    expected = {
        "jti": child.jti,
        "subject": child.sub,
        "scope_actions": child.scope_actions,
        "scope_domains": child.scope_domains,
        "scope_paths": child.scope_paths,
        "bounds": child.bounds,
        "aud": child.aud,
        "max_depth": child.max_depth,
    }
    for name, value in expected.items():
        if request.get(name) != value:
            raise ValueError(f"issued child changes authenticated {name}")
    if (
        _moment(request.get("expires_at")) != child.exp
        or request.get("scope_tools", parent.scope_tools) != child.scope_tools
        or request.get("named_set_ref") != child.named_set_ref
        or child.max_revocation_age_ms != parent.max_revocation_age_ms
        or child.iss != parent.iss
        or child.approval_quorum is not None
        or child.capabilities
    ):
        raise ValueError("issued child changes authenticated or inherited claims")


def verify_issuance_reservation(
    record: Mapping[str, Any],
    *,
    preceding_by_hash: Mapping[str, Mapping[str, Any]],
    admission_trust_roots_by_adapter: Mapping[str, Mapping[str, Any]],
    expected_domain: str,
    expected_ledger_id: str,
    enforcement_point_id: str,
) -> IssuanceAuthority:
    """Check a reserved child against its exact authenticated admitted request."""
    evidence = record.get("verification_evidence")
    if (
        not isinstance(evidence, Mapping)
        or set(evidence)
        != {
            "profile",
            "authentication_hash",
            "origin_artifacts",
            "parent_statuses",
            "revocation_epoch_floor",
            "child_claims",
        }
        or evidence.get("profile") != ISSUANCE_EVIDENCE_PROFILE
    ):
        raise ValueError("issuance reservation lacks supported independent evidence")
    authentication = preceding_by_hash.get(evidence["authentication_hash"])
    if authentication is None or authentication.get("authentication_kind") != "delegation_issuance":
        raise ValueError("issuance reservation lacks its earlier holder authentication")
    context = authentication["authentication_context"]
    at = _moment(authentication["evaluated_at"])
    # Try only the adapter declared by the independently verified admission.
    from .execution_evidence import _admission_token_adapter

    adapter = _admission_token_adapter(context["admission_token"])
    verified = verify_authority_admission(
        context["admission_token"],
        admission_trust_roots=admission_trust_roots_by_adapter.get(adapter, {}),
        expected_domain=expected_domain,
        expected_ledger_id=expected_ledger_id,
        at=at,
    )
    admission = verified.admission
    if (
        not verified.valid
        or admission is None
        or admission.claims["enforcement_point_id"] != enforcement_point_id
    ):
        raise ValueError("issuance admission does not verify for this point")
    request = authentication["request"]
    tokens = request["parents"]
    child = parse_delegation_claims(evidence["child_claims"])
    chain = validate_delegation_chain(
        child, tokens, trust_roots=admission.claims["credential_trust_roots"], evaluation_time=at
    )
    if not chain.valid or chain.depth_exceeded or not chain.parent_claims:
        raise ValueError("issued child does not narrow its complete parent ancestry")
    parents = tuple(chain.parent_claims)
    if child.nbf != at or request["actor"]["id"] != parents[0].sub:
        raise ValueError("issuance time or holder differs from the authenticated request")
    _match_request(child, parents[0], request["claims"])
    artefacts = evidence["origin_artifacts"]
    if not isinstance(artefacts, Mapping) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in artefacts.items()
    ):
        raise ValueError("issuance origin artefacts are malformed")
    origin = verify_admitted_path(
        tokens[0],
        tokens[1:],
        {name: value.encode("utf-8") for name, value in artefacts.items()},
        admission=admission,
        at=at,
    )
    if not origin.valid:
        raise ValueError("issuance parent does not join its independently admitted origin")
    statuses = evidence["parent_statuses"]
    floor = evidence["revocation_epoch_floor"]
    if (
        type(floor) is not int
        or floor < 0
        or not isinstance(statuses, list)
        or len(statuses) != len(parents)
    ):
        raise ValueError("issuance parent statuses or epoch floor are malformed")
    previous_epoch = floor
    for parent, status in zip(parents, statuses, strict=True):
        error = _verify_revocation_status(
            status,
            jti=parent.jti,
            roots=admission.claims["revocation_attestation_public_keys"],
            at=at,
            admission_age_limit_ms=admission.claims["max_revocation_age_ms"],
            grant_age_limit_ms=parent.max_revocation_age_ms,
            epoch_floor=previous_epoch,
        )
        if error:
            raise ValueError(error)
        previous_epoch = status["revocation_epoch"]
    if (
        record.get("jti") != child.jti
        or record.get("parent_jti") != parents[0].jti
        or record.get("content_hash") != delegation_content_hash(child)
    ):
        raise ValueError("issuance row changes its verified child or parent")
    expected_grant = {
        "parent_content_hash": delegation_content_hash(parents[0]),
        "ancestry_content_hash": hash_object(
            {"child": child.to_dict(), "parents": [p.to_dict() for p in parents]}
        ),
        "parent_ancestry_hash": hash_object(
            {"child": parents[0].to_dict(), "parents": [p.to_dict() for p in parents[1:]]}
        ),
        "sub": child.sub,
        "chain_depth": child.chain_depth,
        "issued_at": child.nbf.isoformat(),
        "authority_entry_hash": child.authority_entry_hash,
        "ratification_hash": child.ratification_hash,
    }
    if record.get("grant") != expected_grant:
        raise ValueError("issuance row changes verified grant identity or ancestry")
    return IssuanceAuthority(
        child, parents, admission, tuple(tokens), str(authentication["record_hash"])
    )
