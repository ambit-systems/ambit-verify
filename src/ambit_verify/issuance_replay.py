# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Ordered child-issuance state and sibling allocation from verified evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .admission import _moment
from .claim_shapes import delegation_content_hash
from .hashing import hash_object
from .issuance_evidence import (
    ISSUANCE_EVIDENCE_PROFILE,
    IssuanceAuthority,
    verify_issuance_reservation,
)
from .lifecycle_models import RecordCoverage
from .models import DelegationClaims
from .tokens_slips import _verified_slip_signer_id, parse_delegation


@dataclass(frozen=True, slots=True)
class IssuanceReplayState:
    """A unique child grant and its retained allocation state."""

    jti: str
    parent_jti: str
    content_hash: str
    state: str
    reservation_hash: str
    terminal_hash: str | None
    allocation: tuple[tuple[str, str, str, str], ...]


def _allocations(claims: DelegationClaims) -> tuple[tuple[str, str, str, str], ...]:
    return tuple(
        sorted(
            (
                entry["kind"],
                entry["unit"],
                "shared" if entry.get("aggregation") else "per_grant",
                str(entry["amount_scaled"]),
            )
            for entry in claims.bounds
        )
    )


def replay_issuance_records(
    records: Sequence[Mapping[str, Any]],
    *,
    admission_trust_roots_by_adapter: Mapping[str, Mapping[str, Any]],
    expected_domain: str,
    expected_ledger_id: str,
    enforcement_point_id: str,
) -> tuple[dict[int, RecordCoverage], tuple[IssuanceReplayState, ...]]:
    """Validate every supported issuance transition without trusting SQL projections."""
    preceding: dict[str, Mapping[str, Any]] = {}
    coverage: dict[int, RecordCoverage] = {}
    authorities: dict[str, IssuanceAuthority] = {}
    states: dict[str, IssuanceReplayState] = {}
    pins: dict[str, str] = {}
    observed_pins: set[str] = set()
    used_authentications: set[str] = set()
    for record in records:
        if record.get("record_type") != "issuance_event":
            preceding[str(record["record_hash"])] = record
            continue
        seq, event, jti = record["seq"], record.get("event"), record.get("jti")
        if not isinstance(jti, str) or not jti:
            raise ValueError("issuance identifier is missing")
        _moment(record.get("recorded_at"))
        if event == "reserved":
            if record.get("verification_evidence") is None:
                coverage[seq] = RecordCoverage(
                    seq,
                    "issuance_event",
                    event,
                    "not_established",
                    "historical issuance has no independently bound authority evidence",
                )
                preceding[str(record["record_hash"])] = record
                continue
            authority = verify_issuance_reservation(
                record,
                preceding_by_hash=preceding,
                admission_trust_roots_by_adapter=admission_trust_roots_by_adapter,
                expected_domain=expected_domain,
                expected_ledger_id=expected_ledger_id,
                enforcement_point_id=enforcement_point_id,
            )
            if jti in states or authority.authentication_hash in used_authentications:
                raise ValueError("issuance repeats a child or holder authentication")
            used_authentications.add(authority.authentication_hash)
            for claims in (authority.child, *authority.parents):
                content = delegation_content_hash(claims)
                if claims.jti in pins and pins[claims.jti] != content:
                    raise ValueError("issuance changes a permanently pinned grant")
                pins[claims.jti] = content
            parent = authority.parents[0]
            if parent.jti in states and states[parent.jti].state != "committed":
                raise ValueError("issuance parent was not committed")
            entries = _allocations(authority.child)
            expected = [
                {"kind": kind, "unit": unit, "limit_type": limit_type, "amount_scaled": amount}
                for kind, unit, limit_type, amount in entries
            ]
            if record.get("allocation") != expected:
                raise ValueError("issuance allocation differs from verified child bounds")
            ceiling: dict[tuple[str, str], int] = {}
            for kind, unit, limit_type, amount in _allocations(parent):
                if limit_type == "per_grant":
                    ceiling[kind, unit] = ceiling.get((kind, unit), 0) + int(amount)
            charged: dict[tuple[str, str], int] = {}
            for sibling in states.values():
                if sibling.parent_jti == parent.jti and sibling.state in {"pending", "committed"}:
                    for kind, unit, limit_type, amount in sibling.allocation:
                        if limit_type == "per_grant":
                            charged[kind, unit] = charged.get((kind, unit), 0) + int(amount)
            for kind, unit, limit_type, amount in entries:
                if limit_type == "per_grant":
                    charged[kind, unit] = charged.get((kind, unit), 0) + int(amount)
                    if (kind, unit) in ceiling and charged[kind, unit] > ceiling[kind, unit]:
                        raise ValueError("issuance exceeds a verified sibling allocation ceiling")
            authorities[jti] = authority
            states[jti] = IssuanceReplayState(
                jti, parent.jti, pins[jti], "pending", record["record_hash"], None, entries
            )
        elif event == "identity_pinned":
            if jti not in pins:
                coverage[seq] = RecordCoverage(
                    seq,
                    "issuance_event",
                    event,
                    "not_established",
                    "identity pin has no independently verified reservation",
                )
                continue
            if jti in observed_pins or record.get("content_hash") != pins[jti]:
                raise ValueError("issuance identity pin repeats or changes its verified claim")
            observed_pins.add(jti)
        elif event in {"committed", "released"}:
            old = states.get(jti)
            if old is None:
                coverage[seq] = RecordCoverage(
                    seq,
                    "issuance_event",
                    event,
                    "not_established",
                    "terminal issuance has no independently verified reservation",
                )
                continue
            if old.state != "pending":
                raise ValueError("issuance repeats a terminal transition")
            if event == "committed":
                evidence = record.get("verification_evidence")
                if (
                    not isinstance(evidence, Mapping)
                    or set(evidence) != {"profile", "signed_token"}
                    or evidence.get("profile") != ISSUANCE_EVIDENCE_PROFILE
                ):
                    raise ValueError("issuance commitment lacks its exact signed child")
                authority = authorities[jti]
                roots = authority.admission.claims["credential_trust_roots"]
                token = evidence["signed_token"]
                valid, child = parse_delegation(token, trust_roots=roots)
                if not valid or child is None or hash_object(child.to_dict()) != old.content_hash:
                    raise ValueError("issuance commitment changes the reserved child")
                if _verified_slip_signer_id(token, roots) != _verified_slip_signer_id(
                    authority.parent_tokens[-1], roots
                ):
                    raise ValueError("issuance commitment uses another origin signing key")
            states[jti] = IssuanceReplayState(
                old.jti,
                old.parent_jti,
                old.content_hash,
                event,
                old.reservation_hash,
                record["record_hash"],
                old.allocation,
            )
        else:
            coverage[seq] = RecordCoverage(
                seq,
                "issuance_event",
                str(event),
                "not_established",
                "issuance administration event lacks independently verified authority material",
            )
            continue
        coverage[seq] = RecordCoverage(seq, "issuance_event", str(event), "valid")
        preceding[str(record["record_hash"])] = record
    return coverage, tuple(states[key] for key in sorted(states))
