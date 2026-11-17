# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Ordered revocation intent/outcome replay with explicit uncertainty."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .admission import _moment
from .hashing import hash_object
from .lifecycle_models import RecordCoverage
from .revocation_evidence import verify_revocation_intent, verify_revocation_request
from .revocation_types import verify_revocation_attestation
from .status_evidence import _status_from_evidence, _status_public_key


def replay_revocation_records(
    records: Sequence[Mapping[str, Any]], policy: Mapping[str, Any] | None
) -> dict[int, RecordCoverage]:
    """Check each retained revocation record without inventing an unobserved mutation."""
    coverage: dict[int, RecordCoverage] = {}
    intents: dict[int, Mapping[str, Any]] = {}
    outcomes: dict[int, Mapping[str, Any]] = {}
    for record in records:
        if record.get("record_type") != "revocation":
            continue
        seq, phase = record["seq"], record.get("phase")
        reason = None
        status = "valid"
        if policy is None:
            status, reason = "not_established", "independent revocation policy roots are required"
        elif phase == "intent":
            deferred = record.get("deferred_from_seq")
            if deferred is not None:
                original = intents.get(deferred)
                outcome = outcomes.get(deferred)
                if original is None or outcome is None or outcome.get("result") != "pending":
                    raise ValueError(
                        "deferred revocation does not answer an earlier pending intent"
                    )
                for name in (
                    "retained",
                    "revocation_request_hash",
                    "authorised_at",
                    "target_jti",
                    "target_content_hash",
                ):
                    if record.get(name) != original.get(name):
                        raise ValueError("deferred revocation changes original authority")
                if _moment(record["recorded_at"]) < _moment(outcome["recorded_at"]):
                    raise ValueError("deferred revocation predates its pending result")
            if not verify_revocation_intent(record, policy):
                status, reason = (
                    "not_established",
                    "historical revocation omits revoker status evidence",
                )
            intents[seq] = record
        elif phase == "outcome":
            intent_seq = record.get("intent_seq")
            intent = intents.get(intent_seq) if type(intent_seq) is int else None
            if (
                intent is None
                or intent_seq in outcomes
                or record.get("revocation_request_hash") != intent.get("revocation_request_hash")
            ):
                raise ValueError("revocation outcome lacks its exact unresolved earlier intent")
            result = record.get("result")
            if result not in {"revoked", "unconfirmed", "pending"}:
                raise ValueError("revocation outcome has unsupported semantics")
            recorded = _moment(record["recorded_at"])
            if recorded < _moment(intent["recorded_at"]):
                raise ValueError("revocation outcome predates its intent")
            if result == "revoked":
                artefact = record["retained"]["status"]
                observed = _status_from_evidence(artefact)
                key = _status_public_key(
                    policy["revocation_attestation_public_keys"], observed.trust_root_id
                )
                if (
                    hash_object(artefact) != record.get("status_artefact_hash")
                    or artefact.get("jti") != intent["target_jti"]
                    or observed.is_revoked is not True
                ):
                    raise ValueError("revocation outcome changes its signed target status")
                if (
                    not _moment(intent["recorded_at"]) <= observed.checked_at <= recorded
                    or key is None
                    or not verify_revocation_attestation(observed, intent["target_jti"], key)
                ):
                    raise ValueError("revocation outcome status signature or ordering is invalid")
            elif record.get("retained") != {} or "status_artefact_hash" in record:
                raise ValueError("uncertain revocation must not invent a successful status")
            assert isinstance(intent_seq, int)
            outcomes[intent_seq] = record
            if coverage[intent_seq].status != "valid":
                status, reason = (
                    "not_established",
                    "revocation outcome depends on unsupported intent authority",
                )
            elif result in {"unconfirmed", "pending"}:
                reason = "explicit unresolved revocation; no successful mutation asserted"
        elif phase == "refusal":
            verify_revocation_request(record, policy["revoker_trust_roots"])
            if not isinstance(record.get("refusal_reason"), str) or not record["refusal_reason"]:
                raise ValueError("revocation refusal reason is missing")
            reason = "signed request refusal; no revocation state transition"
        else:
            status, reason = (
                "not_established",
                "revocation phase needs an explicit authority verifier",
            )
        coverage[seq] = RecordCoverage(seq, "revocation", str(phase), status, reason)
    for seq in intents.keys() - outcomes.keys():
        row = coverage[seq]
        if row.status == "valid":
            coverage[seq] = RecordCoverage(
                seq,
                "revocation",
                "intent",
                "valid",
                "authorized revocation; mutation result remains unknown",
            )
    return coverage
