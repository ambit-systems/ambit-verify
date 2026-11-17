# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Ordered execution links that a terminal-only bundle check cannot cover."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .lifecycle_models import RecordCoverage
from .native_start import validate_start_history, validate_terminal_start_record
from .resource_protocol import verify_dispatch


@dataclass
class OperationLinks:
    """Retain each observed link while checking one canonical prefix."""

    decision: Mapping[str, Any]
    intent: Mapping[str, Any] | None = None
    fence: Mapping[str, Any] | None = None
    start: Mapping[str, Any] | None = None
    transports: list[Mapping[str, Any]] = field(default_factory=list)
    settlement: Mapping[str, Any] | None = None
    resume: Mapping[str, Any] | None = None
    pending: Mapping[str, Any] | None = None
    authentications: list[Mapping[str, Any]] = field(default_factory=list)


def _operation(record: Mapping[str, Any]) -> Mapping[str, Any] | None:
    value = record.get("operation")
    consumption = record.get("consumption")
    if record.get("record_type") == "decision" and isinstance(consumption, Mapping):
        value = consumption.get("operation")
    return value if isinstance(value, Mapping) else None


def _identity(value: Mapping[str, Any]) -> tuple[str, str]:
    domain, operation = value.get("domain_id"), value.get("operation_id")
    if not isinstance(domain, str) or not domain or not isinstance(operation, str) or not operation:
        raise ValueError("lifecycle operation identity is missing")
    return domain, operation


def _same_fields(
    child: Mapping[str, Any], parent: Mapping[str, Any], names: tuple[str, ...]
) -> None:
    for name in names:
        if name not in child or child[name] != parent.get(name):
            raise ValueError(f"lifecycle {child.get('record_type')} changes {name}")


def _intent(record: Mapping[str, Any], links: OperationLinks) -> None:
    decision = links.decision
    consumption = decision["consumption"]
    if consumption["state"] != "authorized" or links.intent is not None or links.settlement:
        raise ValueError("intent is not the unique intent of an authorized operation")
    if record.get("decision_seq") != decision["seq"] or _operation(record) != _operation(decision):
        raise ValueError("intent does not join the exact earlier decision and operation")
    _same_fields(record, decision, ("adapter_id", "actor_id", "request_fingerprint"))
    links.intent = record


def _transport(record: Mapping[str, Any], links: OperationLinks) -> None:
    decision, intent, fence = links.decision, links.intent, links.fence
    if intent is None or fence is None or links.settlement is not None:
        raise ValueError("transport outcome lacks an unresolved earlier dispatch fence")
    if record.get("intent_seq") != intent["seq"] or record.get("decision_seq") != decision["seq"]:
        raise ValueError("transport outcome changes its exact decision or intent")
    _same_fields(
        record,
        decision,
        (
            "adapter_id",
            "actor_id",
            "request_fingerprint",
            "ontology_hash",
            "policy_hash",
            "decision",
        ),
    )
    for name in ("actor", "action", "object"):
        _same_fields(record, decision, (name,))
    evidence, original = record.get("evidence"), decision.get("evidence")
    if not isinstance(evidence, Mapping) or not isinstance(original, Mapping):
        raise ValueError("transport outcome lacks retained action evidence")
    for name in ("request_envelope", "authority_admission", "actor_proof", "enforcement_point_id"):
        if evidence.get(name) != original.get(name):
            raise ValueError(f"transport outcome changes retained {name}")
    if record.get("dry_run") is not False or type(record.get("success")) not in (bool, type(None)):
        raise ValueError("transport outcome has invalid dry-run or tri-state success")
    if "success" not in record:
        raise ValueError("transport outcome must retain unknown success explicitly")
    if links.transports and (
        links.resume is None
        or not links.transports[-1]["seq"] < links.resume["seq"] < record["seq"]
    ):
        raise ValueError("duplicate transport outcome without a new counterparty resume")
    links.transports.append(record)


def _unsigned_generic_fence(record: Mapping[str, Any], links: OperationLinks) -> None:
    decision = links.decision
    evidence = decision["evidence"]
    binding = evidence["authority_admission"]["resource_binding"]
    call = evidence["request_envelope"]["call"]
    profile = binding.get("outcome_profile")
    generic = profile is None or (
        profile == "customer-delete/1" and call.get("name") != "customer.delete"
    )
    descriptor = _operation(decision)
    assert descriptor is not None
    expected = {name: descriptor[name] for name in ("operation_id", "request_hash", "payload_hash")}
    if (
        not generic
        or decision["consumption"]["accounts"]
        or record.get("dispatch_claims") != expected
    ):
        raise ValueError("unsigned generic fence has unsupported action or accounting claims")


def validate_lifecycle_links(
    records: Sequence[Mapping[str, Any]],
    *,
    expected_domain: str,
    expected_ledger_id: str,
    enforcement_point_id: str,
    enforcement_point_public_key: str,
) -> tuple[dict[tuple[str, str], OperationLinks], tuple[RecordCoverage, ...]]:
    """Check every execution record in order; retain every unsupported record."""
    operations: dict[tuple[str, str], OperationLinks] = {}
    by_decision: dict[int, OperationLinks] = {}
    preceding: list[Mapping[str, Any]] = []
    coverage: list[RecordCoverage] = []
    for record in records:
        links: OperationLinks | None
        kind, event = record.get("record_type"), record.get("event")
        status, reason = "valid", None
        if kind == "decision":
            descriptor = _operation(record)
            if descriptor is not None:
                if any(
                    descriptor.get(name) != expected
                    for name, expected in (
                        ("domain_id", expected_domain),
                        ("ledger_id", expected_ledger_id),
                        ("enforcement_point_id", enforcement_point_id),
                    )
                ):
                    raise ValueError(
                        "decision operation does not match the admitted domain and point"
                    )
                identity = _identity(descriptor)
                if identity in operations:
                    raise ValueError("duplicate canonical operation decision")
                links = OperationLinks(record)
                operations[identity] = links
                by_decision[int(record["seq"])] = links
            elif record.get("dry_run") is not True and record.get("decision") == "ALLOW":
                raise ValueError("consequential authorization has no canonical consumption")
        elif kind in {"consequence_intent", "outcome"}:
            decision_seq = record.get("decision_seq")
            links = by_decision.get(decision_seq) if type(decision_seq) is int else None
            if links is None:
                raise ValueError("orphan lifecycle record has no earlier canonical decision")
            if kind == "consequence_intent":
                _intent(record, links)
            else:
                _transport(record, links)
        elif kind == "native_start":
            identity = _identity(record)
            links = operations.get(identity)
            if links is None or links.fence is None or links.settlement is not None:
                raise ValueError("native Start lacks an unresolved earlier operation fence")
            if links.fence.get("dispatch_token") is None:
                raise ValueError("unsigned generic fence cannot establish native Start")
            if links.start is not None:
                raise ValueError("duplicate native Start")
            validate_start_history(
                record, preceding, authority_public_key=enforcement_point_public_key
            )
            links.start = record
        elif kind == "consumption":
            descriptor = _operation(record)
            if event == "counterparty_cancelled":
                pass  # The accounting replay verifies the complete signed cancellation.
            elif event == "authentication" and descriptor is None:
                pass  # The accounting replay verifies the issuance holder and consumed nonce.
            else:
                links = operations.get(_identity(descriptor)) if descriptor is not None else None
                if links is None or descriptor != _operation(links.decision):
                    raise ValueError("consumption event changes or omits its earlier operation")
                if event == "authentication":
                    links.authentications.append(record)
                elif event == "dispatch_fenced":
                    if links.intent is None or links.fence is not None or links.settlement:
                        raise ValueError("dispatch fence does not follow its unique intent")
                    if record.get("intent_hash") != links.intent["record_hash"]:
                        raise ValueError("dispatch fence changes its canonical intent")
                    token, claims = record.get("dispatch_token"), record.get("dispatch_claims")
                    if token is None:
                        _unsigned_generic_fence(record, links)
                        reason = "generic transport fenced; external result remains unknown"
                    elif not isinstance(token, str) or not isinstance(claims, Mapping):
                        raise ValueError("lifecycle dispatch evidence is malformed")
                    elif verify_dispatch(token, public_key=enforcement_point_public_key) != dict(
                        claims
                    ):
                        raise ValueError("dispatch signature differs from the retained claims")
                    links.fence = record
                elif event == "counterparty_pending":
                    if not links.transports or links.pending is not None:
                        raise ValueError(
                            "counterparty pending lacks its unique preceding transport"
                        )
                    if (
                        links.resume is not None
                        and links.transports[-1]["seq"] < links.resume["seq"]
                    ):
                        raise ValueError("counterparty pending precedes its resumed transport")
                    links.pending = record
                elif event == "counterparty_resume_fenced":
                    if links.pending is None:
                        raise ValueError("counterparty resume lacks its unique pending state")
                    links.resume = record
                    links.pending = None
                elif event == "settlement":
                    if links.fence is not None and links.fence.get("dispatch_token") is None:
                        raise ValueError(
                            "unsigned generic fence cannot establish a terminal outcome"
                        )
                    if links.settlement is not None:
                        raise ValueError("duplicate terminal settlement")
                    if links.fence is not None:
                        claims = links.fence.get("dispatch_claims", {})
                        if (
                            claims.get("profile") == "git-publication/1"
                            and record.get("status") == "committed"
                            and links.start is None
                        ):
                            raise ValueError(
                                "current Git commitment requires its exact native Start"
                            )
                    validate_terminal_start_record(record, preceding)
                    links.settlement = record
                elif event == "counterparty_recovered":
                    validate_terminal_start_record(record, preceding)
                else:
                    raise ValueError("unsupported consumption event")
        elif kind == "rejection":
            if (
                not isinstance(record.get("reason"), str)
                or not record["reason"]
                or any(not isinstance(record.get(name), str) for name in ("actor_id", "adapter_id"))
                or type(record.get("dry_run")) is not bool
            ):
                raise ValueError("rejection observation has an invalid required field")
            if any(name in record for name in ("operation", "consumption", "resource_outcome")):
                raise ValueError("rejection observation cannot assert a lifecycle transition")
            reason = "refusal observation; no operation or accounting transition"
        else:
            status, reason = "not_established", "record semantics need an explicit verifier"
        coverage.append(
            RecordCoverage(
                int(record["seq"]), str(kind), str(event) if event else None, status, reason
            )
        )
        preceding.append(record)
    return operations, tuple(coverage)


def dispatch_token_hash(links: OperationLinks) -> str | None:
    """Identify the exact signed dispatch without copying its credential into a report."""
    token = links.fence.get("dispatch_token") if links.fence is not None else None
    return hashlib.sha256(token.encode()).hexdigest() if isinstance(token, str) else None
