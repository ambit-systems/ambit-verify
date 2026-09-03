# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Semantic verification for decision-to-consequence receipt links."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .verify import read_verified_records

_DECISIONS = frozenset({"ALLOW", "DENY", "ESCALATE"})
_HEX_DIGITS = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class ReceiptLinkIssue:
    """One semantic failure in a receipt ledger."""

    code: str
    message: str
    seq: int | None = None
    related_seq: int | None = None


@dataclass(frozen=True)
class ReceiptConsequence:
    """One decision and the consequence records that name it."""

    decision_seq: int
    decision: str
    actor_id: str
    adapter_id: str
    request_fingerprint: str
    intent_seqs: tuple[int, ...]
    outcome_seqs: tuple[int, ...]
    outcome_states: tuple[str, ...]


@dataclass(frozen=True)
class ReceiptRefusal:
    """One denied or escalated decision and whether it demonstrably blocked."""

    seq: int
    record_hash: str | None
    decision: str
    actor_id: str
    adapter_id: str
    request_fingerprint: str
    governance_mode: str
    matched_rule_id: str | None
    blocked: bool
    genuine: bool
    required_authority: Mapping[str, Any] | None


@dataclass(frozen=True)
class ReceiptLinkReport:
    """Chain and semantic verification result for a receipt ledger."""

    chain_ok: bool
    record_count: int
    decision_count: int
    allow_count: int
    refusal_count: int
    genuine_refusal_count: int
    intent_count: int
    outcome_count: int
    unconfirmed_outcome_count: int
    consequences: tuple[ReceiptConsequence, ...]
    refusals: tuple[ReceiptRefusal, ...]
    issues: tuple[ReceiptLinkIssue, ...]
    chain_error: str | None = None

    @property
    def is_valid(self) -> bool:
        """Return whether both the chain and receipt links are valid."""
        return self.chain_ok and not self.issues


def _positive_int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _non_empty_string(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _sha256(value: object) -> str | None:
    text = _non_empty_string(value)
    if text is not None and len(text) == 64 and set(text) <= _HEX_DIGITS:
        return text
    return None


def _issue(
    issues: list[ReceiptLinkIssue],
    code: str,
    message: str,
    *,
    seq: int | None = None,
    related_seq: int | None = None,
) -> None:
    issues.append(ReceiptLinkIssue(code=code, message=message, seq=seq, related_seq=related_seq))


def _link_value(record: Mapping[str, Any], key: str) -> object:
    return record.get(key)


def _check_same_link_fields(
    child: Mapping[str, Any],
    parent: Mapping[str, Any],
    *,
    child_kind: str,
    child_seq: int,
    parent_seq: int,
    issues: list[ReceiptLinkIssue],
) -> None:
    for key in ("actor_id", "adapter_id", "request_fingerprint"):
        if _link_value(child, key) != _link_value(parent, key):
            _issue(
                issues,
                f"{child_kind}_{key}_mismatch",
                f"{child_kind} {child_seq} {key} does not match decision {parent_seq}",
                seq=child_seq,
                related_seq=parent_seq,
            )


def _decision_was_blocked(record: Mapping[str, Any]) -> bool:
    if record.get("decision") == "ALLOW" or record.get("dry_run") is True:
        return False
    if record.get("governance_mode") != "decision":
        return True
    matched_rule_id = record.get("matched_rule_id")
    return isinstance(matched_rule_id, str) and matched_rule_id.startswith("delegation_")


def _required_authority(record: Mapping[str, Any]) -> Mapping[str, Any] | None:
    direct = record.get("required_authority")
    if isinstance(direct, Mapping):
        return direct
    evidence = record.get("evidence")
    if isinstance(evidence, Mapping):
        nested = evidence.get("required_authority")
        if isinstance(nested, Mapping):
            return nested
    return None


def verify_receipt_records(records: Iterable[Mapping[str, Any]]) -> ReceiptLinkReport:
    """Verify semantic links in records whose transport integrity is trusted.

    This pure verifier does not hash records. Use :func:`verify_receipt_links`
    for a ledger path; that entry point verifies the complete hash chain before
    calling this function.
    """
    materialized = tuple(records)
    issues: list[ReceiptLinkIssue] = []
    records_by_seq: dict[int, Mapping[str, Any]] = {}
    decisions: dict[int, Mapping[str, Any]] = {}
    intents: dict[int, Mapping[str, Any]] = {}
    outcomes: dict[int, Mapping[str, Any]] = {}

    for record in materialized:
        seq = _positive_int(record.get("seq"))
        if seq is None:
            _issue(issues, "invalid_record_seq", "record seq must be a positive integer")
            continue
        if seq in records_by_seq:
            _issue(
                issues, "duplicate_record_seq", f"record seq {seq} appears more than once", seq=seq
            )
            continue
        records_by_seq[seq] = record
        record_type = record.get("record_type")
        if record_type == "decision":
            decisions[seq] = record
        elif record_type == "consequence_intent":
            intents[seq] = record
        elif record_type == "outcome":
            outcomes[seq] = record

    for seq, decision_record in decisions.items():
        verdict = decision_record.get("decision")
        if verdict not in _DECISIONS:
            _issue(
                issues,
                "decision_invalid_verdict",
                f"decision {seq} has invalid verdict {verdict!r}",
                seq=seq,
            )
        if (
            _positive_int(decision_record.get("seq")) != seq
            or decision_record.get("record_type") != "decision"
        ):
            _issue(
                issues,
                "decision_identity_invalid",
                f"decision {seq} has inconsistent record identity",
                seq=seq,
            )
        for key in ("request_fingerprint", "policy_hash", "ontology_hash"):
            if _sha256(decision_record.get(key)) is None:
                _issue(
                    issues,
                    f"decision_invalid_{key}",
                    f"decision {seq} {key} must be a lowercase SHA-256 hex digest",
                    seq=seq,
                )
        actor = decision_record.get("actor")
        if isinstance(actor, Mapping) and actor.get("id") != decision_record.get("actor_id"):
            _issue(
                issues,
                "decision_actor_id_mismatch",
                f"decision {seq} actor.id does not match actor_id",
                seq=seq,
            )

    intents_by_decision: dict[int, list[int]] = {}
    for seq, intent in intents.items():
        decision_seq = _positive_int(intent.get("decision_seq"))
        if decision_seq is None:
            _issue(
                issues,
                "intent_invalid_decision_seq",
                f"consequence intent {seq} has no valid decision_seq",
                seq=seq,
            )
            continue
        linked_decision = decisions.get(decision_seq)
        if linked_decision is None:
            _issue(
                issues,
                "intent_unanchored_decision",
                f"consequence intent {seq} names missing decision {decision_seq}",
                seq=seq,
                related_seq=decision_seq,
            )
            continue
        intents_by_decision.setdefault(decision_seq, []).append(seq)
        _check_same_link_fields(
            intent,
            linked_decision,
            child_kind="intent",
            child_seq=seq,
            parent_seq=decision_seq,
            issues=issues,
        )

    for decision_seq, linked_intents in intents_by_decision.items():
        if len(linked_intents) > 1:
            _issue(
                issues,
                "duplicate_consequence_intent",
                f"decision {decision_seq} has multiple consequence intents {linked_intents}",
                seq=decision_seq,
            )

    outcomes_by_intent: dict[int, list[int]] = {}
    outcomes_by_decision: dict[int, list[int]] = {}
    unconfirmed_count = 0
    for seq, outcome in outcomes.items():
        decision_seq = _positive_int(outcome.get("decision_seq"))
        intent_seq = _positive_int(outcome.get("intent_seq"))
        success = outcome.get("success")
        if "success" not in outcome or not (success is True or success is False or success is None):
            _issue(
                issues,
                "outcome_invalid_success",
                f"outcome {seq} success must be true, false, or null",
                seq=seq,
            )
        elif success is None:
            unconfirmed_count += 1

        linked_decision = decisions.get(decision_seq) if decision_seq is not None else None
        if decision_seq is None:
            _issue(
                issues,
                "outcome_invalid_decision_seq",
                f"outcome {seq} has no valid decision_seq",
                seq=seq,
            )
        elif linked_decision is None:
            _issue(
                issues,
                "outcome_unanchored_decision",
                f"outcome {seq} names missing decision {decision_seq}",
                seq=seq,
                related_seq=decision_seq,
            )
        else:
            outcomes_by_decision.setdefault(decision_seq, []).append(seq)
            _check_same_link_fields(
                outcome,
                linked_decision,
                child_kind="outcome",
                child_seq=seq,
                parent_seq=decision_seq,
                issues=issues,
            )
            if outcome.get("decision") != linked_decision.get("decision"):
                _issue(
                    issues,
                    "outcome_decision_mismatch",
                    f"outcome {seq} verdict does not match decision {decision_seq}",
                    seq=seq,
                    related_seq=decision_seq,
                )

        linked_intent = intents.get(intent_seq) if intent_seq is not None else None
        if intent_seq is None:
            _issue(
                issues,
                "outcome_invalid_intent_seq",
                f"outcome {seq} has no valid intent_seq",
                seq=seq,
            )
        elif linked_intent is None:
            _issue(
                issues,
                "outcome_unanchored_intent",
                f"outcome {seq} names missing consequence intent {intent_seq}",
                seq=seq,
                related_seq=intent_seq,
            )
        else:
            outcomes_by_intent.setdefault(intent_seq, []).append(seq)
            intent_decision_seq = _positive_int(linked_intent.get("decision_seq"))
            if decision_seq != intent_decision_seq:
                _issue(
                    issues,
                    "outcome_link_mismatch",
                    f"outcome {seq} and intent {intent_seq} name different decisions",
                    seq=seq,
                    related_seq=intent_seq,
                )
            for key in ("actor_id", "adapter_id", "request_fingerprint"):
                if outcome.get(key) != linked_intent.get(key):
                    _issue(
                        issues,
                        f"outcome_intent_{key}_mismatch",
                        f"outcome {seq} {key} does not match intent {intent_seq}",
                        seq=seq,
                        related_seq=intent_seq,
                    )

    for intent_seq in intents:
        linked_outcomes = outcomes_by_intent.get(intent_seq, [])
        if not linked_outcomes:
            _issue(
                issues,
                "intent_missing_outcome",
                f"consequence intent {intent_seq} has no outcome",
                seq=intent_seq,
            )
        elif len(linked_outcomes) > 1:
            _issue(
                issues,
                "duplicate_consequence_outcome",
                f"consequence intent {intent_seq} has multiple outcomes {linked_outcomes}",
                seq=intent_seq,
            )

    for decision_seq, decision in decisions.items():
        linked_intents = intents_by_decision.get(decision_seq, [])
        linked_outcomes = outcomes_by_decision.get(decision_seq, [])
        if decision.get("decision") == "ALLOW" and decision.get("dry_run") is not True:
            if not linked_intents:
                _issue(
                    issues,
                    "allow_missing_intent",
                    f"ALLOW decision {decision_seq} has no consequence intent",
                    seq=decision_seq,
                )
        elif _decision_was_blocked(decision) and (linked_intents or linked_outcomes):
            _issue(
                issues,
                "blocked_decision_has_consequence",
                f"blocked decision {decision_seq} has downstream consequence records",
                seq=decision_seq,
            )

    consequence_rows: list[ReceiptConsequence] = []
    for decision_seq, decision in decisions.items():
        intent_seqs = tuple(intents_by_decision.get(decision_seq, []))
        outcome_seqs = tuple(outcomes_by_decision.get(decision_seq, []))
        if (
            intent_seqs
            or outcome_seqs
            or (decision.get("decision") == "ALLOW" and decision.get("dry_run") is not True)
        ):
            consequence_rows.append(
                ReceiptConsequence(
                    decision_seq=decision_seq,
                    decision=str(decision.get("decision", "")),
                    actor_id=str(decision.get("actor_id", "")),
                    adapter_id=str(decision.get("adapter_id", "")),
                    request_fingerprint=str(decision.get("request_fingerprint", "")),
                    intent_seqs=intent_seqs,
                    outcome_seqs=outcome_seqs,
                    outcome_states=tuple(
                        (
                            "confirmed_success"
                            if outcomes[outcome_seq].get("success") is True
                            else "confirmed_failure"
                            if outcomes[outcome_seq].get("success") is False
                            else "unconfirmed"
                            if outcomes[outcome_seq].get("success") is None
                            else "invalid"
                        )
                        for outcome_seq in outcome_seqs
                    ),
                )
            )

    refusal_rows: list[ReceiptRefusal] = []
    for decision_seq, decision in decisions.items():
        verdict = decision.get("decision")
        if verdict not in {"DENY", "ESCALATE"}:
            continue
        blocked = _decision_was_blocked(decision)
        genuine = (
            blocked
            and not intents_by_decision.get(decision_seq)
            and not outcomes_by_decision.get(decision_seq)
        )
        record_hash = decision.get("record_hash")
        matched_rule_id = decision.get("matched_rule_id")
        refusal_rows.append(
            ReceiptRefusal(
                seq=decision_seq,
                record_hash=record_hash if isinstance(record_hash, str) else None,
                decision=str(verdict),
                actor_id=str(decision.get("actor_id", "")),
                adapter_id=str(decision.get("adapter_id", "")),
                request_fingerprint=str(decision.get("request_fingerprint", "")),
                governance_mode=str(decision.get("governance_mode", "")),
                matched_rule_id=matched_rule_id if isinstance(matched_rule_id, str) else None,
                blocked=blocked,
                genuine=genuine,
                required_authority=_required_authority(decision),
            )
        )
    return ReceiptLinkReport(
        chain_ok=True,
        record_count=len(materialized),
        decision_count=len(decisions),
        allow_count=sum(
            1 for decision in decisions.values() if decision.get("decision") == "ALLOW"
        ),
        refusal_count=len(refusal_rows),
        genuine_refusal_count=sum(1 for refusal in refusal_rows if refusal.genuine),
        intent_count=len(intents),
        outcome_count=len(outcomes),
        unconfirmed_outcome_count=unconfirmed_count,
        consequences=tuple(consequence_rows),
        refusals=tuple(refusal_rows),
        issues=tuple(issues),
    )


def verify_receipt_links(path: str | Path) -> ReceiptLinkReport:
    """Verify a ledger's hash chain, then its receipt-link semantics."""
    chain_ok, records, error = read_verified_records(path)
    if not chain_ok:
        issue = ReceiptLinkIssue(code="chain_invalid", message=error or "chain verification failed")
        return ReceiptLinkReport(
            chain_ok=False,
            record_count=0,
            decision_count=0,
            allow_count=0,
            refusal_count=0,
            genuine_refusal_count=0,
            intent_count=0,
            outcome_count=0,
            unconfirmed_outcome_count=0,
            consequences=(),
            refusals=(),
            issues=(issue,),
            chain_error=error,
        )
    return verify_receipt_records(records)
