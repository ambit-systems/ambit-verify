# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for semantic decision-to-consequence receipt verification."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from ambit_verify import verify_receipt_links, verify_receipt_records
from ledger_fixtures import append

_FINGERPRINT = "a" * 64
_POLICY_HASH = "b" * 64
_ONTOLOGY_HASH = "c" * 64


def _complete_records(
    *, decision: str = "ALLOW", governance_mode: str = "enforcement"
) -> list[dict[str, Any]]:
    actor_id = "agent-1"
    adapter_id = "http"
    records: list[dict[str, Any]] = [
        {
            "seq": 1,
            "record_type": "decision",
            "decision": decision,
            "actor_id": actor_id,
            "actor": {"id": actor_id},
            "adapter_id": adapter_id,
            "request_fingerprint": _FINGERPRINT,
            "policy_hash": _POLICY_HASH,
            "ontology_hash": _ONTOLOGY_HASH,
            "governance_mode": governance_mode,
            "dry_run": False,
            "matched_rule_id": "policy_default",
            "reasons": [],
        },
        {
            "seq": 2,
            "record_type": "consequence_intent",
            "decision_seq": 1,
            "actor_id": actor_id,
            "adapter_id": adapter_id,
            "request_fingerprint": _FINGERPRINT,
        },
        {
            "seq": 3,
            "record_type": "outcome",
            "decision_seq": 1,
            "intent_seq": 2,
            "decision": decision,
            "actor_id": actor_id,
            "adapter_id": adapter_id,
            "request_fingerprint": _FINGERPRINT,
            "success": True,
        },
    ]
    return records


def _codes(records: list[dict[str, Any]]) -> set[str]:
    return {issue.code for issue in verify_receipt_records(records).issues}


def test_complete_allow_triplet_passes() -> None:
    report = verify_receipt_records(_complete_records())

    assert report.is_valid
    assert report.record_count == 3
    assert report.decision_count == 1
    assert report.allow_count == 1
    assert report.intent_count == 1
    assert report.outcome_count == 1


def test_link_identity_mismatches_are_rejected() -> None:
    records = _complete_records()
    records[1]["actor_id"] = "agent-2"
    records[2]["adapter_id"] = "mcp"
    records[2]["request_fingerprint"] = "d" * 64

    assert _codes(records) >= {
        "intent_actor_id_mismatch",
        "outcome_adapter_id_mismatch",
        "outcome_request_fingerprint_mismatch",
        "outcome_intent_actor_id_mismatch",
        "outcome_intent_adapter_id_mismatch",
        "outcome_intent_request_fingerprint_mismatch",
    }


def test_orphaned_intent_and_outcome_are_rejected() -> None:
    records = _complete_records()
    records[1]["decision_seq"] = 99
    records[2]["decision_seq"] = 98
    records[2]["intent_seq"] = 97

    assert _codes(records) >= {
        "intent_unanchored_decision",
        "outcome_unanchored_decision",
        "outcome_unanchored_intent",
        "intent_missing_outcome",
    }


@pytest.mark.parametrize(
    ("positions", "expected"),
    [
        ((2, 1, 3), "intent_not_after_decision"),
        ((1, 3, 2), "outcome_not_after_intent"),
        ((2, 3, 1), "outcome_not_after_decision"),
    ],
    ids=["intent_before_decision", "outcome_before_intent", "outcome_before_decision"],
)
def test_receipt_links_require_causal_append_order(
    positions: tuple[int, int, int], expected: str
) -> None:
    records = _complete_records()
    decision_seq, intent_seq, outcome_seq = positions
    records[0]["seq"] = decision_seq
    records[1]["seq"] = intent_seq
    records[1]["decision_seq"] = decision_seq
    records[2]["seq"] = outcome_seq
    records[2]["decision_seq"] = decision_seq
    records[2]["intent_seq"] = intent_seq

    assert expected in _codes(records)


@pytest.mark.parametrize("record_index", [0, 1, 2], ids=["decision", "intent", "outcome"])
@pytest.mark.parametrize("field", ["actor_id", "adapter_id"])
@pytest.mark.parametrize(
    "value",
    [None, "", 1, {"id": "agent-1"}, ["agent-1"]],
    ids=["missing", "empty", "integer", "mapping", "list"],
)
def test_receipt_links_require_concrete_string_identities(
    record_index: int, field: str, value: Any
) -> None:
    records = _complete_records()
    if value is None:
        records[record_index].pop(field)
    else:
        records[record_index][field] = value

    report = verify_receipt_records(records)
    assert not report.is_valid
    assert f"{records[record_index]['record_type']}_invalid_{field}" in {
        issue.code for issue in report.issues
    }


@pytest.mark.parametrize(
    "actor",
    [None, {}, {"id": ""}, {"id": 1}, [], "agent-1"],
    ids=["missing", "missing_id", "empty_id", "integer_id", "list", "string"],
)
def test_decision_requires_actor_object_with_matching_string_id(actor: Any) -> None:
    records = _complete_records()
    if actor is None:
        records[0].pop("actor")
    else:
        records[0]["actor"] = actor

    assert "decision_actor_invalid" in _codes(records)


def test_duplicate_intent_and_outcome_are_rejected() -> None:
    records = _complete_records()
    duplicate_intent = copy.deepcopy(records[1])
    duplicate_intent["seq"] = 4
    duplicate_outcome = copy.deepcopy(records[2])
    duplicate_outcome["seq"] = 5
    records.extend((duplicate_intent, duplicate_outcome))

    assert _codes(records) >= {
        "duplicate_consequence_intent",
        "duplicate_consequence_outcome",
    }


def test_enforced_refusal_cannot_have_consequence_records() -> None:
    records = _complete_records(decision="DENY")
    report = verify_receipt_records(records)

    assert "blocked_decision_has_consequence" in {issue.code for issue in report.issues}
    assert report.refusal_count == 1
    assert report.blocked_refusal_count == 1


def test_advisory_refusal_with_consequence_is_not_mislabeled_as_blocked() -> None:
    records = _complete_records(decision="DENY", governance_mode="decision")
    report = verify_receipt_records(records)

    assert report.is_valid
    assert report.refusal_count == 1
    assert report.blocked_refusal_count == 0


def test_decision_mode_uses_complete_reasons_for_hard_delegation() -> None:
    records = _complete_records(decision="DENY", governance_mode="decision")[:1]
    records[0]["matched_rule_id"] = "approval_rule"
    records[0]["reasons"] = [
        {"rule_id": "approval_rule", "result": "match"},
        {"rule_id": "delegation_production", "result": "match"},
    ]

    report = verify_receipt_records(records)

    assert report.is_valid
    assert report.refusals[0].blocked is True
    assert report.blocked_refusal_count == 1


def test_decision_mode_hard_delegation_rejects_claimed_consequences() -> None:
    records = _complete_records(decision="DENY", governance_mode="decision")
    records[0]["matched_rule_id"] = "approval_rule"
    records[0]["reasons"] = [
        {"rule_id": "approval_rule", "result": "match"},
        {"rule_id": "delegation_production", "result": "match"},
    ]

    report = verify_receipt_records(records)

    assert not report.is_valid
    assert "blocked_decision_has_consequence" in {issue.code for issue in report.issues}
    assert report.refusals[0].blocked is True


def test_decision_mode_delegation_pass_remains_advisory() -> None:
    records = _complete_records(decision="DENY", governance_mode="decision")
    records[0]["matched_rule_id"] = "delegation_production"
    records[0]["reasons"] = [{"rule_id": "delegation_production", "result": "pass"}]

    report = verify_receipt_records(records)

    assert report.is_valid
    assert report.refusals[0].blocked is False


@pytest.mark.parametrize(
    "reasons",
    [
        None,
        {},
        [{"rule_id": "delegation_production"}],
        [
            {"rule_id": "delegation_production", "result": "match"},
            {},
        ],
    ],
)
def test_malformed_or_missing_reasons_never_prove_hard_delegation(
    reasons: Any,
) -> None:
    records = _complete_records(decision="DENY", governance_mode="decision")[:1]
    records[0]["matched_rule_id"] = "delegation_production"
    if reasons is None:
        records[0].pop("reasons")
    else:
        records[0]["reasons"] = reasons

    report = verify_receipt_records(records)

    assert report.refusals[0].blocked is False


def test_enforced_refusal_reports_structural_blocking() -> None:
    report = verify_receipt_records(_complete_records(decision="ESCALATE")[:1])

    assert report.is_valid
    assert report.refusal_count == 1
    assert report.blocked_refusal_count == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("actor", None),
        ("actor", []),
        ("actor", {"id": "another-agent"}),
        ("actor_id", None),
        ("actor_id", 7),
        ("adapter_id", None),
        ("adapter_id", 7),
        ("request_fingerprint", None),
        ("request_fingerprint", 7),
        ("policy_hash", None),
        ("policy_hash", 7),
        ("ontology_hash", None),
        ("ontology_hash", 7),
    ],
)
def test_invalid_refusal_identity_keeps_blocking_claim_structural(field: str, value: Any) -> None:
    records = _complete_records(decision="DENY")[:1]
    if value is None:
        records[0].pop(field)
    else:
        records[0][field] = value

    report = verify_receipt_records(records)

    assert not report.is_valid
    assert report.refusal_count == 1
    assert report.blocked_refusal_count == 1
    assert report.refusals[0].blocked is True


@pytest.mark.parametrize("verdict", [None, "", "REJECT", 7, {}, []])
def test_malformed_verdict_never_crashes_or_proves_a_refusal(verdict: Any) -> None:
    records = _complete_records(decision="DENY")[:1]
    if verdict is None:
        records[0].pop("decision")
    else:
        records[0]["decision"] = verdict

    report = verify_receipt_records(records)

    assert not report.is_valid
    assert report.refusal_count == 0
    assert report.blocked_refusal_count == 0
    assert "decision_invalid_verdict" in {issue.code for issue in report.issues}


@pytest.mark.parametrize("mode", [None, "", "enforcment", 1, {}])
def test_unknown_governance_state_never_proves_a_refusal(mode: Any) -> None:
    records = _complete_records(decision="DENY")[:1]
    if mode is None:
        records[0].pop("governance_mode")
    else:
        records[0]["governance_mode"] = mode

    report = verify_receipt_records(records)
    assert not report.is_valid
    assert report.blocked_refusal_count == 0
    assert report.refusals[0].blocked is False
    assert "decision_invalid_governance_mode" in {issue.code for issue in report.issues}


@pytest.mark.parametrize("dry_run", [None, 0, 1, "", "false", {}])
def test_non_boolean_dry_run_never_proves_a_refusal(dry_run: Any) -> None:
    records = _complete_records(decision="DENY")[:1]
    if dry_run is None:
        records[0].pop("dry_run")
    else:
        records[0]["dry_run"] = dry_run

    report = verify_receipt_records(records)
    assert not report.is_valid
    assert report.blocked_refusal_count == 0
    assert report.refusals[0].blocked is False
    assert "decision_invalid_dry_run" in {issue.code for issue in report.issues}


def test_allow_without_intent_is_incomplete_unless_dry_run() -> None:
    records = _complete_records()[:1]
    assert "allow_missing_intent" in _codes(records)

    records[0]["dry_run"] = True
    assert verify_receipt_records(records).is_valid


@pytest.mark.parametrize("verdict", ["ALLOW", "DENY", "ESCALATE"])
def test_dry_run_decision_rejects_claimed_consequences(verdict: str) -> None:
    records = _complete_records(decision=verdict)
    records[0]["dry_run"] = True

    report = verify_receipt_records(records)

    assert not report.is_valid
    assert "dry_run_decision_has_consequence" in {issue.code for issue in report.issues}


@pytest.mark.parametrize("verdict", ["ALLOW", "DENY", "ESCALATE"])
def test_dry_run_decision_without_consequences_remains_valid(verdict: str) -> None:
    records = _complete_records(decision=verdict)[:1]
    records[0]["dry_run"] = True

    assert verify_receipt_records(records).is_valid


def test_unconfirmed_outcome_is_preserved() -> None:
    records = _complete_records()
    records[2]["success"] = None

    report = verify_receipt_records(records)
    assert report.is_valid
    assert report.unconfirmed_outcome_count == 1


def test_integer_success_is_not_accepted_as_boolean() -> None:
    records = _complete_records()
    records[2]["success"] = 1

    assert "outcome_invalid_success" in _codes(records)


def test_path_verifier_checks_chain_before_semantics(tmp_path: Path) -> None:
    path = tmp_path / "evidence.jsonl"
    for record in _complete_records():
        payload = {key: value for key, value in record.items() if key != "seq"}
        append(path, payload)

    assert verify_receipt_links(path).is_valid

    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("agent-1", "agent-x", 1)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = verify_receipt_links(path)
    assert not report.chain_ok
    assert report.issues[0].code == "chain_invalid"
    assert report.decision_count == 0


def test_bare_self_hashed_refusal_is_only_structurally_blocked(
    tmp_path: Path,
) -> None:
    path = tmp_path / "fabricated.jsonl"
    decision = _complete_records(decision="DENY")[0]
    append(path, {key: value for key, value in decision.items() if key != "seq"})

    report = verify_receipt_links(path)

    assert report.is_valid
    assert report.blocked_refusal_count == 1
    assert report.refusals[0].blocked is True
    assert not hasattr(report, "genuine_refusal_count")
    assert not hasattr(report.refusals[0], "genuine")

    original = path.read_text(encoding="utf-8")
    path.write_text(original.replace("agent-1", "agent-x", 1), encoding="utf-8")
    mutated = verify_receipt_links(path)
    assert not mutated.chain_ok
    assert mutated.blocked_refusal_count == 0
    assert mutated.refusals == ()

    path.write_text("", encoding="utf-8")
    truncated = verify_receipt_links(path)
    assert truncated.chain_ok
    assert truncated.blocked_refusal_count == 0
    assert truncated.refusals == ()
