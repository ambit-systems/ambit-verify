# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for semantic decision-to-consequence receipt verification."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

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
    assert report.genuine_refusal_count == 0


def test_advisory_refusal_with_consequence_is_not_mislabeled_as_blocked() -> None:
    records = _complete_records(decision="DENY", governance_mode="decision")
    report = verify_receipt_records(records)

    assert report.is_valid
    assert report.refusal_count == 1
    assert report.genuine_refusal_count == 0


def test_enforced_refusal_without_consequence_is_genuine() -> None:
    report = verify_receipt_records(_complete_records(decision="ESCALATE")[:1])

    assert report.is_valid
    assert report.refusal_count == 1
    assert report.genuine_refusal_count == 1


def test_allow_without_intent_is_incomplete_unless_dry_run() -> None:
    records = _complete_records()[:1]
    assert "allow_missing_intent" in _codes(records)

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
