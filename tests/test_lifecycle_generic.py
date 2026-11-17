"""Generic transport uncertainty remains explicit and cannot become settlement."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ambit_verify import replay_execution_prefix
from test_lifecycle_prefix import rechain


def material():
    fixture = Path(__file__).with_name("fixtures") / "generic_unresolved_v1" / "prefix.json"
    return json.loads(fixture.read_text())


def test_existing_generic_unknown_state_is_discoverable_without_inventing_an_effect():
    data = material()
    result = replay_execution_prefix(data["records"], **data["context"])
    assert result.valid and result.coverage_complete, result.errors
    assert result.accounts == ()
    assert len(result.unresolved_operations) == 1
    assert result.unresolved_operations[0].state == "fenced"
    assert result.unresolved_operations[0].dispatch_token_hash is None
    assert not result.all_operations_terminal
    assert any(
        "external result remains unknown" in (row.reason or "") for row in result.record_coverage
    )


@pytest.mark.parametrize("status", ["released", "committed"])
def test_generic_unknown_cannot_acquire_a_terminal_state(status):
    data = material()
    records = data["records"]
    decision = next(r for r in records if r.get("record_type") == "decision")
    fence = next(r for r in records if r.get("event") == "dispatch_fenced")
    records.append(
        {
            "record_type": "consumption",
            "profile": "canonical-operation/1",
            "event": "settlement",
            "operation": fence["operation"],
            "decision_hash": decision["record_hash"],
            "intent_hash": fence["intent_hash"],
            "status": status,
            "basis": "resource_receipt" if status == "committed" else "durable_no_dispatch",
            "resource_outcome": "unverified-receipt" if status == "committed" else None,
            "evaluated_at": fence["evaluated_at"],
        }
    )
    result = replay_execution_prefix(rechain(records), **data["context"])
    assert not result.valid
    assert any(
        "unsigned generic fence cannot establish a terminal" in error for error in result.errors
    ), result.errors


def test_generic_fence_exact_payload_claim_cannot_change():
    data = material()
    fence = next(r for r in data["records"] if r.get("event") == "dispatch_fenced")
    fence["dispatch_claims"]["payload_hash"] = "0" * 64
    result = replay_execution_prefix(rechain(data["records"]), **data["context"])
    assert not result.valid
    assert any("dispatch claims payload hash differs" in error for error in result.errors), (
        result.errors
    )
