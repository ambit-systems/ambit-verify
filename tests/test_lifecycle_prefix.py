"""Complete prefix checks, including pending work and unsupported observations."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from ambit_verify import replay_execution_prefix, verify_execution_prefix
from ambit_verify.hashing import hash_object
from ambit_verify.verify import GENESIS_HASH

FIXTURES = Path(__file__).with_name("fixtures")


def material():
    folder = FIXTURES / "controlled_lifecycle_v6"
    bundle = json.loads((folder / "execution-bundle.json").read_text())
    trust = json.loads((folder / "caller-trust.json").read_text())
    trust.pop("operation_id")
    return bundle, trust


def context(bundle, trust):
    from ambit_verify.credential_registration import verify_enforcement_point_registration

    registration = verify_enforcement_point_registration(
        bundle["enforcement_point_registration"],
        registration_public_keys=trust["enforcement_point_registration_public_keys"],
    )
    return {
        name: trust[name]
        for name in ("admission_trust_roots_by_adapter", "expected_domain", "expected_ledger_id")
    } | {
        "enforcement_point_id": registration.enforcement_point_id,
        "enforcement_point_public_key": registration.public_key,
    }


def rechain(records):
    previous = GENESIS_HASH
    for seq, record in enumerate(records, 1):
        record.update(seq=seq, prev_hash=previous)
        record.pop("record_hash", None)
        record["record_hash"] = previous = hash_object(record)
    return records


def test_complete_retained_lifecycle_covers_each_record_and_reconstructs_accounting():
    bundle, trust = material()
    result = verify_execution_prefix(bundle, **trust)
    assert result.valid and result.coverage_complete, result.errors
    assert len(result.record_coverage) == len(bundle["records"])
    assert result.operations[0].state == "committed"
    assert result.all_operations_terminal
    assert result.accounts == ()  # This fixture carries no numeric reservation.
    assert all(account.pending_amount_scaled == "0" for account in result.accounts)
    assert all(
        account.charged_amount_scaled == account.committed_amount_scaled
        for account in result.accounts
    )


@pytest.mark.parametrize(
    ("length", "state"), [(1, "authorized"), (2, "authorized"), (3, "fenced"), (4, "fenced")]
)
def test_pending_prefix_is_valid_and_keeps_capacity(length, state):
    bundle, trust = material()
    result = replay_execution_prefix(bundle["records"][:length], **context(bundle, trust))
    assert result.valid and result.coverage_complete, result.errors
    assert result.unresolved_operations[0].state == state
    assert not result.all_operations_terminal
    assert result.accounts == ()
    assert all(account.committed_amount_scaled == "0" for account in result.accounts)


def test_genesis_is_healthy_empty_work_but_has_no_external_completeness_claim():
    bundle, trust = material()
    result = replay_execution_prefix([], **context(bundle, trust))
    assert result.valid and result.coverage_complete
    assert result.unresolved_operations == ()
    assert result.external_history_completeness == "not_established"


def test_unknown_record_is_retained_and_blocks_coverage():
    bundle, trust = material()
    records = copy.deepcopy(bundle["records"])
    records.append({"record_type": "new_unimplemented_effect"})
    result = replay_execution_prefix(rechain(records), **context(bundle, trust))
    assert result.valid and not result.coverage_complete
    assert len(result.record_coverage) == len(records)
    assert result.record_coverage[-1].status == "not_established"


@pytest.mark.parametrize(
    ("index", "field", "value"),
    [
        (1, "actor_id", "other"),
        (1, "decision_seq", 9),
        (3, "intent_seq", 9),
        (3, "success", "unknown"),
        (3, "actor_id", "other"),
    ],
)
def test_rehashed_link_forgery_is_refused(index, field, value):
    bundle, trust = material()
    records = copy.deepcopy(bundle["records"])
    records[index][field] = value
    result = replay_execution_prefix(rechain(records), **context(bundle, trust))
    assert not result.valid
    assert not result.coverage_complete


def test_malformed_sequence_returns_refusal_instead_of_raising():
    bundle, trust = material()
    records = copy.deepcopy(bundle["records"])
    records[0]["seq"] = "not an integer"
    result = replay_execution_prefix(records, **context(bundle, trust))
    assert not result.valid


def test_exact_head_pin_and_schema_version_are_required():
    bundle, trust = material()
    bundle["schema_version"] = True
    assert not verify_execution_prefix(bundle, **trust).valid


def issuance():
    folder = FIXTURES / "admitted_issuance_v1"
    return json.loads((folder / "records.json").read_text()), json.loads(
        (folder / "context.json").read_text()
    )


def test_admitted_issuance_replays_without_core_or_live_stores():
    records, ctx = issuance()
    result = replay_execution_prefix(records, **ctx)
    assert result.valid and result.coverage_complete, result.errors
    assert len(result.issuances) == 1
    assert result.issuances[0].state == "committed"
    assert result.issuances[0].allocation
    assert result.consumed_identifiers


@pytest.mark.parametrize(
    "fault", ["parent_status", "child", "allocation", "authentication", "token", "origin"]
)
def test_issuance_exact_evidence_substitution_fails(fault):
    records, ctx = issuance()
    reserved = next(r for r in records if r.get("event") == "reserved")
    evidence = reserved["verification_evidence"]
    if fault == "parent_status":
        evidence["parent_statuses"][0]["is_revoked"] = True
    if fault == "child":
        evidence["child_claims"]["sub"] = "other"
    if fault == "allocation":
        reserved["allocation"][0]["amount_scaled"] = "0"
    if fault == "authentication":
        evidence["authentication_hash"] = "0" * 64
    if fault == "token":
        next(r for r in records if r.get("event") == "committed")["verification_evidence"][
            "signed_token"
        ] += "x"
    if fault == "origin":
        evidence["origin_artifacts"] = {}
    result = replay_execution_prefix(rechain(records), **ctx)
    assert not result.valid and not result.coverage_complete
    expected = {
        "parent_status": "states revoked",
        "child": "changes authenticated subject",
        "allocation": "allocation differs",
        "authentication": "earlier holder authentication",
        "token": "commitment changes",
        "origin": "independently admitted origin",
    }
    assert any(expected[fault] in error for error in result.errors), result.errors


def test_historical_issuance_stays_explicitly_unsupported():
    records, ctx = issuance()
    for record in records:
        record.pop("verification_evidence", None)
    result = replay_execution_prefix(rechain(records), **ctx)
    assert result.valid and not result.coverage_complete
    assert any(row.status == "not_established" for row in result.record_coverage)


def test_retained_bounded_prefix_reconstructs_capacity_without_claiming_legacy_issuance_proof():
    folder = FIXTURES / "controlled_cumulative_sibling_v6"
    bundle = json.loads((folder / "execution-bundle.json").read_text())
    trust = json.loads((folder / "caller-trust.json").read_text())
    pending = replay_execution_prefix(bundle["records"][:12], **context(bundle, trust))
    terminal = replay_execution_prefix(bundle["records"], **context(bundle, trust))
    assert pending.valid and terminal.valid, (pending.errors, terminal.errors)
    assert not pending.coverage_complete and not terminal.coverage_complete
    assert any(int(account.pending_amount_scaled) > 0 for account in pending.accounts)
    assert any(int(account.committed_amount_scaled) > 0 for account in terminal.accounts)
    assert all(account.pending_amount_scaled == "0" for account in terminal.accounts)
