"""Independent revocation authority and ordered mutation evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ambit_verify import replay_execution_prefix
from test_lifecycle_prefix import context, material, rechain

FIXTURE = Path(__file__).with_name("fixtures") / "revocation_authority_v1"


def revocation():
    records = json.loads((FIXTURE / "records.json").read_text())
    policy = json.loads((FIXTURE / "policy.json").read_text())
    bundle, trust = material()
    return records, context(bundle, trust) | {"revocation_policy": policy}


def test_complete_revocation_retains_and_verifies_authorizing_statuses():
    records, ctx = revocation()
    result = replay_execution_prefix(records, **ctx)
    assert result.valid and result.coverage_complete, result.errors
    assert len(result.record_coverage) == len(records)


def test_unanswered_authorized_revocation_is_valid_explicit_uncertainty():
    records, ctx = revocation()
    result = replay_execution_prefix(records[:1], **ctx)
    assert result.valid and result.coverage_complete, result.errors


@pytest.mark.parametrize(
    "fault",
    [
        "revoked_revoker",
        "stale",
        "late_comparison",
        "omitted_parent",
        "changed_target",
        "changed_outcome",
        "missing_intent",
        "wrong_roots",
    ],
)
def test_revocation_evidence_substitution_fails(fault):
    records, ctx = revocation()
    statuses = records[0]["retained"]["authority_evidence"]["statuses"]
    if fault == "revoked_revoker":
        statuses[0]["is_revoked"] = True
    if fault == "stale":
        statuses[0]["checked_at"] = "2000-01-01T00:00:00Z"
    if fault == "late_comparison":
        statuses[0]["freshness_evaluated_at"] = "2099-01-01T00:00:00Z"
    if fault == "omitted_parent":
        statuses.pop()
    if fault == "changed_target":
        records[0]["target_jti"] = "unrelated"
    if fault == "changed_outcome":
        records[1]["revocation_request_hash"] = "0" * 64
    if fault == "missing_intent":
        records.pop(0)
    if fault == "wrong_roots":
        ctx["revocation_policy"]["revocation_attestation_public_keys"] = {}
    result = replay_execution_prefix(rechain(records), **ctx)
    assert not result.valid and not result.coverage_complete


def test_legacy_revocation_is_not_promoted_to_complete_authority():
    records, ctx = revocation()
    records[0]["retained"].pop("authority_evidence")
    result = replay_execution_prefix(rechain(records), **ctx)
    assert result.valid and not result.coverage_complete
    assert all(row.status == "not_established" for row in result.record_coverage)


def test_missing_independent_revocation_policy_prevents_qualification():
    records, ctx = revocation()
    ctx.pop("revocation_policy")
    result = replay_execution_prefix(records, **ctx)
    assert result.valid and not result.coverage_complete


def test_validly_signed_stale_revoker_status_fails_freshness_not_signature():
    from datetime import timedelta

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ambit_verify.admission import _moment
    from ambit_verify.hashing import canonical_iso
    from test_foreign_revocation import _status

    records, ctx = revocation()
    key = Ed25519PrivateKey.generate()
    ctx["revocation_policy"]["revocation_attestation_public_keys"] = {
        "a-status-root": key.public_key().public_bytes_raw().hex()
    }
    statuses = records[0]["retained"]["authority_evidence"]["statuses"]
    for index, original in enumerate(statuses):
        comparison = _moment(original["freshness_evaluated_at"])
        statuses[index] = dict(
            _status(key, jti=original["jti"], at=comparison, epoch=1),
            freshness_evaluated_at=canonical_iso(comparison),
        )
    positive = replay_execution_prefix(rechain(records[:1]), **ctx)
    assert positive.valid and positive.coverage_complete, positive.errors
    first = statuses[0]
    comparison = _moment(first["freshness_evaluated_at"])
    statuses[0] = dict(
        _status(key, jti=first["jti"], at=comparison - timedelta(minutes=1), epoch=1),
        freshness_evaluated_at=canonical_iso(comparison),
    )
    refused = replay_execution_prefix(rechain(records[:1]), **ctx)
    assert not refused.valid
    assert any(
        "does not cover the retained comparison time" in error for error in refused.errors
    ), refused.errors
