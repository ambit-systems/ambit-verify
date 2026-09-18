# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Repeated origin-ratification verification must reuse its result, never a stale one."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ambit_verify import AuthorityAdmission, verify_admitted_origin, verify_authority_admission

_FIXTURE = Path(__file__).parent / "fixtures" / "controlled_lifecycle_v6"


def _admission() -> AuthorityAdmission:
    bundle = json.loads((_FIXTURE / "execution-bundle.json").read_text(encoding="utf-8"))
    trust = json.loads((_FIXTURE / "caller-trust.json").read_text(encoding="utf-8"))
    receipt = bundle["records"][0]
    admission_evidence = receipt["evidence"]["authority_admission"]
    at = datetime.fromisoformat(receipt["evaluated_at"].replace("Z", "+00:00")).astimezone(UTC)
    result = verify_authority_admission(
        admission_evidence["artifact"],
        admission_trust_roots=trust["admission_trust_roots_by_adapter"]["http"],
        expected_domain=admission_evidence["domain_id"],
        expected_ledger_id=admission_evidence["ledger_id"],
        at=at,
        minimum_version=admission_evidence["minimum_version"],
        expected_previous_hash=admission_evidence["expected_previous_hash"],
    )
    assert result.valid, result.errors
    assert result.admission is not None
    return result.admission


def _origin_inputs() -> tuple[str, dict[str, bytes]]:
    bundle = json.loads((_FIXTURE / "execution-bundle.json").read_text(encoding="utf-8"))
    receipt = bundle["records"][0]
    admission_evidence = receipt["evidence"]["authority_admission"]
    artifacts = {
        name: value.encode("utf-8")
        for name, value in admission_evidence["origin_artifacts"].items()
    }
    origin_token = artifacts["grant.slip"].decode("utf-8")
    return origin_token, artifacts


def test_repeated_call_with_identical_inputs_returns_the_same_result_object() -> None:
    admission = _admission()
    origin_token, artifacts = _origin_inputs()
    first = verify_admitted_origin(origin_token, artifacts, admission=admission)
    second = verify_admitted_origin(origin_token, artifacts, admission=admission)
    assert first.valid
    assert first is second


def test_changed_artifact_byte_yields_a_different_failed_result() -> None:
    admission = _admission()
    origin_token, artifacts = _origin_inputs()
    baseline = verify_admitted_origin(origin_token, artifacts, admission=admission)
    assert baseline.valid

    tampered = dict(artifacts)
    tampered["candidate.json"] = tampered["candidate.json"] + b" "
    result = verify_admitted_origin(origin_token, tampered, admission=admission)
    assert not result.valid
    assert result is not baseline
