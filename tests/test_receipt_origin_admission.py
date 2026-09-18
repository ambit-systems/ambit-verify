# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""A verified credential chain must not read as origin admission."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ambit_verify import verify_receipt_credentials

_FIXTURE = Path(__file__).parent / "fixtures" / "controlled_lifecycle_v6"


def _v6_receipt() -> dict[str, Any]:
    bundle = json.loads((_FIXTURE / "execution-bundle.json").read_text(encoding="utf-8"))
    return bundle["records"][0]


def _v6_admission_roots() -> dict[str, Any]:
    trust = json.loads((_FIXTURE / "caller-trust.json").read_text(encoding="utf-8"))
    return trust["admission_trust_roots_by_adapter"]["http"]


def _check(receipt: dict[str, Any], *, admission_trust_roots: dict[str, Any] | None = None):
    configuration = receipt["evidence"]["authority_admission"]["verification_configuration"]
    return verify_receipt_credentials(
        receipt,
        configuration["credential_trust_roots"],
        registration_public_keys=configuration["credential_registration_public_keys"],
        escalation_record=None,
        audience="sandbox",
        admission_trust_roots=admission_trust_roots,
    )


def test_v6_receipt_without_roots_does_not_establish_origin() -> None:
    result = _check(_v6_receipt())
    assert result.origin_admission == "not_established"
    assert result.valid


def test_v6_receipt_with_correct_roots_establishes_origin() -> None:
    result = _check(_v6_receipt(), admission_trust_roots=_v6_admission_roots())
    assert result.origin_admission == "valid"
    assert result.valid


def test_v6_receipt_with_wrong_roots_fails_origin_admission() -> None:
    roots = _v6_admission_roots()
    wrong_roots = {root_id: {**root, "public_key": "00" * 32} for root_id, root in roots.items()}
    result = _check(_v6_receipt(), admission_trust_roots=wrong_roots)
    assert result.origin_admission == "failed"
    assert not result.valid


def test_schema_3_receipt_does_not_establish_origin() -> None:
    receipt = {
        "evidence": {"schema_version": "3"},
        "decision": {"evaluated_at": "2026-01-01T00:00:00Z"},
    }
    result = verify_receipt_credentials(
        receipt, {}, registration_public_keys=None, escalation_record=None
    )
    assert result.origin_admission == "not_established"
    assert result.valid
