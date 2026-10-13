# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Paired A/B bundle verification joins the two sides on the A dispatch."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

import ambit_verify
from ambit_verify import (
    ExecutionBundleTrust,
    ExecutionBundleVerification,
    PairedBundleVerification,
    verify_paired_execution_bundles,
)
from ambit_verify.hashing import sha256_hex

_A_DISPATCH = "a-dispatch-token"
_FIELDS = (
    "schema_version",
    "profile",
    "records",
    "head_attestation",
    "enforcement_point_registration",
)


def _trust(name: str) -> ExecutionBundleTrust:
    return ExecutionBundleTrust(
        admission_trust_roots_by_adapter={},
        enforcement_point_registration_public_keys={},
        expected_domain=f"{name}-domain",
        expected_ledger_id=f"{name}-ledger",
        expected_head={},
        operation_id=f"{name}-operation",
    )


def _bundle(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "profile": "canonical_operation",
        "records": records,
        "head_attestation": {},
        "enforcement_point_registration": {},
    }


def _a_bundle(token: object = _A_DISPATCH) -> dict[str, Any]:
    return _bundle([{"event": "dispatch_fenced", "dispatch_token": token}])


def _b_bundle(dispatch: object = _A_DISPATCH) -> dict[str, Any]:
    claims = {"foreign_dependency": {"dispatch": dispatch}}
    return _bundle([{"event": "dispatch_fenced", "dispatch_claims": claims}])


@pytest.fixture
def results(monkeypatch: pytest.MonkeyPatch) -> dict[str, ExecutionBundleVerification]:
    """Stub the single-bundle verifier; the key is the pinned domain."""
    by_domain: dict[str, ExecutionBundleVerification] = {
        "a-domain": ExecutionBundleVerification(True, {}),
        "b-domain": ExecutionBundleVerification(
            True, {}, foreign_dispatch_hash="ab" * 32, foreign_evidence_form="fenced_v2"
        ),
    }

    def fake(bundle: Mapping[str, Any], **inputs: Any) -> ExecutionBundleVerification:
        assert set(bundle) == set(_FIELDS)
        return by_domain[inputs["expected_domain"]]

    monkeypatch.setattr("ambit_verify.paired_bundles.verify_execution_bundle", fake)
    return by_domain


def test_paired_bundles_are_exported_from_the_package_surface() -> None:
    for name in (
        "ExecutionBundleTrust",
        "PairedBundleVerification",
        "verify_paired_execution_bundles",
    ):
        assert name in ambit_verify.__all__
        assert hasattr(ambit_verify, name)


def test_valid_pair_names_the_verified_a_dispatch_and_evidence_form(
    results: dict[str, ExecutionBundleVerification],
) -> None:
    result = verify_paired_execution_bundles(
        _a_bundle(), _b_bundle(), a_trust=_trust("a"), b_trust=_trust("b")
    )

    assert isinstance(result, PairedBundleVerification)
    assert result.valid
    assert result.paired_dispatch_equal
    assert result.a_dispatch == _A_DISPATCH
    assert result.a_dispatch_hash == sha256_hex(_A_DISPATCH.encode("utf-8"))
    assert result.evidence_form == "fenced_v2"
    assert (result.a_errors, result.b_errors) == ((), ())


@pytest.mark.parametrize("b_dispatch", ["other-dispatch", None])
def test_unequal_or_missing_b_dependency_dispatch_is_not_paired(
    results: dict[str, ExecutionBundleVerification], b_dispatch: object
) -> None:
    result = verify_paired_execution_bundles(
        _a_bundle(), _b_bundle(b_dispatch), a_trust=_trust("a"), b_trust=_trust("b")
    )

    assert not result.valid
    assert not result.paired_dispatch_equal
    assert result.a_dispatch is None
    assert result.a_dispatch_hash is None
    assert result.evidence_form is None


def test_a_bundle_without_a_dispatch_token_is_not_paired(
    results: dict[str, ExecutionBundleVerification],
) -> None:
    result = verify_paired_execution_bundles(
        _a_bundle(None), _b_bundle(None), a_trust=_trust("a"), b_trust=_trust("b")
    )

    assert not result.valid
    assert not result.paired_dispatch_equal


def test_each_side_reports_its_own_errors(
    results: dict[str, ExecutionBundleVerification],
) -> None:
    results["a-domain"] = ExecutionBundleVerification(False, {}, ("a failed",))
    results["b-domain"] = ExecutionBundleVerification(False, {}, ("b failed",))

    result = verify_paired_execution_bundles(
        _a_bundle(), _b_bundle(), a_trust=_trust("a"), b_trust=_trust("b")
    )

    assert not result.valid
    assert result.paired_dispatch_equal
    assert result.a_errors == ("a failed",)
    assert result.b_errors == ("b failed",)
    assert result.a_dispatch is None


def test_bundle_with_missing_fields_is_refused_without_calling_the_verifier(
    results: dict[str, ExecutionBundleVerification],
) -> None:
    incomplete = {name: value for name, value in _a_bundle().items() if name != "records"}

    result = verify_paired_execution_bundles(
        incomplete, _b_bundle(), a_trust=_trust("a"), b_trust=_trust("b")
    )

    assert not result.valid
    assert result.a_errors == ("execution bundle fields are missing",)
