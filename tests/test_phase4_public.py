# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Public Phase-4 wire regressions with no Core dependency."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify import canonical_json_bytes
from ambit_verify.consumption import validate_consumption_record
from ambit_verify.execution_evidence import verify_execution_bundle
from ambit_verify.resource_protocol import (
    dispatch_message,
    outcome_message,
    verify_dispatch,
)

_DIGEST = "ab" * 32
_FIXTURE = Path(__file__).with_name("fixtures") / "controlled_lifecycle_v6"
_CUMULATIVE_FIXTURE = Path(__file__).with_name("fixtures") / "controlled_cumulative_sibling_v6"


def test_complete_current_lifecycle_bundle_verifies_without_private_runtime() -> None:
    bundle = json.loads((_FIXTURE / "execution-bundle.json").read_text(encoding="utf-8"))
    trust = json.loads((_FIXTURE / "caller-trust.json").read_text(encoding="utf-8"))

    result = verify_execution_bundle(
        bundle,
        admission_trust_roots_by_adapter=trust["admission_trust_roots_by_adapter"],
        enforcement_point_registration_public_keys=trust[
            "enforcement_point_registration_public_keys"
        ],
        expected_domain=trust["expected_domain"],
        expected_ledger_id=trust["expected_ledger_id"],
        expected_head=trust["expected_head"],
        operation_id=trust["operation_id"],
    )

    assert result.valid, result.errors
    assert set(result.checks.values()) == {"valid"}


def test_complete_bundle_refuses_cross_adapter_admission_root_fallback() -> None:
    bundle = json.loads((_FIXTURE / "execution-bundle.json").read_text(encoding="utf-8"))
    trust = json.loads((_FIXTURE / "caller-trust.json").read_text(encoding="utf-8"))
    roots = trust["admission_trust_roots_by_adapter"]
    wrong_adapter_roots = {"http": {}, "mcp": roots["http"]}

    result = verify_execution_bundle(
        bundle,
        admission_trust_roots_by_adapter=wrong_adapter_roots,
        enforcement_point_registration_public_keys=trust[
            "enforcement_point_registration_public_keys"
        ],
        expected_domain=trust["expected_domain"],
        expected_ledger_id=trust["expected_ledger_id"],
        expected_head=trust["expected_head"],
        operation_id=trust["operation_id"],
    )

    assert not result.valid
    assert result.checks["prefix_accounting"] == "failed"
    assert result.checks["enforcement_point_registration"] == "not_established"


def test_complete_cumulative_child_bundle_verifies_all_retained_accounts() -> None:
    bundle = json.loads((_CUMULATIVE_FIXTURE / "execution-bundle.json").read_text(encoding="utf-8"))
    trust = json.loads((_CUMULATIVE_FIXTURE / "caller-trust.json").read_text(encoding="utf-8"))

    result = verify_execution_bundle(
        bundle,
        admission_trust_roots_by_adapter=trust["admission_trust_roots_by_adapter"],
        enforcement_point_registration_public_keys=trust[
            "enforcement_point_registration_public_keys"
        ],
        expected_domain=trust["expected_domain"],
        expected_ledger_id=trust["expected_ledger_id"],
        expected_head=trust["expected_head"],
        operation_id=trust["operation_id"],
    )

    assert result.valid, result.errors
    assert result.checks["prefix_accounting"] == "valid"


def _dispatch_claims() -> dict[str, object]:
    return {
        "version": 1,
        "profile": "record-egress/1",
        "domain_id": "domain",
        "ledger_id": "ledger",
        "enforcement_point_id": "point",
        "resource_id": "resource",
        "resource_binding_hash": _DIGEST,
        "operation_id": "operation-1",
        "request_hash": _DIGEST,
        "payload_hash": _DIGEST,
        "decision_hash": _DIGEST,
        "intent_hash": _DIGEST,
        "action_type": "send",
        "action_boundary": "network_egress",
        "action_domain": "domain",
        "action_path": ".",
        "authorized_at": "2026-01-01T00:00:00Z",
        "not_after": "2026-01-01T00:01:00Z",
    }


def _token(claims: dict[str, object], key: Ed25519PrivateKey) -> str:
    payload = canonical_json_bytes(claims)
    segment = base64.urlsafe_b64encode(payload).rstrip(b"=")
    signature = key.sign(dispatch_message(claims))
    return f"{segment.decode()}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


def test_dispatch_verification_refuses_tampered_canonical_claims() -> None:
    key = Ed25519PrivateKey.generate()
    claims = _dispatch_claims()
    token = _token(claims, key)
    assert verify_dispatch(token, public_key=key.public_key().public_bytes_raw()) == claims

    tampered = {**claims, "operation_id": "operation-2"}
    payload = canonical_json_bytes(tampered)
    payload_segment = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    assert token.split(".", 1)[0] != payload_segment
    with pytest.raises(ValueError, match="signature"):
        verify_dispatch(
            f"{payload_segment}.{token.split('.', 1)[1]}",
            public_key=key.public_key().public_bytes_raw(),
        )


def test_terminal_tombstone_cannot_bind_records() -> None:
    claims = {
        name: value
        for name, value in _dispatch_claims().items()
        if name
        not in {
            "action_type",
            "action_boundary",
            "action_domain",
            "action_path",
            "authorized_at",
            "not_after",
        }
    }
    claims.update(
        {
            "status": "not_executed",
            "accepted_at": None,
            "recorded_at": "2026-01-01T00:00:01Z",
            "record_count": 0,
            "records_hash": _DIGEST,
        }
    )
    with pytest.raises(ValueError, match="zero-record tombstone"):
        outcome_message(claims)


def test_consumption_refuses_account_period_outside_authorization() -> None:
    record = {
        "record_type": "decision",
        "evaluated_at": "2026-01-01T00:00:02Z",
        "consumption": {
            "profile": "canonical-operation/1",
            "operation": {
                "operation_id": "operation-1",
                "domain_id": "domain",
                "ledger_id": "ledger",
                "enforcement_point_id": "point",
                "actor_key_fingerprint": "actor",
                "request_hash": _DIGEST,
                "payload_hash": _DIGEST,
                "resource_binding_hash": _DIGEST,
            },
            "state": "authorized",
            "consumed_identifiers": [],
            "accounts": [
                {
                    "jti": "grant",
                    "scope": None,
                    "scope_id": None,
                    "kind": "records",
                    "unit": "count",
                    "ceiling_amount_scaled": "10",
                    "window_epoch": "2026-01-01T00:00:00Z",
                    "window_duration_ms": 1_000,
                    "amount_scaled": "1",
                    "reservation_id": "reservation",
                }
            ],
        },
    }
    with pytest.raises(ValueError, match="outside the supplied half-open"):
        validate_consumption_record(record)
