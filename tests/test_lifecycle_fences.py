"""Exact cross-party fence verification with independent key inputs."""

from __future__ import annotations

import base64
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify.hashing import canonical_iso, canonical_json_bytes, sha256_hex
from ambit_verify.lifecycle_fences import replay_fence_records
from ambit_verify.resource_protocol import outcome_message
from ambit_verify.revocation_fence import FENCE_PROFILE, fence_request_hash
from test_foreign_revocation import _fence_token, _material


def material():
    m = _material()
    a = m["a_claims"]
    b = m["native"]
    door = Ed25519PrivateKey.generate()
    token = b["foreign_dependency"]["dispatch"]
    request = {
        "version": 1,
        "profile": FENCE_PROFILE,
        "a_dispatch": token,
        "b_dispatch_hash": "a" * 64,
        "b_operation_id": b["operation_id"],
        "b_domain_id": b["domain_id"],
        "b_ledger_id": b["ledger_id"],
        "b_resource_id": b["resource_id"],
        "b_resource_binding_hash": b["resource_binding_hash"],
        "customer_id": b["customer_id"],
        "payload_hash": b["payload_hash"],
    }
    request_token = _fence_token(door, request, grant=False)
    prepared = canonical_iso(m["base"] + timedelta(seconds=2))
    grant = {
        "version": 1,
        "profile": FENCE_PROFILE,
        "request_hash": fence_request_hash(request_token),
        "a_dispatch_hash": sha256_hex(token.encode()),
        "b_dispatch_hash": request["b_dispatch_hash"],
        "delegation_jtis": a["delegation_jtis"],
        "revocation_epoch": a["revocation_epoch"],
        "prepared_at": prepared,
        "trust_root_id": "a-status-root",
    }
    records = [
        {"seq": 1, "event": "dispatch_fenced", "dispatch_token": token, "dispatch_claims": a},
        {
            "seq": 2,
            "record_type": "revocation_fence",
            "phase": "prepared",
            "request_hash": grant["request_hash"],
            "request_token": request_token,
            "grant_token": _fence_token(m["status_key"], grant, grant=True),
            "delegation_jtis": grant["delegation_jtis"],
            "revocation_epoch": grant["revocation_epoch"],
            "prepared_at": prepared,
            "recorded_at": prepared,
            "expires_at": a["not_after"],
            "door_public_key": door.public_key().public_bytes_raw().hex(),
            "a_dispatch_hash": grant["a_dispatch_hash"],
        },
    ]
    terminal = {
        "version": 1,
        "profile": "customer-delete/1",
        "domain_id": b["domain_id"],
        "ledger_id": b["ledger_id"],
        "enforcement_point_id": b["enforcement_point_id"],
        "resource_id": b["resource_id"],
        "resource_binding_hash": b["resource_binding_hash"],
        "operation_id": b["operation_id"],
        "request_hash": b["request_hash"],
        "payload_hash": b["payload_hash"],
        "decision_hash": b["decision_hash"],
        "intent_hash": b["intent_hash"],
        "customer_id": b["customer_id"],
        "status": "not_executed",
        "accepted_at": None,
        "recorded_at": canonical_iso(m["base"] + timedelta(seconds=3)),
    }
    terminal.update(
        deleted_count=0,
        before_hash=None,
        before_state="unknown",
        after_state="unknown",
        reason="cancelled",
    )
    payload = base64.urlsafe_b64encode(canonical_json_bytes(terminal)).rstrip(b"=").decode()
    signature = base64.urlsafe_b64encode(door.sign(outcome_message(terminal))).rstrip(b"=").decode()
    terminal_token = payload + "." + signature
    records.append(
        {
            "seq": 3,
            "record_type": "revocation_fence",
            "phase": "settled",
            "request_hash": grant["request_hash"],
            "terminal_token": terminal_token,
            "terminal_hash": sha256_hex(terminal_token.encode()),
            "recorded_at": terminal["recorded_at"],
        }
    )
    context = {
        "policy": {
            "revocation_fence_doors": {
                b["resource_binding_hash"]: door.public_key().public_bytes_raw().hex()
            },
            "revocation_attestation_public_keys": {
                "a-status-root": m["status_key"].public_key().public_bytes_raw().hex()
            },
        },
        "enforcement_point_public_key": m["a_dispatch_key"].public_key().public_bytes_raw().hex(),
        "expected_domain": a["domain_id"],
        "expected_ledger_id": a["ledger_id"],
        "enforcement_point_id": a["enforcement_point_id"],
    }
    return records, context


def test_exact_prepare_and_terminal_use_independent_keys():
    records, context = material()
    result = replay_fence_records(records, **context)
    assert set(result) == {2, 3}
    assert all(row.status == "valid" for row in result.values())


@pytest.mark.parametrize(
    "fault", ["door", "expiry", "grant", "terminal", "missing_dispatch", "repeated_prepare"]
)
def test_fence_substitution_or_omission_fails(fault):
    records, context = material()
    if fault == "door":
        records[1]["door_public_key"] = "00" * 32
    if fault == "expiry":
        records[1]["expires_at"] = "2000-01-01T00:00:00Z"
    if fault == "grant":
        records[1]["delegation_jtis"] = ["another-grant"]
    if fault == "terminal":
        records[2]["terminal_hash"] = "00" * 32
    if fault == "missing_dispatch":
        records.pop(0)
    if fault == "repeated_prepare":
        records.insert(2, dict(records[1]))
    with pytest.raises(ValueError):
        replay_fence_records(records, **context)
