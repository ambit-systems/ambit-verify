# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Independent replay of cross-party revocation fence evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .admission import _moment
from .hashing import sha256_hex
from .lifecycle_models import RecordCoverage
from .resource_protocol import (
    dispatch_revocation_identity,
    verify_dispatch,
    verify_resource_outcome,
)
from .revocation_fence import fence_request_hash, unverified_fence_claims, verify_fence_token
from .status_evidence import _status_public_key


def replay_fence_records(
    records: Sequence[Mapping[str, Any]],
    *,
    policy: Mapping[str, Any] | None,
    enforcement_point_public_key: str,
    expected_domain: str,
    expected_ledger_id: str,
    enforcement_point_id: str,
) -> dict[int, RecordCoverage]:
    """Verify each exact fence grant and terminal against independently installed keys."""
    coverage: dict[int, RecordCoverage] = {}
    dispatches: dict[str, Mapping[str, Any]] = {}
    fences: dict[str, tuple[Mapping[str, Any], dict[str, Any], str]] = {}
    settled: set[str] = set()
    for record in records:
        if record.get("event") == "dispatch_fenced" and isinstance(
            record.get("dispatch_token"), str
        ):
            dispatches[record["dispatch_token"]] = record
        if record.get("record_type") != "revocation_fence":
            if (
                record.get("record_type") == "revocation"
                and record.get("phase") == "outcome"
                and record.get("result") == "revoked"
            ):
                target = record["retained"]["status"]["jti"]
                for active_hash, (prepared_record, _request, _door) in fences.items():
                    if (
                        active_hash not in settled
                        and target in prepared_record["delegation_jtis"]
                        and _moment(record["recorded_at"]) < _moment(prepared_record["expires_at"])
                    ):
                        raise ValueError(
                            "revocation mutation overtakes an unresolved protected fence"
                        )
            continue
        seq, phase = record["seq"], record.get("phase")
        if policy is None or not isinstance(policy.get("revocation_fence_doors"), Mapping):
            coverage[seq] = RecordCoverage(
                seq,
                "revocation_fence",
                str(phase),
                "not_established",
                "independent revocation fence door keys are required",
            )
            continue
        request_hash = record.get("request_hash")
        if not isinstance(request_hash, str) or request_hash in settled:
            raise ValueError("revocation fence identity is invalid or already terminal")
        if phase == "prepared":
            if request_hash in fences:
                raise ValueError("canonical prefix repeats a revocation fence prepare")
            token = record["request_token"]
            candidate = unverified_fence_claims(token, grant=False)
            door = policy["revocation_fence_doors"].get(candidate["b_resource_binding_hash"])
            if not isinstance(door, str) or record.get("door_public_key") != door:
                raise ValueError("revocation fence door is not independently trusted")
            request = verify_fence_token(token, public_key=door, grant=False)
            dispatch_token = request["a_dispatch"]
            dispatch = verify_dispatch(dispatch_token, public_key=enforcement_point_public_key)
            original = dispatches.get(dispatch_token)
            if original is None or original.get("dispatch_claims") != dispatch:
                raise ValueError("revocation fence lacks its earlier exact A dispatch")
            expected = {
                "profile": "customer-delete/1",
                "domain_id": expected_domain,
                "ledger_id": expected_ledger_id,
                "enforcement_point_id": enforcement_point_id,
                "customer_id": request["customer_id"],
                "payload_hash": request["payload_hash"],
            }
            if any(dispatch.get(name) != value for name, value in expected.items()):
                raise ValueError("revocation fence changes its exact A action or domain")
            identity = dispatch_revocation_identity(dispatch)
            if identity is None:
                raise ValueError("revocation fence dispatch omits its grant identity")
            candidate_grant = unverified_fence_claims(record["grant_token"], grant=True)
            key = _status_public_key(
                policy["revocation_attestation_public_keys"], candidate_grant["trust_root_id"]
            )
            if key is None:
                raise ValueError("revocation fence grant signer is not independently trusted")
            grant = verify_fence_token(record["grant_token"], public_key=key, grant=True)
            if request_hash != fence_request_hash(token) or grant["request_hash"] != request_hash:
                raise ValueError("revocation fence request and grant differ")
            dispatch_hash = sha256_hex(dispatch_token.encode())
            if (
                grant["a_dispatch_hash"] != dispatch_hash
                or record.get("a_dispatch_hash") != dispatch_hash
                or grant["b_dispatch_hash"] != request["b_dispatch_hash"]
            ):
                raise ValueError("revocation fence changes its dispatch joins")
            if (
                grant["delegation_jtis"] != list(identity[0])
                or grant["revocation_epoch"] < identity[1]
            ):
                raise ValueError("revocation fence changes its delegation identity or epoch")
            for name in ("delegation_jtis", "revocation_epoch", "prepared_at"):
                if record.get(name) != grant[name]:
                    raise ValueError("revocation fence changes its signed grant")
            prepared = _moment(grant["prepared_at"])
            if (
                not _moment(dispatch["authorized_at"]) <= prepared < _moment(dispatch["not_after"])
                or _moment(record["recorded_at"]) < prepared
                or _moment(record["expires_at"]) < _moment(dispatch["not_after"])
            ):
                raise ValueError("revocation fence time or expiry is invalid")
            fences[request_hash] = record, request, door
        elif phase == "settled":
            retained_fence = fences.get(request_hash)
            if retained_fence is None:
                raise ValueError("revocation fence terminal lacks its exact prepare")
            prepared_record, request, door = retained_fence
            token = record["terminal_token"]
            terminal = verify_resource_outcome(token, public_key=door)
            expected = {
                "profile": "customer-delete/1",
                "domain_id": request["b_domain_id"],
                "ledger_id": request["b_ledger_id"],
                "resource_id": request["b_resource_id"],
                "resource_binding_hash": request["b_resource_binding_hash"],
                "operation_id": request["b_operation_id"],
                "customer_id": request["customer_id"],
                "payload_hash": request["payload_hash"],
            }
            if any(terminal.get(name) != value for name, value in expected.items()) or record[
                "terminal_hash"
            ] != sha256_hex(token.encode()):
                raise ValueError("revocation fence terminal changes the exact B action")
            if _moment(record["recorded_at"]) < _moment(prepared_record["recorded_at"]):
                raise ValueError("revocation fence settlement precedes prepare")
            settled.add(request_hash)
        else:
            raise ValueError("revocation fence phase is unsupported")
        coverage[seq] = RecordCoverage(seq, "revocation_fence", str(phase), "valid")
    return coverage
