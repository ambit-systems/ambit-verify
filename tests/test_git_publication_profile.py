# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Public grammar regressions for the signed Git-publication resource profile."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify import canonical_json_bytes, verify_authority_admission
from ambit_verify.resource_protocol import (
    GIT_PUBLICATION_PROFILE,
    dispatch_message,
    git_publication_plan_hash,
    outcome_message,
    verify_dispatch,
    verify_resource_outcome,
)

_HASH = "a" * 64
_OLD = "b" * 40
_NEW = "c" * 40


def _token(claims: dict[str, object], message: bytes, key: Ed25519PrivateKey) -> str:
    payload = base64.urlsafe_b64encode(canonical_json_bytes(claims)).rstrip(b"=")
    signature = base64.urlsafe_b64encode(key.sign(message)).rstrip(b"=")
    return f"{payload.decode()}.{signature.decode()}"


def _dispatch() -> dict[str, object]:
    return {
        "version": 1,
        "profile": GIT_PUBLICATION_PROFILE,
        "domain_id": "git",
        "ledger_id": "ledger",
        "enforcement_point_id": "0123456789abcdef",
        "resource_id": "console-door",
        "resource_binding_hash": _HASH,
        "operation_id": "operation-1",
        "request_hash": _HASH,
        "payload_hash": _HASH,
        "decision_hash": _HASH,
        "intent_hash": _HASH,
        "actor_id": "console-agent",
        "plan_hash": git_publication_plan_hash(
            remote_url="console-candidate",
            ref="refs/heads/agent/console/fix",
            expected_old_oid=_OLD,
            new_oid=_NEW,
            commit_range=f"{_OLD}..{_NEW}",
        ),
        "action_type": "execute",
        "action_boundary": "code_execution",
        "action_domain": "process",
        "action_path": "refs/heads/agent/console/fix",
        "authorized_at": "2026-01-01T00:00:00Z",
        "not_after": "2026-01-01T00:01:00Z",
        "remote": "console-candidate",
        "ref": "refs/heads/agent/console/fix",
        "expected_old_oid": _OLD,
        "new_oid": _NEW,
        "range": f"{_OLD}..{_NEW}",
        "force": False,
    }


def _outcome(status: str) -> dict[str, object]:
    claims = _dispatch()
    for field in (
        "action_type",
        "action_boundary",
        "action_domain",
        "action_path",
        "authorized_at",
        "not_after",
    ):
        claims.pop(field)
    claims.update(
        {
            "status": status,
            "accepted_at": "2026-01-01T00:00:01Z" if status == "committed" else None,
            "recorded_at": "2026-01-01T00:00:02Z",
        }
    )
    return claims


def test_git_dispatch_requires_a_non_forced_agent_ref_and_exact_range() -> None:
    key = Ed25519PrivateKey.generate()
    claims = _dispatch()
    token = _token(claims, dispatch_message(claims), key)

    assert verify_dispatch(token, public_key=key.public_key().public_bytes_raw()) == claims

    claims["force"] = True
    with pytest.raises(ValueError):
        dispatch_message(claims)
    claims["force"] = False
    claims["range"] = "not-the-signed-range"
    with pytest.raises(ValueError):
        dispatch_message(claims)


def test_git_terminal_unknown_is_signed_but_never_a_success_status() -> None:
    key = Ed25519PrivateKey.generate()
    claims = _outcome("unknown")
    token = _token(claims, outcome_message(claims), key)

    assert verify_resource_outcome(token, public_key=key.public_key().public_bytes_raw()) == claims


def _admission_token(claims: dict[str, object], key: Ed25519PrivateKey) -> str:
    payload = {**claims, "trust_root_id": "admission"}
    encoded = base64.urlsafe_b64encode(canonical_json_bytes(payload)).rstrip(b"=")
    signature = base64.b64encode(key.sign(b"ambit:authority-admission:v1." + encoded))
    return f"{encoded.decode()}.ed25519:{signature.decode()}"


def _git_admission(schema_version: int) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "domain_id": "git",
        "principal_id": "console-owner",
        "resource_id": "console-door",
        "ledger_id": "ledger",
        "enforcement_point_id": "0123456789abcdef",
        "version": 1,
        "previous_admission_hash": None,
        "nbf": "2026-01-01T00:00:00Z",
        "exp": "2027-01-01T00:00:00Z",
        "credential_trust_roots": {"issuer": {"scheme": "ed25519", "public_key": "1" * 64}},
        "credential_registration_public_keys": {"registrar": "2" * 64},
        "revocation_attestation_public_keys": {"revocation": "3" * 64},
        "cumulative_attestation_public_keys": {"cumulative": "4" * 64},
        "origin_grant_hashes": ["5" * 64],
        "resource_binding": {
            "adapter_id": "code",
            "downstream_url": "https://door.invalid",
            "downstream_path": "/v1/tools/call",
            "receipt_public_key": "d" * 64,
            "outcome_profile": GIT_PUBLICATION_PROFILE,
            "outcome_public_key": "e" * 64,
            "git_remote": "console-candidate",
            "git_ref": "refs/heads/agent/console/fix",
        },
        "max_revocation_age_ms": 1000,
        "max_cumulative_age_ms": 1000,
        "max_actor_proof_age_seconds": 10,
    }


def test_git_binding_requires_schema3_and_retains_its_fixed_remote_and_ref() -> None:
    signer = Ed25519PrivateKey.generate()
    roots = {
        "admission": {
            "scheme": "ed25519",
            "public_key": signer.public_key().public_bytes_raw().hex(),
        }
    }

    assert not verify_authority_admission(
        _admission_token(_git_admission(2), signer),
        admission_trust_roots=roots,
        expected_domain="git",
        expected_ledger_id="ledger",
        at=datetime(2026, 1, 1, tzinfo=UTC),
    ).valid

    verified = verify_authority_admission(
        _admission_token(_git_admission(3), signer),
        admission_trust_roots=roots,
        expected_domain="git",
        expected_ledger_id="ledger",
        at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert verified.valid and verified.admission is not None
    assert verified.admission.claims["resource_binding"]["git_remote"] == "console-candidate"
