# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Foreign customer-delete clearance is independently reproducible from public proof."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify.foreign_revocation import (
    ForeignRevocationRevokedError,
    project_foreign_revocation_policy,
    verify_foreign_dependency,
    verify_foreign_revocation_evidence,
)
from ambit_verify.hashing import canonical_iso, canonical_json_bytes, hash_object
from ambit_verify.resource_protocol import dispatch_message
from ambit_verify.revocation_types import (
    RevocationStatus,
    revocation_attestation_payload,
    signed_status_bytes,
)
from ambit_verify.status_evidence import status_artefact
from ambit_verify.tokens_slips import SLIP_CONTEXT_DELEGATION

_POINT_ID = "0123456789abcdef"
_BINDING = "ab" * 32


def _slip(key: Ed25519PrivateKey, claims: dict[str, object]) -> str:
    encoded = base64.urlsafe_b64encode(canonical_json_bytes(claims)).rstrip(b"=").decode("ascii")
    signature = key.sign(f"{SLIP_CONTEXT_DELEGATION}.{encoded}".encode())
    return f"{encoded}.ed25519:{base64.b64encode(signature).decode('ascii')}"


def _dispatch(key: Ed25519PrivateKey, claims: dict[str, object]) -> str:
    encoded = base64.urlsafe_b64encode(canonical_json_bytes(claims)).rstrip(b"=").decode("ascii")
    signature = key.sign(dispatch_message(claims))
    return f"{encoded}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')}"


def _status(
    key: Ed25519PrivateKey,
    *,
    jti: str,
    at: datetime,
    revoked: bool = False,
    epoch: int = 7,
    root: str = "a-status-root",
) -> dict[str, object]:
    unsigned = RevocationStatus(
        is_revoked=revoked,
        checked_at=at,
        freshness_bound_ms=30_000,
        source="a-http",
        verifiable=True,
        trust_root_id=root,
        revocation_epoch=epoch,
    )
    signature = key.sign(
        signed_status_bytes(
            revocation_attestation_payload(unsigned, jti), context="ambit.revocation.status.v1"
        )
    )
    return status_artefact(
        replace(unsigned, attestation=f"ed25519:{base64.b64encode(signature).decode('ascii')}"),
        jti,
    )


def _material() -> dict[str, Any]:
    base = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
    b_consent_key = Ed25519PrivateKey.generate()
    a_dispatch_key = Ed25519PrivateKey.generate()
    a_status_key = Ed25519PrivateKey.generate()
    credential_roots = {
        "b-consent-root": {
            "scheme": "ed25519",
            "public_key": b_consent_key.public_key().public_bytes_raw().hex(),
        }
    }
    consent = _slip(
        b_consent_key,
        {
            "jti": "b-consent-leaf",
            "sub": "B customer-delete consent",
            "scope_actions": ["delegate"],
            "scope_paths": ["/customers"],
            "scope_domains": ["http"],
            "nbf": canonical_iso(base - timedelta(hours=1)),
            "exp": canonical_iso(base + timedelta(hours=1)),
            "chain_depth": 0,
            "max_depth": 0,
            "trust_root_id": "b-consent-root",
        },
    )
    points = {
        _POINT_ID: {
            "domain_id": "a-domain",
            "ledger_id": "a-ledger",
            "resource_id": "a-customers",
            "resource_binding_hash": _BINDING,
            "profile": "customer-delete/1",
            "public_key": a_dispatch_key.public_key().public_bytes_raw().hex(),
            "revocation_status_url": "https://a.example.test/revocation",
            "revocation_trust_roots": {
                "a-status-root": a_status_key.public_key().public_bytes_raw().hex()
            },
            "max_revocation_age_ms": 20_000,
            "consent_delegation_token": consent,
            "consent_parent_delegation_tokens": [],
        }
    }
    policy = project_foreign_revocation_policy(points, credential_roots)
    a_claims = {
        "version": 1,
        "profile": "customer-delete/1",
        "domain_id": "a-domain",
        "ledger_id": "a-ledger",
        "enforcement_point_id": _POINT_ID,
        "resource_id": "a-customers",
        "resource_binding_hash": _BINDING,
        "operation_id": "delete-customer-1",
        "request_hash": "cd" * 32,
        "payload_hash": "ef" * 32,
        "decision_hash": "01" * 32,
        "intent_hash": "23" * 32,
        "action_type": "delete",
        "action_boundary": "network_egress",
        "action_domain": "http",
        "action_path": "/customers/customer-1",
        "customer_id": "customer-1",
        "authorized_at": canonical_iso(base),
        "not_after": canonical_iso(base + timedelta(minutes=5)),
        "delegation_jtis": ["a-leaf", "a-parent"],
        "revocation_epoch": 5,
        "max_revocation_age_ms": 15_000,
        "counterparty_consent_hash": policy["points"][_POINT_ID]["consent_hash"],
    }
    raw_a_dispatch = _dispatch(a_dispatch_key, a_claims)
    native_claims = {
        **{
            name: value
            for name, value in a_claims.items()
            if name
            not in {
                "domain_id",
                "ledger_id",
                "enforcement_point_id",
                "resource_id",
                "resource_binding_hash",
                "operation_id",
                "request_hash",
                "decision_hash",
                "intent_hash",
                "counterparty_consent_hash",
                "delegation_jtis",
                "revocation_epoch",
                "max_revocation_age_ms",
            }
        },
        "domain_id": "b-domain",
        "ledger_id": "b-ledger",
        "enforcement_point_id": "fedcba9876543210",
        "resource_id": "b-customers",
        "resource_binding_hash": "45" * 32,
        "operation_id": "b-delete-1",
        "request_hash": "67" * 32,
        "decision_hash": "89" * 32,
        "intent_hash": "aa" * 32,
        "authorized_at": canonical_iso(base + timedelta(seconds=1)),
        "not_after": canonical_iso(base + timedelta(minutes=4)),
        "delegation_jtis": ["b-consent-leaf"],
        "revocation_epoch": 99,
        "max_revocation_age_ms": 10_000,
        "foreign_dependency": {"dispatch": raw_a_dispatch, "policy_hash": hash_object(policy)},
    }
    evidence = {
        "foreign_dispatch_hash": hashlib.sha256(raw_a_dispatch.encode()).hexdigest(),
        "policy_hash": hash_object(policy),
        "statuses": [
            _status(a_status_key, jti="a-leaf", at=base + timedelta(seconds=2)),
            _status(a_status_key, jti="a-parent", at=base + timedelta(seconds=3)),
        ],
        "checked_at": canonical_iso(base + timedelta(seconds=4)),
    }
    return {
        "base": base,
        "policy": policy,
        "a_claims": a_claims,
        "a_dispatch_key": a_dispatch_key,
        "native": native_claims,
        "evidence": evidence,
        "status_key": a_status_key,
    }


def test_signed_foreign_dependency_and_clearance_verify() -> None:
    material = _material()
    dependency = verify_foreign_dependency(material["native"], material["policy"])

    assert dependency is not None
    assert dependency.point_id == _POINT_ID
    assert dependency.foreign_delegation_jtis == ("a-leaf", "a-parent")
    assert dependency.foreign_revocation_epoch == 5
    verify_foreign_revocation_evidence(
        material["evidence"],
        native_dispatch_claims=material["native"],
        policy=material["policy"],
        terminal_recorded_at="2026-10-03T12:00:05Z",
    )


def test_policy_age_bound_clears_when_a_and_b_omit_optional_bounds() -> None:
    material = _material()
    foreign_claims = {
        name: value
        for name, value in material["a_claims"].items()
        if name != "max_revocation_age_ms"
    }
    raw_dispatch = _dispatch(material["a_dispatch_key"], foreign_claims)
    native = {
        name: value for name, value in material["native"].items() if name != "max_revocation_age_ms"
    }
    native["foreign_dependency"] = {
        "dispatch": raw_dispatch,
        "policy_hash": hash_object(material["policy"]),
    }
    evidence = {
        **material["evidence"],
        "foreign_dispatch_hash": hashlib.sha256(raw_dispatch.encode()).hexdigest(),
    }

    dependency = verify_foreign_dependency(native, material["policy"])

    assert dependency is not None
    assert dependency.effective_max_revocation_age_ms == 20_000
    verify_foreign_revocation_evidence(
        evidence,
        native_dispatch_claims=native,
        policy=material["policy"],
        terminal_recorded_at="2026-10-03T12:00:05Z",
    )


def test_foreign_dependency_requires_the_signed_a_revocation_identity() -> None:
    material = _material()
    foreign_claims = {
        name: value
        for name, value in material["a_claims"].items()
        if name not in {"delegation_jtis", "revocation_epoch", "max_revocation_age_ms"}
    }
    native = dict(material["native"])
    native["foreign_dependency"] = {
        "dispatch": _dispatch(material["a_dispatch_key"], foreign_claims),
        "policy_hash": hash_object(material["policy"]),
    }

    with pytest.raises(ValueError, match="requires signed A revocation identity"):
        verify_foreign_dependency(native, material["policy"])


def test_mixed_a_status_epochs_are_unavailable_even_when_they_increase() -> None:
    material = _material()
    material["evidence"]["statuses"][1] = _status(
        material["status_key"],
        jti="a-parent",
        at=material["base"] + timedelta(seconds=3),
        epoch=8,
    )

    with pytest.raises(ValueError, match="epochs differ"):
        verify_foreign_revocation_evidence(
            material["evidence"],
            native_dispatch_claims=material["native"],
            policy=material["policy"],
            terminal_recorded_at="2026-10-03T12:00:05Z",
        )


def test_only_a_verified_fresh_revocation_has_the_revoked_signal() -> None:
    material = _material()
    material["evidence"]["statuses"][1] = _status(
        material["status_key"],
        jti="a-parent",
        at=material["base"] + timedelta(seconds=3),
        revoked=True,
    )

    with pytest.raises(ForeignRevocationRevokedError):
        verify_foreign_revocation_evidence(
            material["evidence"],
            native_dispatch_claims=material["native"],
            policy=material["policy"],
            terminal_recorded_at="2026-10-03T12:00:05Z",
        )


@pytest.mark.parametrize("mutation", ["stale", "wrong-root", "wrong-jti", "epoch", "malformed"])
def test_untrusted_or_incomplete_statuses_fail_closed_as_unavailable(mutation: str) -> None:
    material = _material()
    statuses = material["evidence"]["statuses"]
    if mutation == "stale":
        statuses[0] = _status(
            material["status_key"],
            jti="a-leaf",
            at=material["base"] - timedelta(seconds=11),
        )
    elif mutation == "wrong-root":
        statuses[0]["trust_root_id"] = "other-root"
    elif mutation == "wrong-jti":
        statuses[0] = _status(material["status_key"], jti="other", at=material["base"])
    elif mutation == "epoch":
        statuses[1] = _status(
            material["status_key"],
            jti="a-parent",
            at=material["base"] + timedelta(seconds=3),
            epoch=4,
        )
    else:
        material["evidence"]["statuses"] = statuses[:1]

    with pytest.raises(ValueError, match="foreign revocation"):
        verify_foreign_revocation_evidence(
            material["evidence"],
            native_dispatch_claims=material["native"],
            policy=material["policy"],
            terminal_recorded_at="2026-10-03T12:00:05Z",
        )


def test_missing_dependency_and_nonexact_foreign_vector_refuse_but_shared_parent_is_ordinary() -> (
    None
):
    material = _material()
    native = material["native"]
    missing = {name: value for name, value in native.items() if name != "foreign_dependency"}
    with pytest.raises(ValueError, match="requires a foreign dependency"):
        verify_foreign_dependency(missing, material["policy"])
    malformed = {**native, "foreign_dependency": {"dispatch": "not-a-complete-dependency"}}
    with pytest.raises(ValueError, match="foreign dependency fields"):
        verify_foreign_dependency(malformed, material["policy"])

    nonexact_foreign = {**missing, "delegation_jtis": ["ordinary-leaf", "b-consent-leaf"]}
    with pytest.raises(ValueError, match="requires a foreign dependency"):
        verify_foreign_dependency(nonexact_foreign, material["policy"])

    shared_parent_policy = {
        **material["policy"],
        "points": {
            **material["policy"]["points"],
            _POINT_ID: {
                **material["policy"]["points"][_POINT_ID],
                "consent_delegation_jtis": ["b-consent-leaf", "shared-parent"],
            },
        },
    }
    ordinary = {**missing, "delegation_jtis": ["ordinary-leaf", "shared-parent"]}
    assert verify_foreign_dependency(ordinary, shared_parent_policy) is None

    historic_ordinary = {
        name: value
        for name, value in ordinary.items()
        if name not in {"delegation_jtis", "revocation_epoch", "max_revocation_age_ms"}
    }
    assert verify_foreign_dependency(historic_ordinary, material["policy"]) is None


def test_policy_tamper_and_gate_time_boundaries_refuse() -> None:
    material = _material()
    tampered_policy = {
        **material["policy"],
        "points": {
            **material["policy"]["points"],
            _POINT_ID: {**material["policy"]["points"][_POINT_ID], "max_revocation_age_ms": 1},
        },
    }
    with pytest.raises(ValueError, match="policy hash"):
        verify_foreign_dependency(material["native"], tampered_policy)

    material["evidence"]["checked_at"] = "2026-10-03T12:04:00Z"
    with pytest.raises(ValueError, match="strict dispatch validity"):
        verify_foreign_revocation_evidence(
            material["evidence"],
            native_dispatch_claims=material["native"],
            policy=material["policy"],
            terminal_recorded_at="2026-10-03T12:04:00Z",
        )


def test_gate_time_after_terminal_refuses_even_with_valid_signed_statuses() -> None:
    material = _material()
    with pytest.raises(ValueError, match="recorded before"):
        verify_foreign_revocation_evidence(
            material["evidence"],
            native_dispatch_claims=material["native"],
            policy=material["policy"],
            terminal_recorded_at="2026-10-03T12:00:03Z",
        )


def test_terminal_at_dispatch_expiry_refuses_after_a_valid_gate() -> None:
    material = _material()

    with pytest.raises(ValueError, match="recorded outside strict dispatch validity"):
        verify_foreign_revocation_evidence(
            material["evidence"],
            native_dispatch_claims=material["native"],
            policy=material["policy"],
            terminal_recorded_at="2026-10-03T12:04:00Z",
        )
