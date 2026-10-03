# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Public-only regressions for admitted authority and retained evidence joins."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify import (
    AuthorityAdmission,
    canonical_json_bytes,
    hash_object,
    verify_admitted_origin,
    verify_authority_admission,
    verify_foreign_dispatch,
    verify_receipt_credentials,
)
from ambit_verify.foreign_revocation import project_foreign_revocation_policy
from ambit_verify.resource_protocol import dispatch_message

ADMISSION_CONTEXT = b"ambit:authority-admission:v1."
DELEGATION_CONTEXT = b"ambit.slip.delegation.v1."
NOW = datetime(2026, 1, 1, tzinfo=UTC)
ENFORCEMENT_POINT = "0123456789abcdef"


def _slip(
    claims: dict[str, Any], key: Ed25519PrivateKey, *, trust_root_id: str, context: bytes
) -> str:
    payload = dict(claims)
    payload["trust_root_id"] = trust_root_id
    encoded = base64.urlsafe_b64encode(canonical_json_bytes(payload)).rstrip(b"=")
    signature = base64.b64encode(key.sign(context + encoded))
    return f"{encoded.decode()}.ed25519:{signature.decode()}"


def _admission_claims(*, origin_hash: str, version: int = 1) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "domain_id": "customer-domain",
        "principal_id": "principal",
        "resource_id": "resource",
        "ledger_id": "ledger",
        "enforcement_point_id": ENFORCEMENT_POINT,
        "version": version,
        "previous_admission_hash": None,
        "nbf": "2025-01-01T00:00:00Z",
        "exp": "2027-01-01T00:00:00Z",
        "credential_trust_roots": {"issuer": {"scheme": "ed25519", "public_key": "11" * 32}},
        "credential_registration_public_keys": {"registrar": "22" * 32},
        "revocation_attestation_public_keys": {"revocations": "33" * 32},
        "cumulative_attestation_public_keys": {"cumulative": "44" * 32},
        "origin_grant_hashes": [origin_hash],
        "resource_binding": {
            "adapter_id": "adapter",
            "downstream_url": "https://receiver.invalid",
            "downstream_path": "/effects",
            "receipt_public_key": "55" * 32,
        },
        "max_revocation_age_ms": 1000,
        "max_cumulative_age_ms": 1000,
        "max_actor_proof_age_seconds": 10,
        "trust_root_id": "admission",
    }


def _schema5_customer_delete_admission() -> tuple[dict[str, Any], Ed25519PrivateKey, str]:
    consent_signer = Ed25519PrivateKey.generate()
    foreign_dispatch_signer = Ed25519PrivateKey.generate()
    credential_roots = {
        "b-consent": {
            "scheme": "ed25519",
            "public_key": consent_signer.public_key().public_bytes_raw().hex(),
        }
    }
    consent = _slip(
        {
            "jti": "b-consent-leaf",
            "sub": "B customer-delete consent",
            "scope_actions": ["delegate"],
            "scope_paths": ["/customers"],
            "scope_domains": ["http"],
            "nbf": "2025-01-01T00:00:00Z",
            "exp": "2027-01-01T00:00:00Z",
            "chain_depth": 0,
            "max_depth": 0,
        },
        consent_signer,
        trust_root_id="b-consent",
        context=DELEGATION_CONTEXT,
    )
    point_id = "fedcba9876543210"
    points = {
        point_id: {
            "domain_id": "a-domain",
            "ledger_id": "a-ledger",
            "resource_id": "a-customer-door",
            "resource_binding_hash": "66" * 32,
            "public_key": foreign_dispatch_signer.public_key().public_bytes_raw().hex(),
            "revocation_trust_roots": {"a-revocations": "77" * 32},
            "revocation_status_url": "https://a.invalid/revocations",
            "profile": "customer-delete/1",
            "max_revocation_age_ms": 1_000,
            "consent_delegation_token": consent,
            "consent_parent_delegation_tokens": [],
        }
    }
    claims = _admission_claims(origin_hash="aa" * 32)
    claims["schema_version"] = 5
    claims["credential_trust_roots"] = credential_roots
    claims["trusted_counterparty_points"] = points
    claims["resource_binding"] = {
        "adapter_id": "http",
        "downstream_url": "https://b.invalid",
        "downstream_path": "/customers",
        "receipt_public_key": "55" * 32,
        "outcome_profile": "customer-delete/1",
        "outcome_public_key": "88" * 32,
        "foreign_revocation_policy_hash": hash_object(
            project_foreign_revocation_policy(points, credential_roots)
        ),
    }
    return claims, foreign_dispatch_signer, point_id


def _origin_token(
    key: Ed25519PrivateKey,
    *,
    audience: list[str] | None,
    chain_depth: int = 0,
    parent_jti: str | None = None,
) -> str:
    claims: dict[str, Any] = {
        "jti": "origin-jti",
        "sub": "subject",
        "iss": "principal",
        "scope_actions": ["read"],
        "scope_paths": ["/effects"],
        "scope_domains": ["customer-domain"],
        "scope_tools": [],
        "nbf": "2025-01-01T00:00:00Z",
        "exp": "2027-01-01T00:00:00Z",
        "parent_jti": parent_jti,
        "chain_depth": chain_depth,
        "max_depth": 1,
    }
    if audience is not None:
        claims["aud"] = audience
    return _slip(claims, key, trust_root_id="issuer", context=DELEGATION_CONTEXT)


def _admission_fixture() -> tuple[AuthorityAdmission, str, dict[str, bytes], Ed25519PrivateKey]:
    issuer = Ed25519PrivateKey.generate()
    issuer_public = issuer.public_key().public_bytes_raw().hex()
    admission_signer = Ed25519PrivateKey.generate()
    admission_public = admission_signer.public_key().public_bytes_raw().hex()
    origin = _origin_token(issuer, audience=[ENFORCEMENT_POINT])
    claims = _admission_claims(origin_hash=hashlib.sha256(origin.encode()).hexdigest())
    claims["credential_trust_roots"]["issuer"]["public_key"] = issuer_public
    token = _slip(claims, admission_signer, trust_root_id="admission", context=ADMISSION_CONTEXT)
    result = verify_authority_admission(
        token,
        admission_trust_roots={"admission": {"scheme": "ed25519", "public_key": admission_public}},
        expected_domain="customer-domain",
        expected_ledger_id="ledger",
        at=NOW,
    )
    assert result.valid and result.admission is not None
    return result.admission, origin, {"grant.slip": origin.encode()}, issuer


def test_admission_uses_independent_roots_and_checks_version_predecessor() -> None:
    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes_raw().hex()
    claims = _admission_claims(origin_hash="aa" * 32, version=2)
    claims["previous_admission_hash"] = "bb" * 32
    token = _slip(claims, signer, trust_root_id="admission", context=ADMISSION_CONTEXT)
    roots = {"admission": {"scheme": "ed25519", "public_key": public}}

    accepted = verify_authority_admission(
        token,
        admission_trust_roots=roots,
        expected_domain="customer-domain",
        expected_ledger_id="ledger",
        at=NOW,
        minimum_version=2,
        expected_previous_hash="bb" * 32,
    )
    assert accepted.valid
    assert not verify_authority_admission(
        token,
        admission_trust_roots={"other": roots["admission"]},
        expected_domain="customer-domain",
        expected_ledger_id="ledger",
        at=NOW,
    ).valid
    assert not verify_authority_admission(
        token,
        admission_trust_roots=roots,
        expected_domain="customer-domain",
        expected_ledger_id="ledger",
        at=NOW,
        minimum_version=3,
    ).valid
    assert not verify_authority_admission(
        token,
        admission_trust_roots=roots,
        expected_domain="customer-domain",
        expected_ledger_id="ledger",
        at=NOW,
        expected_previous_hash="cc" * 32,
    ).valid


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("origin_grant_hashes", []),
        ("version", 0),
        ("credential_trust_roots", {}),
        ("max_actor_proof_age_seconds", -1),
        ("exp", "not-a-time"),
        ("exp", "2027-01-01T00:00:00"),
        ("nbf", "2028-01-01T00:00:00Z"),
    ],
)
def test_public_verifier_refuses_signed_malformed_admission_claims(field: str, value: Any) -> None:
    signer = Ed25519PrivateKey.generate()
    claims = _admission_claims(origin_hash="aa" * 32)
    claims[field] = value
    roots = {
        "admission": {
            "scheme": "ed25519",
            "public_key": signer.public_key().public_bytes_raw().hex(),
        }
    }
    token = _slip(claims, signer, trust_root_id="admission", context=ADMISSION_CONTEXT)

    result = verify_authority_admission(
        token,
        admission_trust_roots=roots,
        expected_domain="customer-domain",
        expected_ledger_id="ledger",
        at=NOW,
    )
    assert not result.valid


def test_origin_requires_exact_enforcement_point_audience() -> None:
    admission, origin, artifacts, issuer = _admission_fixture()
    wrong_audience = _origin_token(issuer, audience=["fedcba9876543210"])
    wrong_hash_admission = AuthorityAdmission(
        claims={
            **admission.claims,
            "origin_grant_hashes": [hashlib.sha256(wrong_audience.encode()).hexdigest()],
        },
        admission_hash=admission.admission_hash,
        trust_configuration_hash=admission.trust_configuration_hash,
        nbf=admission.nbf,
        exp=admission.exp,
    )
    result = verify_admitted_origin(
        wrong_audience, {"grant.slip": wrong_audience.encode()}, admission=wrong_hash_admission
    )
    assert not result.valid
    assert any("audience" in error for error in result.errors)
    assert not verify_admitted_origin(origin, {}, admission=admission).valid
    assert not verify_admitted_origin(origin, artifacts, admission=admission).valid


def test_historical_optional_absence_is_distinct_from_malformed_evidence() -> None:
    base = {
        "evidence": {"schema_version": "3"},
        "decision": {"evaluated_at": "2026-01-01T00:00:00Z"},
    }
    absent = verify_receipt_credentials(
        base, {}, registration_public_keys=None, escalation_record=None
    )
    assert absent.valid
    malformed = verify_receipt_credentials(
        {**base, "delegation": {"credential_evidence": {}}},
        {},
        registration_public_keys=None,
        escalation_record=None,
    )
    assert not malformed.valid
    assert any("artifact missing" in error for error in malformed.errors)


def test_schema4_admits_only_normalized_signed_counterparty_points() -> None:
    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes_raw().hex()
    origin_hash = "a" * 64
    claims = _admission_claims(origin_hash=origin_hash)
    claims["schema_version"] = 4
    claims["resource_binding"] = {
        **claims["resource_binding"],
        "outcome_profile": None,
        "outcome_public_key": None,
    }
    claims["trusted_counterparty_points"] = {}
    token = _slip(claims, signer, trust_root_id="admission", context=ADMISSION_CONTEXT)
    result = verify_authority_admission(
        token,
        admission_trust_roots={"admission": {"scheme": "ed25519", "public_key": public}},
        expected_domain="customer-domain",
        expected_ledger_id="ledger",
        at=NOW,
    )

    assert result.valid and result.admission is not None
    malformed = {
        **claims,
        "trusted_counterparty_points": {
            ENFORCEMENT_POINT: {
                "domain_id": "a-domain",
                "ledger_id": "a-ledger",
                "resource_id": "a-resource",
                "resource_binding_hash": "not-a-digest",
                "public_key": "66" * 32,
                "revocation_trust_roots": {"a-revocations": "77" * 32},
                "revocation_status_url": "https://a.invalid",
                "profile": "customer-delete/1",
                "max_revocation_age_ms": 1000,
                "consent_delegation_token": "consent",
                "consent_parent_delegation_tokens": [],
            }
        },
    }
    rejected = verify_authority_admission(
        _slip(malformed, signer, trust_root_id="admission", context=ADMISSION_CONTEXT),
        admission_trust_roots={"admission": {"scheme": "ed25519", "public_key": public}},
        expected_domain="customer-domain",
        expected_ledger_id="ledger",
        at=NOW,
    )

    assert not rejected.valid

    invalid_outcome = {
        **claims,
        "resource_binding": {
            **claims["resource_binding"],
            "outcome_profile": "customer-delete/1",
            "outcome_public_key": claims["resource_binding"]["receipt_public_key"],
        },
    }
    assert not verify_authority_admission(
        _slip(invalid_outcome, signer, trust_root_id="admission", context=ADMISSION_CONTEXT),
        admission_trust_roots={"admission": {"scheme": "ed25519", "public_key": public}},
        expected_domain="customer-domain",
        expected_ledger_id="ledger",
        at=NOW,
    ).valid


def test_schema5_customer_delete_binds_the_projected_foreign_policy() -> None:
    claims, _foreign_dispatch_signer, _point_id = _schema5_customer_delete_admission()
    admission_signer = Ed25519PrivateKey.generate()
    roots = {
        "admission": {
            "scheme": "ed25519",
            "public_key": admission_signer.public_key().public_bytes_raw().hex(),
        }
    }

    def verify(candidate: dict[str, Any]) -> bool:
        return verify_authority_admission(
            _slip(
                candidate, admission_signer, trust_root_id="admission", context=ADMISSION_CONTEXT
            ),
            admission_trust_roots=roots,
            expected_domain="customer-domain",
            expected_ledger_id="ledger",
            at=NOW,
        ).valid

    assert verify(claims)
    missing_roots = dict(claims)
    del missing_roots["credential_trust_roots"]
    assert not verify(missing_roots)
    missing = {
        **claims,
        "resource_binding": {
            name: value
            for name, value in claims["resource_binding"].items()
            if name != "foreign_revocation_policy_hash"
        },
    }
    assert not verify(missing)
    assert not verify(
        {
            **claims,
            "resource_binding": {
                **claims["resource_binding"],
                "foreign_revocation_policy_hash": "00" * 32,
            },
        }
    )


def test_schema5_foreign_dispatch_requires_an_exact_signed_consent_hash() -> None:
    claims, foreign_dispatch_signer, point_id = _schema5_customer_delete_admission()
    admission_signer = Ed25519PrivateKey.generate()
    result = verify_authority_admission(
        _slip(claims, admission_signer, trust_root_id="admission", context=ADMISSION_CONTEXT),
        admission_trust_roots={
            "admission": {
                "scheme": "ed25519",
                "public_key": admission_signer.public_key().public_bytes_raw().hex(),
            }
        },
        expected_domain="customer-domain",
        expected_ledger_id="ledger",
        at=NOW,
    )
    assert result.valid and result.admission is not None
    points = claims["trusted_counterparty_points"]
    point = points[point_id]
    expected_consent = project_foreign_revocation_policy(points, claims["credential_trust_roots"])[
        "points"
    ][point_id]["consent_hash"]
    dispatch = {
        "version": 1,
        "profile": "customer-delete/1",
        "domain_id": point["domain_id"],
        "ledger_id": point["ledger_id"],
        "enforcement_point_id": point_id,
        "resource_id": point["resource_id"],
        "resource_binding_hash": point["resource_binding_hash"],
        "operation_id": "a-delete-1",
        "request_hash": "11" * 32,
        "payload_hash": "22" * 32,
        "decision_hash": "33" * 32,
        "intent_hash": "44" * 32,
        "customer_id": "customer-1",
        "action_type": "delete",
        "action_boundary": "network_egress",
        "action_domain": "http",
        "action_path": "https://a.invalid/customers/customer-1",
        "authorized_at": "2025-12-31T23:59:00Z",
        "not_after": "2026-01-01T00:01:00Z",
    }

    def verification(consent_hash: str | None):
        candidate = dict(dispatch)
        if consent_hash is not None:
            candidate["counterparty_consent_hash"] = consent_hash
        encoded = base64.urlsafe_b64encode(canonical_json_bytes(candidate)).rstrip(b"=")
        signature = base64.urlsafe_b64encode(
            foreign_dispatch_signer.sign(dispatch_message(candidate))
        ).rstrip(b"=")
        token = f"{encoded.decode()}.{signature.decode()}"
        return verify_foreign_dispatch(
            {
                "evidence": {
                    "hashes": {"foreign_dispatch_hash": hashlib.sha256(token.encode()).hexdigest()},
                    "foreign_dispatch": {
                        "artifact": token,
                        "revocation_statuses": [],
                        "trusted_counterparty_points": points,
                    },
                }
            },
            admission=result.admission,
            at=NOW,
        )

    matching = verification(expected_consent)
    assert not matching.valid
    assert matching.errors == ("foreign dispatch does not bind B's canonical request",)
    for consent_hash in (None, "00" * 32):
        invalid = verification(consent_hash)
        assert not invalid.valid
        assert invalid.errors == ("foreign dispatch counterparty consent hash differs",)


def test_foreign_evidence_never_uses_a_historical_admission_snapshot() -> None:
    historical_claims = _admission_claims(origin_hash="a" * 64)
    historical = AuthorityAdmission(
        claims=historical_claims,
        admission_hash="b" * 64,
        trust_configuration_hash="c" * 64,
        nbf=datetime(2025, 1, 1, tzinfo=UTC),
        exp=datetime(2027, 1, 1, tzinfo=UTC),
    )
    receipt = {
        "evidence": {
            "hashes": {"foreign_dispatch_hash": "d" * 64},
            "foreign_dispatch": {
                "artifact": "plausible-foreign-dispatch",
                "revocation_statuses": [],
                "trusted_counterparty_points": {
                    ENFORCEMENT_POINT: {
                        "domain_id": "a-domain",
                        "ledger_id": "a-ledger",
                        "resource_id": "a-resource",
                        "resource_binding_hash": "88" * 32,
                        "public_key": "66" * 32,
                        "revocation_trust_roots": {"a-revocations": "77" * 32},
                        "revocation_status_url": "https://a.invalid",
                        "profile": "customer-delete/1",
                        "max_revocation_age_ms": 1000,
                        "consent_delegation_token": "consent",
                        "consent_parent_delegation_tokens": [],
                    }
                },
            },
        }
    }

    result = verify_foreign_dispatch(receipt, admission=historical, at=NOW)

    assert not result.valid
