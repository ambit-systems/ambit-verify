# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Public-only regressions for admitted authority and retained evidence joins."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify import (
    AuthorityAdmission,
    canonical_json_bytes,
    verify_admitted_origin,
    verify_authority_admission,
    verify_receipt_credentials,
)

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
