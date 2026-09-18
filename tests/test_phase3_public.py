# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Public-only phase-3 verification boundaries; no Core runtime dependency."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify import (
    CUMULATIVE_STATUS_CONTEXT,
    RATIFICATION_RULE_VERSION,
    DelegationClaims,
    ratifier_reach_widening_axis,
    request_binding_matches,
    verify_admitted_path,
    verify_authority_admission,
    verify_cumulative_status_payload,
    verify_execution_authority,
)
from ambit_verify.actor_proof import actor_proof_request_hash
from ambit_verify.admission import _verify_revocation_status
from ambit_verify.attenuation import ATTENUATION_RULE_VERSION, _scope_widening_axis
from ambit_verify.revocation_types import (
    REVOCATION_CONTEXT,
    RevocationStatus,
    revocation_attestation_payload,
    signed_status_bytes,
)
from ambit_verify.tokens_slips import parse_delegation

_FIXTURE = Path(__file__).parent / "fixtures" / "origin"


def _origin_material() -> tuple[dict[str, bytes], dict[str, object], dict[str, object]]:
    caller_trust = json.loads((_FIXTURE / "origin-caller-trust.json").read_text(encoding="utf-8"))
    metadata = json.loads((_FIXTURE / "metadata.json").read_text(encoding="utf-8"))
    names = (
        "entry.json",
        "candidate.json",
        "ratification.slip",
        "ratifier-leaf.slip",
        "ratifier-parent-0.slip",
        "status-0.json",
        "status-1.json",
        "grant.slip",
        "trust_roots.json",
    )
    artifacts = {name: (_FIXTURE / name).read_bytes() for name in names}
    return artifacts, caller_trust, metadata


def _admission(caller_trust: dict[str, object], metadata: dict[str, object]):
    result = verify_authority_admission(
        (_FIXTURE / "admission.slip").read_text(encoding="utf-8").strip(),
        admission_trust_roots=caller_trust["admission_trust_roots"],
        expected_domain=str(metadata["domain"]),
        expected_ledger_id=str(metadata["ledger_id"]),
        at=datetime.fromisoformat(str(metadata["at"])),
    )
    assert result.valid and result.admission is not None
    return result.admission


_REACH_AT = datetime(2026, 1, 1, tzinfo=UTC)
_HISTORICAL_RATIFICATION_RULE_VERSION = f"authority_entry/1;attenuation/{ATTENUATION_RULE_VERSION}"
_ENTRY_HASH = "a" * 64
_RATIFICATION_HASH = "b" * 64


def _ratifier_reach_claims(
    bounds: list[dict[str, object]],
    *,
    authority_entry_hash: str | None = None,
    ratification_hash: str | None = None,
) -> DelegationClaims:
    return DelegationClaims(
        jti="reach",
        sub="holder",
        scope_actions=["delegate"],
        scope_paths=["/"],
        nbf=_REACH_AT,
        exp=_REACH_AT + timedelta(days=1),
        bounds=bounds,
        authority_entry_hash=authority_entry_hash,
        ratification_hash=ratification_hash,
    )


def _ordinary_bound(*, amount: str = "10", duration_ms: int = 1_000) -> dict[str, object]:
    return {
        "kind": "calls",
        "unit": "count",
        "amount_scaled": amount,
        "window_epoch": "2026-01-01T00:00:00Z",
        "window_duration_ms": duration_ms,
    }


def _aggregate_bound(*, amount: str = "10", duration_ms: int = 1_000) -> dict[str, object]:
    return {
        **_ordinary_bound(amount=amount, duration_ms=duration_ms),
        "aggregation": "entry",
    }


def test_new_ratifier_reach_requires_explicit_ordinary_aggregate_ceiling() -> None:
    parent = _ratifier_reach_claims([_ordinary_bound()])
    candidate = _ratifier_reach_claims(
        [_ordinary_bound(), _aggregate_bound()],
        authority_entry_hash=_ENTRY_HASH,
    )

    assert (
        ratifier_reach_widening_axis(candidate, parent, rule_version=RATIFICATION_RULE_VERSION)
        is None
    )
    assert (
        ratifier_reach_widening_axis(
            _ratifier_reach_claims(
                [_ordinary_bound(), _aggregate_bound(amount="11")],
                authority_entry_hash=_ENTRY_HASH,
            ),
            parent,
            rule_version=RATIFICATION_RULE_VERSION,
        )
        == "bounds"
    )
    assert (
        ratifier_reach_widening_axis(
            _ratifier_reach_claims(
                [_ordinary_bound(), _aggregate_bound(duration_ms=2_000)],
                authority_entry_hash=_ENTRY_HASH,
            ),
            parent,
            rule_version=RATIFICATION_RULE_VERSION,
        )
        == "bounds"
    )
    assert (
        ratifier_reach_widening_axis(
            _ratifier_reach_claims(
                [_ordinary_bound(), _aggregate_bound()],
                authority_entry_hash=_ENTRY_HASH,
            ),
            _ratifier_reach_claims([]),
            rule_version=RATIFICATION_RULE_VERSION,
        )
        == "aggregate_bound"
    )


def test_ratifier_reach_version_dispatch_preserves_historical_attenuation() -> None:
    fresh_aggregate_candidate = _ratifier_reach_claims(
        [_ordinary_bound(), _aggregate_bound()],
        authority_entry_hash=_ENTRY_HASH,
    )
    lineaged_parent = _ratifier_reach_claims(
        [_ordinary_bound()],
        authority_entry_hash=_ENTRY_HASH,
        ratification_hash=_RATIFICATION_HASH,
    )

    assert (
        ratifier_reach_widening_axis(
            fresh_aggregate_candidate,
            lineaged_parent,
            rule_version=RATIFICATION_RULE_VERSION,
        )
        == "lineage"
    )
    assert (
        ratifier_reach_widening_axis(
            fresh_aggregate_candidate,
            _ratifier_reach_claims([_ordinary_bound()]),
            rule_version=_HISTORICAL_RATIFICATION_RULE_VERSION,
        )
        == "aggregate_bound"
    )
    assert (
        ratifier_reach_widening_axis(
            fresh_aggregate_candidate,
            _ratifier_reach_claims([_ordinary_bound()]),
            rule_version="authority_entry/1;attenuation/5;ratifier_reach/unknown",
        )
        == "ratification_rule_version"
    )

    established_parent = _ratifier_reach_claims(
        [_aggregate_bound()],
        authority_entry_hash=_ENTRY_HASH,
        ratification_hash=_RATIFICATION_HASH,
    )
    established_child = _ratifier_reach_claims(
        [_aggregate_bound()],
        authority_entry_hash=_ENTRY_HASH,
        ratification_hash=_RATIFICATION_HASH,
    )
    assert _scope_widening_axis(established_child, established_parent) is None
    assert (
        ratifier_reach_widening_axis(
            established_child,
            established_parent,
            rule_version=RATIFICATION_RULE_VERSION,
        )
        is None
    )


def test_admitted_path_accepts_the_exact_completed_public_origin() -> None:
    artifacts, caller_trust, metadata = _origin_material()
    admission = _admission(caller_trust, metadata)
    origin = artifacts["grant.slip"].decode("utf-8").strip()

    verification = verify_admitted_path(
        origin,
        (),
        artifacts,
        admission=admission,
        at=datetime.fromisoformat(str(metadata["at"])),
    )

    assert verification.valid


def test_authority_envelope_seal_does_not_change_holder_intent_hash() -> None:
    intent = {
        "authority_envelope_version": "1",
        "actor_id": "holder",
        "actor_proof": {"signature": "holder-signature"},
        "action": {"type": "effect"},
        "seal": None,
    }
    intent_hash = actor_proof_request_hash(intent)

    assert (
        actor_proof_request_hash(
            {**intent, "seal": {"alg": "ed25519", "key_id": "ep", "value": "outer-seal"}}
        )
        == intent_hash
    )
    assert actor_proof_request_hash({**intent, "action": {"type": "other-effect"}}) != intent_hash

    native = {
        "envelope_version": "1",
        "actor": {"id": "holder"},
        "call": {"name": "effect", "arguments": {}},
        "seal": None,
    }
    assert actor_proof_request_hash({**native, "seal": {"value": "outer-seal"}}) != (
        actor_proof_request_hash(native)
    )


def test_stronger_status_check_intersects_signed_grant_freshness_cap() -> None:
    checked_at = datetime(2026, 1, 1, tzinfo=UTC)
    signer = Ed25519PrivateKey.generate()
    unsigned_status = RevocationStatus(
        is_revoked=False,
        checked_at=checked_at,
        freshness_bound_ms=1000,
        source="test",
        verifiable=False,
        attestation=None,
        trust_root_id="revocation",
        revocation_epoch=1,
    )
    attestation = "ed25519:" + base64.b64encode(
        signer.sign(
            signed_status_bytes(
                revocation_attestation_payload(unsigned_status, "leaf"),
                context=REVOCATION_CONTEXT,
            )
        )
    ).decode("ascii")
    status = RevocationStatus(
        is_revoked=False,
        checked_at=checked_at,
        freshness_bound_ms=1000,
        source="test",
        verifiable=False,
        attestation=attestation,
        trust_root_id="revocation",
        revocation_epoch=1,
    )
    evidence = {
        "jti": "leaf",
        "is_revoked": status.is_revoked,
        "checked_at": "2026-01-01T00:00:00Z",
        "freshness_bound_ms": status.freshness_bound_ms,
        "source": status.source,
        "verifiable": status.verifiable,
        "attestation": status.attestation,
        "trust_root_id": status.trust_root_id,
        "revocation_epoch": status.revocation_epoch,
    }
    roots = {"revocation": signer.public_key().public_bytes_raw()}

    assert (
        _verify_revocation_status(
            evidence,
            jti="leaf",
            roots=roots,
            at=checked_at + timedelta(milliseconds=100),
            admission_age_limit_ms=1000,
            grant_age_limit_ms=100,
            epoch_floor=1,
        )
        is None
    )
    assert (
        _verify_revocation_status(
            evidence,
            jti="leaf",
            roots=roots,
            at=checked_at + timedelta(milliseconds=101),
            admission_age_limit_ms=1000,
            grant_age_limit_ms=100,
            epoch_floor=1,
        )
        is not None
    )


def test_execution_receipt_revocation_diagnostic_cannot_extend_freshness() -> None:
    checked_at = datetime(2026, 1, 1, tzinfo=UTC)
    signer = Ed25519PrivateKey.generate()
    unsigned_status = RevocationStatus(
        is_revoked=False,
        checked_at=checked_at,
        freshness_bound_ms=1000,
        source="test",
        verifiable=False,
        attestation=None,
        trust_root_id="revocation",
        revocation_epoch=1,
    )
    evidence = {
        "jti": "leaf",
        "is_revoked": unsigned_status.is_revoked,
        "checked_at": "2026-01-01T00:00:00Z",
        "freshness_bound_ms": unsigned_status.freshness_bound_ms,
        "source": unsigned_status.source,
        "verifiable": unsigned_status.verifiable,
        "attestation": "ed25519:"
        + base64.b64encode(
            signer.sign(
                signed_status_bytes(
                    revocation_attestation_payload(unsigned_status, "leaf"),
                    context=REVOCATION_CONTEXT,
                )
            )
        ).decode("ascii"),
        "trust_root_id": unsigned_status.trust_root_id,
        "revocation_epoch": unsigned_status.revocation_epoch,
        "freshness_evaluated_at": "2026-01-01T00:00:00Z",
    }
    roots = {"revocation": signer.public_key().public_bytes_raw()}
    verification = _verify_revocation_status(
        evidence,
        jti="leaf",
        roots=roots,
        at=checked_at + timedelta(milliseconds=100),
        admission_age_limit_ms=1000,
        grant_age_limit_ms=100,
        epoch_floor=1,
    )
    assert verification is None
    stale = _verify_revocation_status(
        {**evidence, "freshness_evaluated_at": "2099-01-01T00:00:00Z"},
        jti="leaf",
        roots=roots,
        at=checked_at + timedelta(milliseconds=101),
        admission_age_limit_ms=1000,
        grant_age_limit_ms=100,
        epoch_floor=1,
    )
    assert stale is not None and "does not cover" in stale
    malformed = _verify_revocation_status(
        {**evidence, "unexpected_metadata": "refuse"},
        jti="leaf",
        roots=roots,
        at=checked_at,
        admission_age_limit_ms=1000,
        grant_age_limit_ms=100,
        epoch_floor=1,
    )
    assert malformed is not None and "malformed" in malformed


def test_cumulative_payload_signature_refuses_a_tampered_join() -> None:
    signer = Ed25519PrivateKey.generate()
    payload = {
        "admissible": True,
        "checked_at": "2026-01-01T00:00:00Z",
        "freshness_bound_ms": 1000,
        "jti": "delegation",
        "kind": "calls",
        "remaining_amount_scaled": "9",
        "source": "test",
        "trust_root_id": "cumulative",
        "unit": "count",
        "window_duration_ms": 60_000,
        "window_epoch": "2026-01-01T00:00:00Z",
    }
    attestation = "ed25519:" + base64.b64encode(
        signer.sign(signed_status_bytes(payload, context=CUMULATIVE_STATUS_CONTEXT))
    ).decode("ascii")
    public_key = signer.public_key().public_bytes_raw()

    assert verify_cumulative_status_payload(payload, attestation, public_key=public_key)
    assert not verify_cumulative_status_payload(
        {**payload, "remaining_amount_scaled": "10"}, attestation, public_key=public_key
    )


def test_request_binding_rejects_same_actor_credential_or_json_type_substitution() -> None:
    envelope = {
        "envelope_version": "1",
        "adapter_id": "http",
        "actor": {"id": "holder"},
        "call": {"name": "effect", "arguments": {"confirmed": True}},
        "delegation_token": "leaf",
        "parent_delegation_tokens": ["parent"],
        "approval_token": "approval",
    }

    assert request_binding_matches(
        envelope,
        actor_id="holder",
        delegation_token="leaf",
        parent_tokens=["parent"],
        approval_token="approval",
        tool_name="effect",
        arguments={"confirmed": True},
        actor_proof=None,
    )
    assert request_binding_matches(
        {**envelope, "call": {"name": "effect"}},
        actor_id="holder",
        delegation_token="leaf",
        parent_tokens=["parent"],
        approval_token="approval",
        tool_name="effect",
        arguments={},
        actor_proof=None,
    )
    native_without_parents = {
        key: value for key, value in envelope.items() if key != "parent_delegation_tokens"
    }
    assert request_binding_matches(
        native_without_parents,
        actor_id="holder",
        delegation_token="leaf",
        parent_tokens=[],
        approval_token="approval",
        tool_name="effect",
        arguments={"confirmed": True},
        actor_proof=None,
    )
    assert not request_binding_matches(
        {**native_without_parents, "parent_delegation_tokens": None},
        actor_id="holder",
        delegation_token="leaf",
        parent_tokens=[],
        approval_token="approval",
        tool_name="effect",
        arguments={"confirmed": True},
        actor_proof=None,
    )
    assert request_binding_matches(
        {
            **envelope,
            "actor": {"id": " holder "},
            "call": {"name": " effect ", "arguments": {"confirmed": True}},
        },
        actor_id="holder",
        delegation_token="leaf",
        parent_tokens=["parent"],
        approval_token="approval",
        tool_name="effect",
        arguments={"confirmed": True},
        actor_proof=None,
    )
    assert not request_binding_matches(
        envelope,
        actor_id="holder",
        delegation_token="other-leaf",
        parent_tokens=["parent"],
        approval_token="approval",
        tool_name="effect",
        arguments={"confirmed": True},
        actor_proof=None,
    )
    assert not request_binding_matches(
        envelope,
        actor_id="holder",
        delegation_token="leaf",
        parent_tokens=["parent"],
        approval_token="approval",
        tool_name="effect",
        arguments={"confirmed": 1},
        actor_proof=None,
    )
    carried_proof = {"scheme": "p256", "nonce": "n"}
    assert request_binding_matches(
        {**envelope, "actor": {"id": "holder", "proof": carried_proof}},
        actor_id="holder",
        delegation_token="leaf",
        parent_tokens=["parent"],
        approval_token="approval",
        tool_name="effect",
        arguments={"confirmed": True},
        actor_proof={**carried_proof, "request_hash": "derived"},
    )
    assert not request_binding_matches(
        {**envelope, "actor": {"id": "holder", "proof": carried_proof}},
        actor_id="holder",
        delegation_token="leaf",
        parent_tokens=["parent"],
        approval_token="approval",
        tool_name="effect",
        arguments={"confirmed": True},
        actor_proof={"scheme": "p256", "nonce": "different", "request_hash": "derived"},
    )


def test_joined_verifier_refuses_missing_holder_and_substituted_native_request() -> None:
    artifacts, caller_trust, metadata = _origin_material()
    admission = _admission(caller_trust, metadata)
    origin = artifacts["grant.slip"].decode("utf-8").strip()
    origin_ok, origin_claims = parse_delegation(
        origin, trust_roots=admission.claims["credential_trust_roots"]
    )
    assert origin_ok and origin_claims is not None
    configuration = {
        name: admission.claims[name]
        for name in (
            "credential_trust_roots",
            "credential_registration_public_keys",
            "revocation_attestation_public_keys",
            "cumulative_attestation_public_keys",
        )
    }
    receipt = {
        "decision": {"evaluated_at": metadata["at"], "actor_id": origin_claims.sub},
        "delegation": {"credential_evidence": {"artifact": origin}, "credential_chain": []},
        "evidence": {
            "schema_version": "5",
            "execution_profile": "live",
            "authority_admission": {
                "artifact": ((_FIXTURE / "admission.slip").read_text(encoding="utf-8").strip()),
                "admission_hash": admission.admission_hash,
                "trust_configuration_hash": admission.trust_configuration_hash,
                "domain_id": metadata["domain"],
                "ledger_id": metadata["ledger_id"],
                "enforcement_point_id": admission.claims["enforcement_point_id"],
                "minimum_version": 1,
                "expected_previous_hash": None,
                "revocation_epoch_floor": 0,
                "origin_grant_hash": hashlib.sha256(origin.encode("utf-8")).hexdigest(),
                "origin_artifacts": {
                    name: value.decode("utf-8") for name, value in artifacts.items()
                },
                "verification_configuration": configuration,
                "resource_binding": admission.claims["resource_binding"],
            },
            "request_envelope": {
                "envelope_version": "1",
                "adapter_id": "http",
                "call": {"name": "substituted-call", "arguments": {"changed": True}},
                "actor": {"id": origin_claims.sub},
                "context": {},
                "delegation_token": "substituted-delegation",
                "parent_delegation_tokens": [],
                "approval_token": None,
                "policy_hash": None,
                "mode": {"dry_run": False},
            },
        },
    }

    verification = verify_execution_authority(
        receipt,
        admission_trust_roots=caller_trust["admission_trust_roots"],
        expected_domain=str(metadata["domain"]),
        expected_ledger_id=str(metadata["ledger_id"]),
    )

    assert not verification.valid
    assert not verification.checks["holder_request"]
    assert not verification.checks["request_artifact_binding"]

    wrong_adapter_receipt = {
        **receipt,
        "evidence": {
            **receipt["evidence"],
            "request_envelope": {
                **receipt["evidence"]["request_envelope"],
                "adapter_id": "mcp",
            },
        },
    }
    wrong_adapter = verify_execution_authority(
        wrong_adapter_receipt,
        admission_trust_roots=caller_trust["admission_trust_roots"],
        expected_domain=str(metadata["domain"]),
        expected_ledger_id=str(metadata["ledger_id"]),
    )
    assert not wrong_adapter.checks["resource_binding"]
