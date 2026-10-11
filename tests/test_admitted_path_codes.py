# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Each admitted-path refusal carries one stable failure code beside its prose."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ambit_verify.admission as admission_module
from ambit_verify import (
    ADMITTED_PATH_FAILURE_CODES,
    OriginVerification,
    verify_admitted_origin,
    verify_admitted_path,
)
from ambit_verify.hashing import canonical_iso
from ambit_verify.ratification_bundle import verify_ratification_bundle
from ambit_verify.tokens_slips import SLIP_CONTEXT_DELEGATION, parse_delegation
from test_phase3_public import _mint_two_root_chain, _sign_slip, _TwoRootChain


def _issuer_child(chain: _TwoRootChain, **overrides: object) -> str:
    """Sign a child under the origin issuer, so only *overrides* differ from a valid hop."""
    claims = {
        **chain.child_claims,
        "jti": "issuer-child",
        "trust_root_id": chain.issuer_root,
        **overrides,
    }
    return _sign_slip(chain.issuer_key, claims, context=SLIP_CONTEXT_DELEGATION)


def _origin_exp(chain: _TwoRootChain) -> datetime:
    ok, origin = parse_delegation(
        chain.origin_token, trust_roots=chain.admission.claims["credential_trust_roots"]
    )
    assert ok and origin is not None
    return origin.exp


def _tamper_signature(token: str) -> str:
    payload, signature = token.split(".", 1)
    scheme, encoded = signature.split(":", 1)
    flipped = "B" if encoded[0] != "B" else "C"
    return f"{payload}.{scheme}:{flipped}{encoded[1:]}"


def _refused(
    verification: OriginVerification, code: str, errors: tuple[str, ...]
) -> OriginVerification:
    assert verification.valid is False
    assert verification.codes == (code,)
    assert verification.errors == errors
    return verification


def test_failure_codes_are_a_closed_set() -> None:
    assert (
        frozenset(
            {
                "origin_artifact_invalid",
                "origin_signer_mismatch",
                "delegation_signature_invalid",
                "delegation_window_not_covered",
                "delegation_chain_invalid",
                "git_ref_not_covered",
                "verification_input_invalid",
            }
        )
        == ADMITTED_PATH_FAILURE_CODES
    )


def test_valid_paths_carry_no_codes() -> None:
    chain = _mint_two_root_chain()

    alone = verify_admitted_path(
        chain.origin_token, (), chain.artifacts, admission=chain.admission, at=chain.at
    )
    child = verify_admitted_path(
        _issuer_child(chain),
        [chain.origin_token],
        chain.artifacts,
        admission=chain.admission,
        at=chain.at,
    )

    assert alone.valid and alone.codes == ()
    assert child.valid and child.codes == ()


def test_single_signer_refusal_still_fires_for_a_second_root_hop() -> None:
    chain = _mint_two_root_chain()

    verification = verify_admitted_path(
        chain.child_token,
        [chain.origin_token],
        chain.artifacts,
        admission=chain.admission,
        at=chain.at,
    )

    _refused(
        verification,
        "origin_signer_mismatch",
        ("delegation signer at path position 0 differs from admitted origin issuer",),
    )


def test_expired_slip_is_a_window_failure() -> None:
    chain = _mint_two_root_chain()

    verification = verify_admitted_path(
        chain.origin_token,
        (),
        chain.artifacts,
        admission=chain.admission,
        at=_origin_exp(chain) + timedelta(days=1),
    )

    _refused(
        verification,
        "delegation_window_not_covered",
        ("delegation token does not cover the comparison time",),
    )


def test_long_ttl_child_is_a_window_failure_inside_and_after_the_parent_window() -> None:
    chain = _mint_two_root_chain()
    origin_exp = _origin_exp(chain)
    long_child = _issuer_child(chain, exp=canonical_iso(origin_exp + timedelta(days=300)))

    inside = verify_admitted_path(
        long_child, [chain.origin_token], chain.artifacts, admission=chain.admission, at=chain.at
    )
    after = verify_admitted_path(
        long_child,
        [chain.origin_token],
        chain.artifacts,
        admission=chain.admission,
        at=origin_exp + timedelta(days=1),
    )

    _refused(
        inside,
        "delegation_window_not_covered",
        (
            "admitted delegation path is invalid: scope widening at depth 0: time; "
            "child scope is not a subset of parent",
        ),
    )
    assert after.valid is False
    assert after.codes == ("delegation_window_not_covered",)
    assert after.errors[0].startswith("admitted delegation path is invalid: parent token 0 (jti=")
    assert after.errors[0].endswith(") is outside its validity window")


def test_tampered_leaf_signature_is_a_signature_failure() -> None:
    chain = _mint_two_root_chain()
    tampered = _tamper_signature(chain.origin_token)

    verification = verify_admitted_path(
        tampered, (), chain.artifacts, admission=chain.admission, at=chain.at
    )

    _refused(
        verification,
        "delegation_signature_invalid",
        ("delegation token does not verify under admitted roots",),
    )


def test_tampered_parent_signature_is_a_signature_failure() -> None:
    chain = _mint_two_root_chain()

    verification = verify_admitted_path(
        _issuer_child(chain),
        [_tamper_signature(chain.origin_token)],
        chain.artifacts,
        admission=chain.admission,
        at=chain.at,
    )

    _refused(
        verification,
        "delegation_signature_invalid",
        ("admitted delegation path is invalid: parent token 0 signature invalid",),
    )


def test_locally_forged_widened_slip_is_a_signature_failure() -> None:
    chain = _mint_two_root_chain()
    forged = _sign_slip(
        Ed25519PrivateKey.generate(),
        {
            **chain.child_claims,
            "jti": "forged-child",
            "trust_root_id": chain.issuer_root,
            "scope_paths": ["/"],
        },
        context=SLIP_CONTEXT_DELEGATION,
    )

    verification = verify_admitted_path(
        forged, [chain.origin_token], chain.artifacts, admission=chain.admission, at=chain.at
    )

    _refused(
        verification,
        "delegation_signature_invalid",
        ("delegation token does not verify under admitted roots",),
    )


def test_attenuation_and_parent_link_breaks_are_chain_failures() -> None:
    chain = _mint_two_root_chain()
    widened = _issuer_child(chain, scope_actions=["delegate", "write"])
    unlinked = _issuer_child(chain, parent_jti="some-other-grant")
    origin_jti = parse_delegation(
        chain.origin_token, trust_roots=chain.admission.claims["credential_trust_roots"]
    )[1]
    assert origin_jti is not None

    widened_result = verify_admitted_path(
        widened, [chain.origin_token], chain.artifacts, admission=chain.admission, at=chain.at
    )
    unlinked_result = verify_admitted_path(
        unlinked, [chain.origin_token], chain.artifacts, admission=chain.admission, at=chain.at
    )

    _refused(
        widened_result,
        "delegation_chain_invalid",
        (
            "admitted delegation path is invalid: scope widening at depth 0: actions; "
            "child scope is not a subset of parent",
        ),
    )
    _refused(
        unlinked_result,
        "delegation_chain_invalid",
        (
            "admitted delegation path is invalid: parent_jti mismatch at depth 0: "
            f"expected some-other-grant, got {origin_jti.jti}",
        ),
    )


def test_bad_origin_artifacts_are_origin_failures() -> None:
    chain = _mint_two_root_chain()
    without_grant = {name: value for name, value in chain.artifacts.items() if name != "grant.slip"}
    tampered_candidate = {**chain.artifacts, "candidate.json": b"{}"}
    unadmitted = dataclasses.replace(
        chain.admission,
        claims={**chain.admission.claims, "origin_grant_hashes": ["0" * 64]},
    )

    missing = verify_admitted_path(
        chain.origin_token, (), without_grant, admission=chain.admission, at=chain.at
    )
    bundle = verify_admitted_path(
        chain.origin_token, (), tampered_candidate, admission=chain.admission, at=chain.at
    )
    not_admitted = verify_admitted_origin(chain.origin_token, chain.artifacts, admission=unadmitted)

    _refused(
        missing,
        "origin_artifact_invalid",
        ("completed bundle does not carry the exact originating grant",),
    )
    expected_bundle_failures = tuple(
        verify_ratification_bundle(
            tampered_candidate,
            trust_roots=chain.admission.claims["credential_trust_roots"],
            revocation_trust_roots=chain.admission.claims["revocation_attestation_public_keys"],
            registration_public_keys=chain.admission.claims["credential_registration_public_keys"],
        ).failures
    )
    assert expected_bundle_failures
    _refused(bundle, "origin_artifact_invalid", expected_bundle_failures)
    _refused(
        not_admitted,
        "origin_artifact_invalid",
        ("originating grant was not independently admitted",),
    )


def test_uncovered_git_ref_is_a_git_ref_failure() -> None:
    chain = _mint_two_root_chain()
    git_admission = dataclasses.replace(
        chain.admission,
        claims={
            **chain.admission.claims,
            "resource_binding": {
                "outcome_profile": "git-publication/1",
                "git_ref": "refs/heads/release",
            },
        },
    )

    verification = verify_admitted_path(
        chain.origin_token, (), chain.artifacts, admission=git_admission, at=chain.at
    )

    _refused(
        verification,
        "git_ref_not_covered",
        ("signed delegation does not cover the admitted Git ref",),
    )


def test_malformed_caller_inputs_are_input_failures() -> None:
    chain = _mint_two_root_chain()
    rootless = dataclasses.replace(
        chain.admission,
        claims={
            name: value
            for name, value in chain.admission.claims.items()
            if name != "credential_trust_roots"
        },
    )

    naive = verify_admitted_path(
        chain.origin_token,
        (),
        chain.artifacts,
        admission=chain.admission,
        at=chain.at.replace(tzinfo=None),
    )
    no_roots = verify_admitted_path(
        chain.origin_token, (), chain.artifacts, admission=rootless, at=chain.at
    )

    _refused(
        naive,
        "verification_input_invalid",
        ("admitted path comparison time requires a timezone",),
    )
    _refused(
        no_roots,
        "verification_input_invalid",
        ("admission carries no credential trust roots",),
    )


def test_unresolvable_signer_is_a_signature_failure_not_a_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chain = _mint_two_root_chain()
    child = _issuer_child(chain)
    resolve = admission_module._verified_slip_signer_id

    monkeypatch.setattr(
        admission_module,
        "_verified_slip_signer_id",
        lambda token, roots: None if token == child else resolve(token, roots),
    )
    verification = verify_admitted_path(
        child, [chain.origin_token], chain.artifacts, admission=chain.admission, at=chain.at
    )

    _refused(
        verification,
        "delegation_signature_invalid",
        ("delegation signer at path position 0 differs from admitted origin issuer",),
    )
