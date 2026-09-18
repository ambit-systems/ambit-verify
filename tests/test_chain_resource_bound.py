# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Public regression for bounded retained delegation ancestry."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify import (
    MAX_VERIFICATION_CHAIN_DEPTH,
    canonical_json_bytes,
    validate_delegation_chain,
)
from ambit_verify.tokens_slips import parse_delegation


def _signed_depth_token(
    signer: Ed25519PrivateKey,
    depth: int,
    *,
    jti: str,
    parent_jti: str | None,
    actions: list[str],
) -> str:
    claims = {
        "chain_depth": depth,
        "exp": "2027-01-01T00:00:00Z",
        "iss": "principal",
        "jti": jti,
        "max_depth": MAX_VERIFICATION_CHAIN_DEPTH,
        "nbf": "2025-01-01T00:00:00Z",
        "parent_jti": parent_jti,
        "scope_actions": actions,
        "scope_domains": ["domain"],
        "scope_paths": ["/"],
        "scope_tools": [],
        "sub": "subject",
        "trust_root_id": "issuer",
    }
    encoded = base64.urlsafe_b64encode(canonical_json_bytes(claims)).rstrip(b"=")
    signed = signer.sign(b"ambit.slip.delegation.v1." + encoded)
    return f"{encoded.decode()}.ed25519:{base64.b64encode(signed).decode()}"


def test_chain_depth_64_is_accepted_and_65_refuses_before_parent_walk() -> None:
    signer = Ed25519PrivateKey.generate()
    roots = {
        "issuer": {
            "scheme": "ed25519",
            "public_key": signer.public_key().public_bytes_raw().hex(),
        }
    }
    parent_tokens = [
        _signed_depth_token(
            signer,
            depth,
            jti=f"parent-{depth}",
            parent_jti=f"parent-{depth - 1}" if depth else None,
            actions=["read", "delegate"],
        )
        for depth in range(MAX_VERIFICATION_CHAIN_DEPTH - 1, -1, -1)
    ]
    leaf_token = _signed_depth_token(
        signer,
        MAX_VERIFICATION_CHAIN_DEPTH,
        jti="leaf",
        parent_jti=f"parent-{MAX_VERIFICATION_CHAIN_DEPTH - 1}",
        actions=["read"],
    )
    parsed, leaf = parse_delegation(leaf_token, trust_roots=roots)
    assert parsed and leaf is not None

    accepted = validate_delegation_chain(leaf, parent_tokens, trust_roots=roots)
    assert accepted.valid
    assert not accepted.depth_exceeded

    over_limit_token = _signed_depth_token(
        signer,
        MAX_VERIFICATION_CHAIN_DEPTH + 1,
        jti="over-limit",
        parent_jti="parent-64",
        actions=["read"],
    )
    parsed, over_limit_leaf = parse_delegation(over_limit_token, trust_roots=roots)
    assert parsed and over_limit_leaf is not None
    refused = validate_delegation_chain(
        over_limit_leaf,
        ["not-a-valid-slip"] * (MAX_VERIFICATION_CHAIN_DEPTH + 1),
        trust_roots=roots,
    )
    assert not refused.valid
    assert "resource limit" in refused.reason


def test_supplied_ancestry_over_profile_is_refused_before_signature_walk() -> None:
    signer = Ed25519PrivateKey.generate()
    roots = {
        "issuer": {
            "scheme": "ed25519",
            "public_key": signer.public_key().public_bytes_raw().hex(),
        }
    }
    root_token = _signed_depth_token(
        signer,
        0,
        jti="root",
        parent_jti=None,
        actions=["read"],
    )
    parsed, root = parse_delegation(root_token, trust_roots=roots)
    assert parsed and root is not None
    refused = validate_delegation_chain(
        root,
        ["not-a-valid-slip"] * (MAX_VERIFICATION_CHAIN_DEPTH + 1),
        trust_roots=roots,
    )
    assert not refused.valid
    assert "resource limit" in refused.reason
