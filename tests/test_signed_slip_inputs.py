# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Consumer regressions for hostile but correctly signed delegation payloads."""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify import canonical_json_bytes
from ambit_verify.tokens_slips import parse_delegation


def _claims() -> dict[str, object]:
    return {
        "chain_depth": 0,
        "exp": "2027-01-01T00:00:00Z",
        "iss": "issuer",
        "jti": "root",
        "max_depth": 1,
        "nbf": "2025-01-01T00:00:00Z",
        "parent_jti": None,
        "scope_actions": ["read"],
        "scope_domains": ["domain"],
        "scope_paths": ["/"],
        "scope_tools": [],
        "sub": "subject",
        "trust_root_id": "issuer",
    }


def _signed_payload(payload: bytes, signer: Ed25519PrivateKey) -> str:
    segment = base64.urlsafe_b64encode(payload).rstrip(b"=")
    signature = signer.sign(b"ambit.slip.delegation.v1." + segment)
    return f"{segment.decode()}.ed25519:{base64.b64encode(signature).decode()}"


def _roots(signer: Ed25519PrivateKey) -> dict[str, dict[str, str]]:
    return {
        "issuer": {
            "scheme": "ed25519",
            "public_key": signer.public_key().public_bytes_raw().hex(),
        }
    }


def test_signed_duplicate_noncanonical_and_malformed_chain_claims_fail_closed() -> None:
    signer = Ed25519PrivateKey.generate()
    roots = _roots(signer)
    canonical = canonical_json_bytes(_claims())
    duplicate = canonical.replace(b'"jti":"root"', b'"jti":"first","jti":"root"')
    noncanonical = json.dumps(_claims(), sort_keys=True).encode("utf-8")
    malformed_claims = {**_claims(), "chain_depth": True}

    for payload in (duplicate, noncanonical, canonical_json_bytes(malformed_claims)):
        valid, claims = parse_delegation(_signed_payload(payload, signer), trust_roots=roots)
        assert not valid
        assert claims is None
