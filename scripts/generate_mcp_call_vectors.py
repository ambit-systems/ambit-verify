# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Generate the golden vectors for the ``mcp-call/1`` resource profile.

Each vector is one JSON file in ``tests/vectors/mcp-call-v1/``. Fixed Ed25519
seeds make every byte and every token reproducible. Invalid cases carry a
signature over claims that the verifier must still refuse.

Run from the repository root::

    uv run python scripts/generate_mcp_call_vectors.py
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify import canonical_json_bytes, hash_object
from ambit_verify.hashing import sha256_hex
from ambit_verify.resource_protocol import (
    DISPATCH_CONTEXT,
    MCP_CALL_PROFILE,
    OUTCOME_CONTEXT,
    payload_bytes,
    resource_binding_hash,
)

REPO = Path(__file__).resolve().parent.parent
VECTOR_DIR = REPO / "tests" / "vectors" / "mcp-call-v1"
DISPATCH_SEED = bytes(range(1, 33))
OUTCOME_SEED = bytes(range(33, 65))
RECEIVER_SEED = bytes(range(65, 97))
BINDING_VECTOR = REPO / "tests" / "vectors" / "mcp-call-v1-binding" / "binding-hashes.json"
_CALL = {"name": "search", "arguments": {"query": "invoices", "limit": 5}}
_RESPONSE = {"jsonrpc": "2.0", "id": 7, "result": {"content": [], "isError": False}}
_RESULT = {"content": [], "isError": False}
_OBSERVED_AT = "2026-11-22T01:00:05Z"
_ATTESTATION = {"operator_id": "op-1", "reason": "door log confirms the call"}


def _public_key_hex(seed: bytes) -> str:
    """Return the raw Ed25519 public key for ``seed`` as lowercase hex."""
    key = Ed25519PrivateKey.from_private_bytes(seed)
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw.hex()


def _token(claims: dict[str, Any], message: bytes, seed: bytes) -> str:
    """Build the compact token: base64url payload, a dot, base64url signature."""
    payload = base64.urlsafe_b64encode(canonical_json_bytes(claims)).rstrip(b"=")
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    return f"{payload.decode()}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"


def binding() -> dict[str, Any]:
    """Return the resource binding the dispatch and every outcome join. It has no receiver key."""
    return {
        "adapter_id": "mcp",
        "downstream_url": "http://127.0.0.1:9000",
        "downstream_path": "/v1/tools/call",
        "receipt_public_key": "b" * 64,
        "outcome_profile": MCP_CALL_PROFILE,
        "outcome_public_key": _public_key_hex(OUTCOME_SEED),
    }


def _join_fields() -> dict[str, Any]:
    """Return the 12 join fields shared by the dispatch and every outcome."""
    return {
        "version": 1,
        "profile": MCP_CALL_PROFILE,
        "domain_id": "example.test",
        "ledger_id": "ledger-1",
        "enforcement_point_id": "ep-1",
        "resource_id": "mcp-door",
        "resource_binding_hash": resource_binding_hash(binding()),
        "operation_id": "op-0001",
        "request_hash": sha256_hex(b"request"),
        "payload_hash": sha256_hex(payload_bytes(_CALL)),
        "decision_hash": sha256_hex(b"decision"),
        "intent_hash": sha256_hex(b"intent"),
    }


def dispatch_claims() -> dict[str, Any]:
    """Return the valid dispatch claims."""
    return {
        **_join_fields(),
        "action_type": "execute",
        "action_boundary": "tool_call",
        "action_domain": "mcp",
        "action_path": ".",
        "authorized_at": "2026-11-22T01:00:00Z",
        "not_after": "2026-11-22T01:05:00Z",
    }


def outcome_claims(
    status: str,
    observed_by: str,
    *,
    response: bool = False,
    attestation: dict[str, str] | None = None,
    response_hash: str | None = None,
) -> dict[str, Any]:
    """Return outcome claims. ``response`` adds an observed response hash and tool_error."""
    return {
        **_join_fields(),
        "status": status,
        "observed_by": observed_by,
        "observed_at": _OBSERVED_AT,
        "response_hash": (response_hash or hash_object(_RESPONSE)) if response else None,
        "tool_error": False if response else None,
        "attestation": attestation,
    }


def _vector(
    claims: dict[str, Any],
    *,
    kind: str,
    valid: bool,
    description: str,
    signer: bytes | None = None,
    verifier: bytes | None = None,
    fails: str | None = None,
) -> dict[str, Any]:
    """Sign ``claims`` and describe the result.

    The signer defaults to the dispatch key for a dispatch and to the outcome key for an
    outcome. ``verifier`` names the key whose public half the vector lists. ``fails`` names
    the layer that refuses a vector whose claims are schema-valid.
    """
    context, seed = (
        (DISPATCH_CONTEXT, DISPATCH_SEED) if kind == "dispatch" else (OUTCOME_CONTEXT, OUTCOME_SEED)
    )
    seed = signer or seed
    canonical = canonical_json_bytes(claims)
    message = context + canonical
    vector = {
        "kind": kind,
        "valid": valid,
        "description": description,
        "claims": claims,
        "canonical_bytes_hex": canonical.hex(),
        "signing_message_hex": message.hex(),
        "public_key_hex": _public_key_hex(verifier or seed),
        "token": _token(claims, message, seed),
    }
    if fails is not None:
        vector["fails"] = fails
    return vector


def _invalid(base: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """Return a copy of ``base`` with ``changes`` applied. A value of ``...`` drops the key."""
    claims = copy.deepcopy(base)
    for name, value in changes.items():
        if value is ...:
            del claims[name]
        else:
            claims[name] = value
    return claims


def build_vectors() -> dict[str, dict[str, Any]]:
    """Return every vector keyed by file stem."""
    committed = outcome_claims("committed", "proxy", response=True)
    receiver_committed = outcome_claims(
        "committed", "receiver", response=True, response_hash=hash_object(_RESULT)
    )
    operator = {"attestation": _ATTESTATION}
    cases: dict[str, tuple[str, dict[str, Any], bool, str]] = {
        "dispatch": ("dispatch", dispatch_claims(), True, "Valid mcp-call/1 dispatch."),
        "outcome-committed-proxy": (
            "outcome",
            committed,
            True,
            "Proxy saw the MCP response.",
        ),
        "outcome-not-executed-proxy": (
            "outcome",
            outcome_claims("not_executed", "proxy"),
            True,
            "Door cancelled before it sent the call.",
        ),
        "outcome-committed-operator": (
            "outcome",
            outcome_claims("committed", "operator", **operator),
            True,
            "Operator attests the call committed.",
        ),
        "outcome-not-executed-operator": (
            "outcome",
            outcome_claims("not_executed", "operator", **operator),
            True,
            "Operator attests the call did not execute.",
        ),
        "outcome-unknown-proxy": (
            "outcome",
            outcome_claims("unknown", "proxy"),
            True,
            "Valid token that is never a terminal.",
        ),
        "invalid-committed-proxy-missing-response-hash": (
            "outcome",
            _invalid(committed, response_hash=None),
            False,
            "Committed proxy outcome without response_hash.",
        ),
        "invalid-proxy-terminal-with-attestation": (
            "outcome",
            _invalid(committed, attestation=_ATTESTATION),
            False,
            "Proxy terminal carries an attestation.",
        ),
        "invalid-operator-terminal-without-attestation": (
            "outcome",
            outcome_claims("committed", "operator"),
            False,
            "Operator terminal has no attestation.",
        ),
        "invalid-extra-field": (
            "outcome",
            _invalid(committed, extra="x"),
            False,
            "Outcome claims carry a field outside the profile.",
        ),
        "invalid-operator-unknown": (
            "outcome",
            outcome_claims("unknown", "operator", **operator),
            False,
            "Operator attestation states unknown.",
        ),
        "invalid-attestation-extra-key": (
            "outcome",
            outcome_claims("committed", "operator", attestation={**_ATTESTATION, "ticket": "T-1"}),
            False,
            "Attestation has a key beyond operator_id and reason.",
        ),
    }
    vectors = {
        name: _vector(claims, kind=kind, valid=valid, description=description)
        for name, (kind, claims, valid, description) in cases.items()
    }
    vectors.update(_receiver_vectors(receiver_committed))
    return vectors


def _receiver_vectors(committed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the vectors for outcomes the receiver of the tool signs."""
    receiver = {"signer": RECEIVER_SEED}
    not_executed = outcome_claims("not_executed", "receiver")
    return {
        "outcome-committed-receiver": _vector(
            committed,
            kind="outcome",
            valid=True,
            description="Receiver committed the effect and signed in the same transaction.",
            **receiver,
        ),
        "outcome-not-executed-receiver": _vector(
            not_executed,
            kind="outcome",
            valid=True,
            description="Receiver states the tool declined before any effect.",
            **receiver,
        ),
        "invalid-receiver-with-attestation": _vector(
            _invalid(committed, attestation=_ATTESTATION),
            kind="outcome",
            valid=False,
            description="Receiver outcome carries an attestation.",
            **receiver,
        ),
        "invalid-receiver-unknown": _vector(
            outcome_claims("unknown", "receiver"),
            kind="outcome",
            valid=False,
            description="Receiver outcome states unknown.",
            **receiver,
        ),
        "invalid-receiver-wrong-key": _vector(
            committed,
            kind="outcome",
            valid=False,
            description="Claims say receiver but the door key signed them.",
            signer=OUTCOME_SEED,
            verifier=RECEIVER_SEED,
            fails="signature",
        ),
    }


def binding_hash_vector() -> dict[str, Any]:
    """Return the vector that pins the binding hash with and without a receiver key."""
    old = binding()
    receiver_key = _public_key_hex(RECEIVER_SEED)
    return {
        "description": (
            "A binding without receiver_public_key hashes as it always did. "
            "The key, when present, joins the hashed fields."
        ),
        "binding_without_receiver": old,
        "hash_without_receiver": resource_binding_hash(old),
        "binding_with_receiver": {**old, "receiver_public_key": receiver_key},
        "hash_with_receiver": resource_binding_hash({**old, "receiver_public_key": receiver_key}),
    }


def render(vector: dict[str, Any]) -> str:
    """Return the file text for one vector."""
    return json.dumps(vector, indent=2, sort_keys=True) + "\n"


def main() -> int:
    """Write every vector file and report how many were written."""
    VECTOR_DIR.mkdir(parents=True, exist_ok=True)
    vectors = build_vectors()
    for name, vector in vectors.items():
        (VECTOR_DIR / f"{name}.json").write_text(render(vector), encoding="utf-8")
    BINDING_VECTOR.parent.mkdir(parents=True, exist_ok=True)
    BINDING_VECTOR.write_text(render(binding_hash_vector()), encoding="utf-8")
    print(f"wrote {len(vectors)} vectors to {VECTOR_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
