# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""The mcp-call/1 profile: golden vectors, schemas, validation and evidence class."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from importlib import resources
from pathlib import Path
from typing import Any

import pytest

import mini_jsonschema
from ambit_verify import (
    DISPATCH_META_KEY,
    OUTCOME_META_KEY,
    dispatch_message,
    load_schema,
    mcp_result_hash,
    outcome_evidence_class,
    outcome_joins_dispatch,
    verify_bound_outcome,
    verify_dispatch,
    verify_resource_outcome,
)
from ambit_verify.resource_protocol import (
    EVIDENCE_OPERATOR_ATTESTED,
    EVIDENCE_PROXY_OBSERVED,
    EVIDENCE_RECEIVER_SIGNED,
    MCP_CALL_PROFILE,
    is_terminal_outcome,
    reconciliation_message,
    resource_binding_hash,
    verify_terminal_resource_outcome,
)

REPO = Path(__file__).resolve().parent.parent
VECTORS = REPO / "tests" / "vectors" / "mcp-call-v1"


def _generator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "generate_mcp_call_vectors", REPO / "scripts" / "generate_mcp_call_vectors.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GENERATOR = _generator()
FILES = sorted(VECTORS.glob("*.json"))
VALID_OUTCOMES = [p for p in FILES if p.name.startswith("outcome-")]
INVALID = [p for p in FILES if p.name.startswith("invalid-")]


def _load(path: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def _schema(kind: str) -> dict[str, Any]:
    return load_schema(f"mcp-call-v1/{kind}-claims")


def _verify(vector: dict[str, Any]) -> dict[str, Any]:
    verify = verify_dispatch if vector["kind"] == "dispatch" else verify_resource_outcome
    return verify(vector["token"], public_key=vector["public_key_hex"])


def test_vector_files_match_the_generator_byte_for_byte() -> None:
    expected = {
        f"{name}.json": GENERATOR.render(v) for name, v in GENERATOR.build_vectors().items()
    }
    actual = {path.name: path.read_text(encoding="utf-8") for path in FILES}
    assert actual == expected


def test_vector_set_covers_the_required_cases() -> None:
    assert len(VALID_OUTCOMES) == 7
    assert len(INVALID) >= 7


@pytest.mark.parametrize("path", [p for p in FILES if not p.name.startswith("invalid-")])
def test_valid_vector_verifies_and_returns_its_claims(path: Path) -> None:
    vector = _load(path)
    assert _verify(vector) == vector["claims"]


@pytest.mark.parametrize("path", FILES)
def test_vector_bytes_are_the_canonical_claims(path: Path) -> None:
    vector = _load(path)
    canonical = bytes.fromhex(vector["canonical_bytes_hex"])
    assert canonical == json.dumps(
        vector["claims"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    assert vector["token"].split(".")[0] == (
        base64.urlsafe_b64encode(canonical).rstrip(b"=").decode()
    )
    assert bytes.fromhex(vector["signing_message_hex"]).endswith(canonical)


@pytest.mark.parametrize("path", INVALID)
def test_invalid_vector_is_rejected_though_correctly_signed(path: Path) -> None:
    vector = _load(path)
    with pytest.raises(ValueError):
        _verify(vector)


@pytest.mark.parametrize("path", FILES)
def test_schema_and_verifier_agree_on_every_vector(path: Path) -> None:
    vector = _load(path)
    if vector.get("fails") == "signature":
        pytest.skip("claims are schema-valid; only the signature check refuses this vector")
    schema = _schema(vector["kind"])
    assert mini_jsonschema.is_valid(vector["claims"], schema) is vector["valid"]


def test_unknown_status_is_a_valid_token_but_never_terminal() -> None:
    vector = _load(VECTORS / "outcome-unknown-proxy.json")
    claims = _verify(vector)
    assert claims["status"] == "unknown"
    assert not is_terminal_outcome(claims)
    with pytest.raises(ValueError, match="not terminal"):
        verify_terminal_resource_outcome(vector["token"], public_key=vector["public_key_hex"])


def test_unknown_outcome_never_joins_its_dispatch() -> None:
    dispatch = _verify(_load(VECTORS / "dispatch.json"))
    unknown = _verify(_load(VECTORS / "outcome-unknown-proxy.json"))
    committed = _verify(_load(VECTORS / "outcome-committed-proxy.json"))
    assert not outcome_joins_dispatch(unknown, dispatch)
    assert outcome_joins_dispatch(committed, dispatch)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("outcome-committed-proxy", EVIDENCE_PROXY_OBSERVED),
        ("outcome-not-executed-proxy", EVIDENCE_PROXY_OBSERVED),
        ("outcome-committed-operator", EVIDENCE_OPERATOR_ATTESTED),
        ("outcome-not-executed-operator", EVIDENCE_OPERATOR_ATTESTED),
        ("outcome-committed-receiver", EVIDENCE_RECEIVER_SIGNED),
        ("outcome-not-executed-receiver", EVIDENCE_RECEIVER_SIGNED),
    ],
)
def test_evidence_class_follows_observed_by(name: str, expected: str) -> None:
    assert outcome_evidence_class(_verify(_load(VECTORS / f"{name}.json"))) == expected


def test_existing_profiles_are_receiver_signed() -> None:
    assert outcome_evidence_class({"profile": "record-egress/1"}) == EVIDENCE_RECEIVER_SIGNED
    assert outcome_evidence_class({"profile": "customer-delete/1"}) == EVIDENCE_RECEIVER_SIGNED


def test_evidence_class_refuses_an_invalid_observer() -> None:
    with pytest.raises(ValueError, match="observed_by"):
        outcome_evidence_class({"profile": MCP_CALL_PROFILE, "observed_by": "agent"})


def test_dispatch_action_path_must_be_a_dot() -> None:
    vector = _load(VECTORS / "dispatch.json")
    claims = {**vector["claims"], "action_path": "/x"}
    with pytest.raises(ValueError, match="action_path"):
        dispatch_message(claims)


def test_reconciliation_accepts_the_profile() -> None:
    join = {
        k: v
        for k, v in _load(VECTORS / "dispatch.json")["claims"].items()
        if k in GENERATOR._join_fields()
    }
    claims = {
        **join,
        "verb": "query",
        "issued_at": "2026-11-22T01:00:00Z",
        "expires_at": "2026-11-22T01:01:00Z",
    }
    assert reconciliation_message(claims).endswith(b"}")


def test_binding_requires_the_mcp_adapter() -> None:
    binding = {
        "adapter_id": "http",
        "downstream_url": "http://127.0.0.1:9000",
        "downstream_path": "/v1/tools/call",
        "receipt_public_key": "b" * 64,
        "outcome_profile": MCP_CALL_PROFILE,
        "outcome_public_key": "c" * 64,
    }
    with pytest.raises(ValueError, match="MCP adapter"):
        resource_binding_hash(binding)
    assert len(resource_binding_hash({**binding, "adapter_id": "mcp"})) == 64


def _binding(*, receiver: bool = False) -> dict[str, Any]:
    binding = GENERATOR.binding()
    if receiver:
        binding["receiver_public_key"] = GENERATOR._public_key_hex(GENERATOR.RECEIVER_SEED)
    return binding


def test_receiver_outcome_joins_its_dispatch_and_is_terminal() -> None:
    dispatch = _verify(_load(VECTORS / "dispatch.json"))
    committed = _verify(_load(VECTORS / "outcome-committed-receiver.json"))
    not_executed = _verify(_load(VECTORS / "outcome-not-executed-receiver.json"))
    assert outcome_joins_dispatch(committed, dispatch)
    assert outcome_joins_dispatch(not_executed, dispatch)


def test_receiver_committed_response_hash_is_the_result_hash() -> None:
    claims = _verify(_load(VECTORS / "outcome-committed-receiver.json"))
    assert claims["response_hash"] == mcp_result_hash(GENERATOR._RESULT)


def test_result_hash_ignores_meta_and_covers_the_rest() -> None:
    result = {"content": [{"type": "text", "text": "x"}], "isError": False}
    assert mcp_result_hash({**result, "_meta": {OUTCOME_META_KEY: "token"}}) == mcp_result_hash(
        result
    )
    assert mcp_result_hash({**result, "isError": True}) != mcp_result_hash(result)
    with pytest.raises(ValueError):
        mcp_result_hash({"x": float("nan")})


def test_meta_keys_have_no_reserved_prefix_and_differ() -> None:
    for key in (DISPATCH_META_KEY, OUTCOME_META_KEY):
        assert "/" not in key
        assert "modelcontextprotocol" not in key
        assert not key.startswith("mcp")
    assert DISPATCH_META_KEY != OUTCOME_META_KEY


def test_bound_outcome_uses_the_receiver_key_for_a_receiver_outcome() -> None:
    vector = _load(VECTORS / "outcome-committed-receiver.json")
    claims = verify_bound_outcome(vector["token"], _binding(receiver=True), terminal=True)
    assert claims == vector["claims"]


def test_bound_outcome_uses_the_outcome_key_for_proxy_and_operator_outcomes() -> None:
    for name in ("outcome-committed-proxy", "outcome-committed-operator"):
        vector = _load(VECTORS / f"{name}.json")
        assert verify_bound_outcome(vector["token"], _binding()) == vector["claims"]
        assert verify_bound_outcome(vector["token"], _binding(receiver=True)) == vector["claims"]


def test_bound_outcome_refuses_a_receiver_outcome_without_a_receiver_key() -> None:
    vector = _load(VECTORS / "outcome-committed-receiver.json")
    with pytest.raises(ValueError, match="receiver_public_key"):
        verify_bound_outcome(vector["token"], _binding())


def test_bound_outcome_refuses_a_receiver_claim_signed_by_the_door_key() -> None:
    vector = _load(VECTORS / "invalid-receiver-wrong-key.json")
    with pytest.raises(ValueError, match="does not verify"):
        verify_bound_outcome(vector["token"], _binding(receiver=True))


def test_bound_outcome_refuses_a_proxy_claim_signed_by_the_receiver_key() -> None:
    receiver = _load(VECTORS / "outcome-committed-receiver.json")
    claims = {**receiver["claims"], "observed_by": "proxy"}
    forged = GENERATOR._vector(
        claims, kind="outcome", valid=False, description="x", signer=GENERATOR.RECEIVER_SEED
    )
    with pytest.raises(ValueError, match="does not verify"):
        verify_bound_outcome(forged["token"], _binding(receiver=True))


def test_bound_outcome_terminal_flag_refuses_unknown() -> None:
    vector = _load(VECTORS / "outcome-unknown-proxy.json")
    assert verify_bound_outcome(vector["token"], _binding())["status"] == "unknown"
    with pytest.raises(ValueError, match="not terminal"):
        verify_bound_outcome(vector["token"], _binding(), terminal=True)


def test_bound_outcome_refuses_a_malformed_token_and_binding() -> None:
    with pytest.raises(ValueError):
        verify_bound_outcome("nope", _binding())
    with pytest.raises(ValueError):
        verify_bound_outcome("a.b", _binding())


def test_old_binding_hashes_as_before_and_the_receiver_key_joins_the_hash() -> None:
    vector = json.loads(
        (REPO / "tests" / "vectors" / "mcp-call-v1-binding" / "binding-hashes.json").read_text(
            encoding="utf-8"
        )
    )
    dispatch = _load(VECTORS / "dispatch.json")["claims"]
    assert (
        resource_binding_hash(vector["binding_without_receiver"]) == vector["hash_without_receiver"]
    )
    assert vector["hash_without_receiver"] == dispatch["resource_binding_hash"]
    assert vector["hash_without_receiver"] == (
        "83d0bc997bfa4485fc65e1a50ff132f5d8d0cba46d67167255276f55bf2b4e64"
    )
    assert resource_binding_hash(vector["binding_with_receiver"]) == vector["hash_with_receiver"]
    assert vector["hash_with_receiver"] != vector["hash_without_receiver"]
    assert vector == GENERATOR.binding_hash_vector()


@pytest.mark.parametrize(
    "change",
    [
        {"receiver_public_key": "c" * 64},
        {"receiver_public_key": "b" * 64},
        {"receiver_public_key": "zz"},
        {"receiver_public_key": 5},
        {"outcome_profile": "record-egress/1", "adapter_id": "http"},
    ],
)
def test_receiver_key_in_a_binding_is_validated(change: dict[str, Any]) -> None:
    binding = {**_binding(), "outcome_public_key": "c" * 64, **change}
    if "receiver_public_key" not in change:
        binding["receiver_public_key"] = "d" * 64
    with pytest.raises(ValueError):
        resource_binding_hash(binding)


def test_receiver_key_must_differ_from_the_outcome_key() -> None:
    binding = _binding()
    with pytest.raises(ValueError, match="receiver_public_key"):
        resource_binding_hash({**binding, "receiver_public_key": binding["outcome_public_key"]})


PACKAGED_SCHEMA_SHA256 = {
    "dispatch-claims": "743634affca8fd75bc979730b629b7cf9d4cf56d096d5c9e5ddfe0c86d4aeeb2",
    "outcome-claims": "d7bd4be6f9202c98b541db24c499f6c3ccef0199b84d8c98665dbd84e49601df",
}


@pytest.mark.parametrize("kind", sorted(PACKAGED_SCHEMA_SHA256))
def test_packaged_schema_bytes_are_unchanged(kind: str) -> None:
    resource = resources.files("ambit_verify.schemas").joinpath(f"mcp-call-v1/{kind}.schema.json")
    digest = hashlib.sha256(resource.read_bytes()).hexdigest()
    assert digest == PACKAGED_SCHEMA_SHA256[kind]


@pytest.mark.parametrize("kind", sorted(PACKAGED_SCHEMA_SHA256))
def test_load_schema_returns_the_packaged_schema(kind: str) -> None:
    schema = load_schema(f"mcp-call-v1/{kind}")
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == f"urn:ambit:verify:schema:mcp-call-v1:{kind}"


@pytest.mark.parametrize("name", ["mcp-call-v1/other", "../pyproject", "dispatch-claims", ""])
def test_load_schema_rejects_an_unknown_name(name: str) -> None:
    with pytest.raises(ValueError, match="unknown schema"):
        load_schema(name)
