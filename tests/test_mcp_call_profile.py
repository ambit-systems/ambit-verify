# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""The mcp-call/1 profile: golden vectors, schemas, validation and evidence class."""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

import mini_jsonschema
from ambit_verify import (
    dispatch_message,
    outcome_evidence_class,
    outcome_joins_dispatch,
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
SCHEMAS = REPO / "schemas" / "mcp-call-v1"


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
    loaded: dict[str, Any] = json.loads(
        (SCHEMAS / f"{kind}-claims.schema.json").read_text(encoding="utf-8")
    )
    return loaded


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
    assert len(VALID_OUTCOMES) == 5
    assert len(INVALID) >= 4


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
