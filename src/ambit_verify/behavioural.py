# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Authenticate bounded behavioural statements, without trusting caches or learning inline.

A valid signature attributes a statement. It does not prove its numerical model
is correct. Full model replay is a separate Observatory operation. Source records
are retained from genesis so an exporter cannot omit inconvenient observations.
"""

from __future__ import annotations

import base64
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .hashing import canonical_json_bytes, hash_object, strict_json_loads
from .head_attestation import ATTESTATION_BLOCK_KEYS, HeadAttestation
from .head_attestation_ed25519 import Ed25519HeadVerifier
from .verify import GENESIS_HASH, _check_record, _read_utf8_document, read_verified_records

SIGNING_DOMAIN = b"ambit.behavioural.snapshot.v1\x00"
SCHEMA = "ambit.behavioural.snapshot.v1"
MAX_SNAPSHOT_BYTES = 1_048_576
MAX_SOURCE_RECORDS = 4096
_PAYLOAD_KEYS = frozenset(
    {
        "schema",
        "issuer",
        "actor_id",
        "domain",
        "audience",
        "issued_at_ms",
        "expires_at_ms",
        "source",
        "model_config",
        "result",
    }
)
_RESULT_KEYS = frozenset(
    {
        "score",
        "score_band",
        "confidence_band",
        "observation_count",
        "posterior_state",
    }
)


class BehaviouralVerificationError(ValueError):
    """An untrusted snapshot failed the explicit verification contract."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise BehaviouralVerificationError(reason)


def _object(value: Any, keys: frozenset[str], name: str) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == keys, f"{name}: invalid fields")
    return dict(value)


def _integer(value: Any, name: str, minimum: int = 0) -> int:
    _require(type(value) is int and minimum <= value <= 2**53 - 1, f"{name}: invalid integer")
    return int(value)


def _text(value: Any, name: str) -> str:
    _require(isinstance(value, str) and 0 < len(value) <= 256, f"{name}: invalid string")
    return str(value)


def _bounded_tree(value: Any) -> None:
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        _require(depth <= 32 and count <= 100_000, "snapshot: structure limit exceeded")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
        elif type(item) is int:
            _require(abs(item) <= 2**53 - 1, "snapshot: integer limit")
        elif isinstance(item, float):
            _require(math.isfinite(item), "snapshot: non-finite number")


def parse_behavioural_snapshot(data: bytes) -> dict[str, Any]:
    """Parse bounded UTF-8 JSON, rejecting duplicates and non-finite numbers."""
    _require(isinstance(data, bytes) and len(data) <= MAX_SNAPSHOT_BYTES, "snapshot: size limit")
    try:
        value = strict_json_loads(data.decode("utf-8"))
        _bounded_tree(value)
        return _object(value, frozenset({"payload", "signature"}), "snapshot")
    except (UnicodeError, RecursionError, ValueError) as exc:
        raise BehaviouralVerificationError(f"snapshot: invalid JSON: {exc}") from exc


def snapshot_bytes(snapshot: Mapping[str, Any]) -> bytes:
    """Copy a snapshot into bounded canonical bytes; no mutable object is trusted."""
    try:
        _bounded_tree(snapshot)
        data = canonical_json_bytes(snapshot)
        parse_behavioural_snapshot(data)
        return data
    except (TypeError, RecursionError, ValueError) as exc:
        raise BehaviouralVerificationError(f"snapshot: invalid value: {exc}") from exc


def read_bounded_json_object(path: str | Path) -> dict[str, Any]:
    """Read bounded UTF-8 JSON through the verifier's regular-file/no-symlink boundary."""
    try:
        data = _read_utf8_document(Path(path))
        _require(len(data.encode("utf-8")) <= MAX_SNAPSHOT_BYTES, "document: size limit")
        value = strict_json_loads(data)
        _bounded_tree(value)
        _require(isinstance(value, dict), "document: expected object")
        return dict(value)
    except Exception as exc:
        raise BehaviouralVerificationError(f"JSON file refused: {exc}") from exc


def read_behavioural_snapshot(path: str | Path) -> bytes:
    """Read and parse a bounded snapshot from a regular file without following symlinks."""
    return snapshot_bytes(read_bounded_json_object(path))


def _signature(value: Any) -> bytes:
    _require(isinstance(value, str) and len(value) <= 128, "signature: invalid encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise BehaviouralVerificationError("signature: invalid base64") from exc
    _require(len(raw) == 64, "signature: invalid length")
    return raw


def read_behavioural_source_records(path: str | Path) -> list[dict[str, Any]]:
    """Load a hash-verified bounded source; a signed head is still required for authentication."""
    ok, records, error = read_verified_records(path)
    _require(ok, error or "source: invalid chain")
    _require(len(records) <= MAX_SOURCE_RECORDS, "source: record limit")
    return list(records)


def verify_behavioural_source(
    source: Any,
    *,
    records: list[dict[str, Any]],
    source_public_keys: Mapping[str, str],
    expected_ledger_id: str,
) -> tuple[list[dict[str, Any]], HeadAttestation]:
    """Verify the full retained source sequence against an operator-trusted Ed25519 head."""
    block = _object(source, frozenset({"head"}), "source")
    head = _object(block["head"], ATTESTATION_BLOCK_KEYS, "source.head")
    _integer(head["max_seq"], "source.head.max_seq", 1)
    _text(head["trust_root_id"], "source.head.trust_root_id")
    _text(head["recorded_at"], "source.head.recorded_at")
    _require(head["ledger_id"] == expected_ledger_id, "source: wrong ledger")
    _require(isinstance(head["signature"], str), "source: invalid signature")
    _require(isinstance(head["head_record_hash"], str), "source: invalid head hash")
    attestation = HeadAttestation(**head)
    try:
        key = bytes.fromhex(source_public_keys[attestation.trust_root_id])
        verified = Ed25519HeadVerifier(
            public_key=key,
            trust_root_id=attestation.trust_root_id,
        ).verify_head(attestation)
    except (KeyError, ValueError, TypeError) as exc:
        raise BehaviouralVerificationError("source: untrusted key") from exc
    _require(verified, "source: invalid head signature")
    _require(
        isinstance(records, list) and 0 < len(records) <= MAX_SOURCE_RECORDS, "source: record limit"
    )
    _require(len(records) == attestation.max_seq, "source: incomplete history")
    previous = GENESIS_HASH
    verified_records = []
    for index, record in enumerate(records):
        checked = _check_record(canonical_json_bytes(record).decode(), index, previous, "source")
        _require(
            checked.error is None and checked.record is not None,
            checked.error or "source: invalid record",
        )
        previous = checked.record_hash
        verified_records.append(dict(record))
    _require(previous == attestation.head_record_hash, "source: head mismatch")
    return verified_records, attestation


@dataclass(frozen=True)
class VerifiedBehaviouralSnapshot:
    """Immutable verified bytes. Admission must reverify rather than trust type construction."""

    data: bytes

    def __init__(self, data: bytes) -> None:
        raise TypeError("use authenticate_behavioural_snapshot; raw bytes are not verified")

    @property
    def snapshot(self) -> dict[str, Any]:
        """Return a detached copy of the retained signed artefact."""
        return parse_behavioural_snapshot(self.data)

    @property
    def payload(self) -> dict[str, Any]:
        """Return a detached copy of its signed statement."""
        return dict(self.snapshot["payload"])

    @property
    def digest(self) -> str:
        """Return the complete signed artefact identity."""
        return hash_object(self.snapshot)


def authenticate_behavioural_snapshot(
    snapshot: bytes,
    *,
    observer_public_keys: Mapping[str, str],
    source_public_keys: Mapping[str, str],
    expected_actor: str,
    expected_domain: str,
    expected_audience: str,
    expected_source_ledger: str,
    expected_model_config_hash: str,
    evaluation_time_ms: int,
    max_age_ms: int,
) -> VerifiedBehaviouralSnapshot:
    """Authenticate and bind a snapshot using explicit trust, identity and evaluation time.

    Caller-owned keys/configuration are not inferred from the signed artefact.
    Freshness covers both the statement and the observed source cutoff. Rollback
    relative to previous admissions is checked atomically by the canonical ledger.
    """
    document = parse_behavioural_snapshot(snapshot)
    payload = _object(document["payload"], _PAYLOAD_KEYS, "payload")
    _require(payload["schema"] == SCHEMA, "snapshot: unsupported schema")
    for field in ("issuer", "actor_id", "domain", "audience"):
        _text(payload[field], field)
    for field, expected in (
        ("actor_id", expected_actor),
        ("domain", expected_domain),
        ("audience", expected_audience),
    ):
        _require(bool(expected) and payload[field] == expected, f"snapshot: wrong {field}")
    now = _integer(evaluation_time_ms, "evaluation_time_ms")
    age = _integer(max_age_ms, "max_age_ms", 1)
    issued = _integer(payload["issued_at_ms"], "issued_at_ms")
    expiry = _integer(payload["expires_at_ms"], "expires_at_ms")
    _require(
        issued <= now < expiry and now - issued <= age and expiry - issued <= age,
        "snapshot: stale, future or excessive validity",
    )
    try:
        key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(
                observer_public_keys[payload["issuer"]],
            )
        )
        key.verify(
            _signature(document["signature"]), SIGNING_DOMAIN + canonical_json_bytes(payload)
        )
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise BehaviouralVerificationError(
            "snapshot: untrusted issuer or invalid signature"
        ) from exc
    config = payload["model_config"]
    _require(
        isinstance(config, dict) and hash_object(config) == expected_model_config_hash,
        "snapshot: model configuration mismatch",
    )
    _text(config.get("model_version"), "model_config.model_version")
    source = _object(payload["source"], frozenset({"head"}), "source")
    head_block = _object(source["head"], ATTESTATION_BLOCK_KEYS, "source.head")
    _integer(head_block["max_seq"], "source.head.max_seq", 1)
    for name in ("recorded_at", "trust_root_id", "ledger_id", "signature", "head_record_hash"):
        _text(head_block[name], "source.head." + name)
    _require(head_block["ledger_id"] == expected_source_ledger, "source: wrong ledger")
    try:
        head = HeadAttestation(**head_block)
        source_key = bytes.fromhex(source_public_keys[head.trust_root_id])
        valid_head = Ed25519HeadVerifier(
            public_key=source_key,
            trust_root_id=head.trust_root_id,
        ).verify_head(head)
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise BehaviouralVerificationError("source: invalid head") from exc
    _require(valid_head, "source: invalid head signature")
    try:
        cutoff = datetime.fromisoformat(head.recorded_at.replace("Z", "+00:00"))
        _require(cutoff.tzinfo is not None, "source: timestamp has no timezone")
        cutoff_ms = int(cutoff.timestamp() * 1000)
    except (ValueError, OverflowError) as exc:
        raise BehaviouralVerificationError("source: invalid timestamp") from exc
    _require(0 <= now - cutoff_ms <= age and cutoff_ms <= issued, "source: stale or future cutoff")
    result = _object(payload["result"], _RESULT_KEYS, "result")
    score = result["score"]
    _require(
        type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 1,
        "result: invalid score",
    )
    _require(
        result["score_band"] in ("normal", "elevated", "anomalous", "critical"),
        "result: invalid band",
    )
    _require(result["confidence_band"] in ("low", "medium", "high"), "result: invalid confidence")
    count = _integer(result["observation_count"], "observation_count", 1)
    _require(count <= head.max_seq, "result: impossible observation count")
    state = result["posterior_state"]
    _require(
        isinstance(state, dict)
        and state.get("actor_id") == expected_actor
        and type(state.get("observation_count")) is int
        and state.get("observation_count") == count,
        "result: invalid posterior identity",
    )
    verified = object.__new__(VerifiedBehaviouralSnapshot)
    object.__setattr__(verified, "data", snapshot_bytes(document))
    return verified


def verify_behavioural_snapshot(
    snapshot: bytes,
    *,
    source_records: list[dict[str, Any]],
    **verification: Any,
) -> VerifiedBehaviouralSnapshot:
    """Authenticate a snapshot AND verify its retained source history from genesis.

    Source records are separate so admission never recursively embeds its own
    history. They must accompany an offline verification export.
    """
    verified = authenticate_behavioural_snapshot(snapshot, **verification)
    records, _head = verify_behavioural_source(
        verified.payload["source"],
        records=source_records,
        source_public_keys=verification["source_public_keys"],
        expected_ledger_id=verification["expected_source_ledger"],
    )
    count = sum(
        r.get("record_type") == "decision" and r.get("actor_id") == verification["expected_actor"]
        for r in records
    )
    _require(
        count == verified.payload["result"]["observation_count"],
        "result: source observation count mismatch",
    )
    return verified
