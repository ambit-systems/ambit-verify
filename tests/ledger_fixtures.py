# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Test-only writer side: a minimal chained-ledger appender and head signers.

The package under test never writes a ledger and never signs one. These
helpers produce the same bytes the Ambit engine writes, so the verifier is
exercised against real fixtures without depending on the engine.
"""

from __future__ import annotations

import base64
import hmac
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify import (
    GENESIS_HASH,
    HeadAttestation,
    attestation_payload,
    canonical_json_bytes,
    hash_object,
)


class HeadSigner(Protocol):
    """Test-only signer protocol; the package exports only verifiers."""

    def sign_head(
        self,
        max_seq: int,
        head_record_hash: str,
        recorded_at: str,
        *,
        ledger_id: str | None = None,
    ) -> HeadAttestation: ...


TS = "2026-06-15T00:00:00.000Z"


def canonical_json(data: Mapping[str, Any]) -> str:
    return canonical_json_bytes(data).decode("utf-8")


def last_seq_and_hash(path: Path) -> tuple[int, str]:
    last_seq, last_hash = 0, GENESIS_HASH
    if not path.exists():
        return last_seq, last_hash
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        payload = json.loads(text)
        last_seq = payload["seq"]
        last_hash = payload["record_hash"]
    return last_seq, last_hash


def append(path: Path, record: Mapping[str, Any]) -> dict[str, Any]:
    """Append one hash-chained record and return it as written."""
    last_seq, last_hash = last_seq_and_hash(path)
    payload = dict(record)
    payload["seq"] = last_seq + 1
    payload.setdefault("timestamp_utc", TS)
    payload["prev_hash"] = last_hash
    hash_input = dict(payload)
    hash_input.pop("record_hash", None)
    payload["record_hash"] = hash_object(hash_input)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(payload) + "\n")
    return payload


def score(i: int) -> dict[str, object]:
    posterior_state = {"schema_version": 1, "actor_id": f"agent-{i}", "observation_count": i}
    return {
        "record_type": "observatory_score",
        "actor_id": f"agent-{i}",
        "score": 0.5,
        "posterior_state": posterior_state,
        "posterior_state_hash": hash_object(posterior_state),
    }


def filled(path: Path, n: int, start: int = 1) -> Path:
    for i in range(start, start + n):
        append(path, score(i))
    return path


def write_attestation(path: Path, attestation: HeadAttestation) -> None:
    """Write the ``.attest`` sidecar exactly as the engine writes it."""
    content = canonical_json(
        {
            "head_record_hash": attestation.head_record_hash,
            **({"ledger_id": attestation.ledger_id} if attestation.ledger_id else {}),
            "max_seq": attestation.max_seq,
            "recorded_at": attestation.recorded_at,
            "signature": attestation.signature,
            "trust_root_id": attestation.trust_root_id,
        }
    )
    path.with_suffix(".attest").write_text(content, encoding="utf-8")


def attest_head(path: Path, signer: HeadSigner, *, ledger_id: str | None = None) -> HeadAttestation:
    """Sign the current head of *path* and persist the sidecar."""
    last_seq, last_hash = last_seq_and_hash(path)
    attestation = signer.sign_head(last_seq, last_hash, TS, ledger_id=ledger_id)
    write_attestation(path, attestation)
    return attestation


def truncate(path: Path, keep: int) -> None:
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    path.write_text("\n".join(lines[:keep]) + "\n", encoding="utf-8")


def generate_keypair() -> tuple[bytes, bytes]:
    private = Ed25519PrivateKey.generate()
    return private.private_bytes_raw(), private.public_key().public_bytes_raw()


class HmacHeadSigner:
    """Test-only HMAC head signer; the shared-secret counterpart of HmacHeadVerifier."""

    def __init__(self, *, secret: str, trust_root_id: str) -> None:
        self._secret = secret
        self.trust_root_id = trust_root_id

    def sign_head(
        self,
        max_seq: int,
        head_record_hash: str,
        recorded_at: str,
        *,
        ledger_id: str | None = None,
    ) -> HeadAttestation:
        digest = hmac.new(
            self._secret.encode("utf-8"),
            attestation_payload(
                max_seq, head_record_hash, recorded_at, self.trust_root_id, ledger_id
            ),
            "sha256",
        ).hexdigest()
        return HeadAttestation(
            max_seq=max_seq,
            head_record_hash=head_record_hash,
            recorded_at=recorded_at,
            trust_root_id=self.trust_root_id,
            signature=f"hmac-sha256:{digest}",
            ledger_id=ledger_id,
        )


class Ed25519HeadSigner:
    """Test-only Ed25519 head signer; mirrors the engine's signer byte for byte."""

    def __init__(self, *, private_key: bytes, trust_root_id: str) -> None:
        self._private = Ed25519PrivateKey.from_private_bytes(private_key)
        self.trust_root_id = trust_root_id

    def sign_head(
        self,
        max_seq: int,
        head_record_hash: str,
        recorded_at: str,
        *,
        ledger_id: str | None = None,
    ) -> HeadAttestation:
        signature = self._private.sign(
            attestation_payload(
                max_seq, head_record_hash, recorded_at, self.trust_root_id, ledger_id
            )
        )
        return HeadAttestation(
            max_seq=max_seq,
            head_record_hash=head_record_hash,
            recorded_at=recorded_at,
            trust_root_id=self.trust_root_id,
            signature="ed25519:" + base64.b64encode(signature).decode("ascii"),
            ledger_id=ledger_id,
        )


class Ed25519Countersigner:
    """Test-only Ed25519 checkpoint countersigner."""

    def __init__(self, *, private_key: bytes, trust_root_id: str) -> None:
        self._private = Ed25519PrivateKey.from_private_bytes(private_key)
        self.trust_root_id = trust_root_id

    def sign_countersignature(self, payload: bytes) -> str:
        return "ed25519:" + base64.b64encode(self._private.sign(payload)).decode("ascii")
