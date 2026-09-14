# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Parsing and checking a countersigned checkpoint against a ledger.

A checkpoint is a holder's own record of one head: the head itself, the
writer's attestation for it, the witness record for that head, and a
countersignature over all three by a key neither the writer nor the witness
holds. ``verify.py`` first sanitises the caller-supplied checkpoint object
into a bounded, JSON-native snapshot (``_checkpoint_snapshot``); this module
reads that snapshot's fields fail-closed and checks them against a ledger.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeGuard

from .hashing import hash_object
from .head_attestation import (
    ATTESTATION_BLOCK_KEYS,
    CheckpointVerifier,
    HeadAttestation,
    HeadVerifier,
    attestation_block,
    checkpoint_payload,
)
from .head_attestation_checks import _attestation_from_block
from .verify import _Chain, _checkpoint_snapshot, _is_digest, _terminal_safe, _walk_ledger

# A checkpoint carries exactly these five fields. Nothing else is signed, so
# nothing else is admitted.
_CHECKPOINT_KEYS = frozenset(
    {"seq", "record_hash", "attestation", "witness_record", "countersignature"}
)


def _is_non_empty_string(value: object) -> TypeGuard[str]:
    """Return True when *value* is a non-empty string."""
    return isinstance(value, str) and bool(value)


@dataclass(frozen=True)
class _Checkpoint:
    """One parsed checkpoint: a head, its two attestations, and the countersignature."""

    seq: int
    record_hash: str
    attestation: HeadAttestation
    attestation_hash: str
    witness_attestation: HeadAttestation
    witness_record_hash: str
    countersignature: str


def _parse_checkpoint_witness_record(
    record: object,
) -> tuple[HeadAttestation | None, str | None, str | None]:
    """Read and validate a checkpoint's ``witness_record`` field.

    Returns ``(witness_attestation, witness_record_hash, error)``. The first
    two are non-None exactly when *error* is None.
    """
    if not isinstance(record, Mapping):
        return None, None, "checkpoint witness_record must be an object"
    if record.get("record_type") != "head_witness":
        return None, None, "checkpoint witness_record is not a head_witness record"
    stored_hash = record.get("record_hash")
    if not _is_digest(stored_hash):
        return None, None, "checkpoint witness_record carries no record hash"
    # The record hash covers every other field the witness record carries, so
    # recomputing it here is what binds the witness attestation, the witnessed
    # ledger id, and anything a witness added beside them.
    unsigned = {key: value for key, value in record.items() if key != "record_hash"}
    if hash_object(unsigned) != stored_hash:
        return None, None, "checkpoint witness_record does not hash to its record_hash"
    witness_block = record.get("attestation")
    if not isinstance(witness_block, Mapping):
        return None, None, "checkpoint witness_record carries no attestation"
    witnessed_ledger_id = record.get("witnessed_ledger_id")
    if not _is_non_empty_string(witnessed_ledger_id):
        return (
            None,
            None,
            "checkpoint witness_record witnessed_ledger_id must be a non-empty string",
        )
    if not _is_non_empty_string(witness_block.get("ledger_id")):
        return None, None, "checkpoint witness attestation ledger_id must be a non-empty string"
    witness_attestation = _attestation_from_block(witness_block)
    if witness_attestation is None:
        return None, None, "checkpoint witness attestation is malformed"
    if witness_attestation.ledger_id != witnessed_ledger_id:
        return None, None, "checkpoint witness attestation names another ledger"
    return witness_attestation, stored_hash, None


def _parse_checkpoint(checkpoint: Mapping[str, Any]) -> tuple[_Checkpoint | None, str | None]:
    """Read a checkpoint fail-closed. Returns ``(parsed, error)``."""
    unknown = set(checkpoint) - _CHECKPOINT_KEYS
    if unknown:
        return None, f"checkpoint has unsupported keys: {sorted(unknown)}"
    missing = _CHECKPOINT_KEYS - set(checkpoint)
    if missing:
        return None, f"checkpoint is missing fields: {sorted(missing)}"

    seq = checkpoint["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        return None, "checkpoint seq must be an integer of at least 1"
    record_hash = checkpoint["record_hash"]
    if not _is_digest(record_hash):
        return None, "checkpoint record_hash must be 64 lower-case hexadecimal characters"

    block = checkpoint["attestation"]
    if not isinstance(block, Mapping) or set(block) != ATTESTATION_BLOCK_KEYS:
        return None, "checkpoint attestation must carry exactly the attestation keys"
    if not _is_non_empty_string(block.get("ledger_id")):
        return None, "checkpoint attestation ledger_id must be a non-empty string"
    attestation = _attestation_from_block(block)
    if attestation is None:
        return None, "checkpoint attestation is malformed"

    witness_attestation, witness_record_hash, witness_error = _parse_checkpoint_witness_record(
        checkpoint["witness_record"]
    )
    if witness_error is not None:
        return None, witness_error
    assert witness_attestation is not None
    assert witness_record_hash is not None

    countersignature = checkpoint["countersignature"]
    if not isinstance(countersignature, str) or not countersignature:
        return None, "checkpoint countersignature must be a non-empty string"

    return (
        _Checkpoint(
            seq=seq,
            record_hash=record_hash,
            attestation=attestation,
            attestation_hash=hash_object(attestation_block(attestation)),
            witness_attestation=witness_attestation,
            witness_record_hash=witness_record_hash,
            countersignature=countersignature,
        ),
        None,
    )


def verify_checkpoint(
    ledger_path: str | Path,
    checkpoint: Mapping[str, Any],
    *,
    witness_verifier: HeadVerifier,
    countersign_verifier: CheckpointVerifier,
    authority_verifier: HeadVerifier | None = None,
    _chain: _Chain | None = None,
) -> tuple[bool, str | None]:
    """Check a ledger against a checkpoint its holder retained.

    A checkpoint names one head (``seq`` and ``record_hash``) and carries the
    writer's head attestation, the witness record for that head, and a
    countersignature by the holder's key. The holder keeps the file; nothing
    online is consulted. ``verify_witnessed_head`` compares a ledger with
    whatever the witness ledger now holds, so a party that writes to both
    ledgers can roll the ledger back, append again, and have the new head
    witnessed. A checkpoint is retained, not re-derived, so that rewrite fails
    here.

    Args:
        ledger_path: The ledger the checkpoint names.
        checkpoint: The parsed checkpoint object with exactly ``seq``,
            ``record_hash``, ``attestation``, ``witness_record`` and
            ``countersignature``.
        witness_verifier: Verifier for the witness key.
        countersign_verifier: Verifier for the holder's key.
        authority_verifier: Verifier for the writer's key. None leaves the
            writer's attestation bound by the countersignature only, with its
            signature unchecked.

    Returns:
        ``(ok, error)``. The check fails when the checkpoint does not parse or
        does not name one head; when the writer's attestation, the witness
        record, or the countersignature does not verify; when the chain does
        not verify; when the head sits below the checkpoint ``seq``
        (truncation); or when the record at that ``seq`` is not the
        checkpointed record (rollback). A ledger that only appended since the
        checkpoint passes.

    Raises:
        OSError: If a ledger file cannot be read.
    """
    try:
        snapshot = _checkpoint_snapshot(checkpoint)
    except (TypeError, ValueError, RecursionError, RuntimeError) as exc:
        return False, f"checkpoint is malformed ({_terminal_safe(exc)})"
    parsed, error = _parse_checkpoint(snapshot)
    if parsed is None:
        return False, error
    if parsed.attestation.ledger_id != parsed.witness_attestation.ledger_id:
        return False, "checkpoint attestations name different ledgers"
    if (
        parsed.attestation.max_seq != parsed.seq
        or parsed.attestation.head_record_hash != parsed.record_hash
    ):
        return False, "checkpoint attestation names another head"
    if (
        parsed.witness_attestation.max_seq != parsed.seq
        or parsed.witness_attestation.head_record_hash != parsed.record_hash
    ):
        return False, "checkpoint witness record names another head"
    if authority_verifier is not None and not authority_verifier.verify_head(parsed.attestation):
        return False, "checkpoint attestation invalid (signature or trust root)"
    if not witness_verifier.verify_head(parsed.witness_attestation):
        return False, "checkpoint witness record invalid (signature or trust root)"
    payload = checkpoint_payload(
        seq=parsed.seq,
        record_hash=parsed.record_hash,
        attestation_hash=parsed.attestation_hash,
        witness_record_hash=parsed.witness_record_hash,
    )
    if not countersign_verifier.verify_countersignature(payload, parsed.countersignature):
        return False, "checkpoint countersignature invalid (signature or trust root)"

    chain = (
        _chain
        if _chain is not None
        else _walk_ledger(Path(ledger_path).expanduser(), want_seq=parsed.seq)
    )
    if not chain.ok:
        return False, f"ledger invalid: {chain.error}"
    if chain.count < parsed.seq:
        return (
            False,
            f"ledger truncated: head seq {chain.count} is behind the checkpoint seq {parsed.seq}",
        )
    if chain.hash_at != parsed.record_hash:
        return (
            False,
            f"rollback: the record at seq {parsed.seq} is not the checkpointed record",
        )
    return True, None
