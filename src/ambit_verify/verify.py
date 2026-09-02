# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Chain, head-attestation, witness, and checkpoint verification.

A ledger is a JSONL file. Each line is one JSON object with at least ``seq``
(1-based, contiguous), ``prev_hash`` (the ``record_hash`` of the previous
record, or ``GENESIS_HASH`` for ``seq`` 1) and ``record_hash`` (SHA-256 over
the canonical JSON of every other key). The verifier reads those three keys
and nothing else: record vocabulary is the writer's contract.

Rotated segments ``<stem>.<n>.jsonl`` beside the ledger are read in ascending
``n`` before the active file, so one chain can span many files. Every check
reads the full chain; no head file is trusted.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
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

GENESIS_HASH = "0" * 64

# A checkpoint carries exactly these five fields. Nothing else is signed, so
# nothing else is admitted.
_CHECKPOINT_KEYS = frozenset(
    {"seq", "record_hash", "attestation", "witness_record", "countersignature"}
)
_HEX_DIGITS = frozenset("0123456789abcdef")


class LedgerReadError(RuntimeError):
    """Raised by ``read_head`` when the ledger is empty or its chain is invalid."""


@dataclass(frozen=True)
class _Chain:
    """Result of one walk over a ledger's files.

    Attributes:
        ok: True when every record verified.
        count: Records verified before the walk stopped.
        error: The first failure, or None.
        head_hash: ``record_hash`` of the last verified record, or
            ``GENESIS_HASH`` when none verified.
        hash_at: ``record_hash`` of the record at the requested seq, or None
            when the walk did not reach it.
    """

    ok: bool
    count: int
    error: str | None
    head_hash: str
    hash_at: str | None


def ledger_files(ledger_path: str | Path) -> list[Path]:
    """Return the files that make up one ledger, in chain order.

    A writer rotates a ledger into segments named ``<stem>.<n><suffix>`` beside
    the active file. The chain runs through the segments in ascending ``n``
    and ends in the active file.

    Args:
        ledger_path: The active ledger file.

    Returns:
        The segment paths in ascending ``n``, then *ledger_path*.
    """
    ledger_path = Path(ledger_path)
    stem = ledger_path.stem
    suffix = ledger_path.suffix
    segments: list[tuple[int, Path]] = []
    for candidate in ledger_path.parent.iterdir():
        if candidate == ledger_path:
            continue
        name = candidate.name
        if not name.startswith(stem + ".") or not name.endswith(suffix):
            continue
        middle = name[len(stem) + 1 : len(name) - len(suffix)]
        if middle.isdigit():
            segments.append((int(middle), candidate))
    return [path for _, path in sorted(segments)] + [ledger_path]


class _NotUtf8Error(Exception):
    """A ledger file is not UTF-8. ``path`` names it."""

    def __init__(self, path: Path) -> None:
        super().__init__(str(path))
        self.path = path


def _lines(files: list[Path]) -> Iterator[tuple[Path, int, str]]:
    """Yield ``(file, line_no, text)`` for every non-blank line in *files*.

    Raises:
        _NotUtf8Error: If a file is not UTF-8.
    """
    for file_path in files:
        try:
            with file_path.open("r", encoding="utf-8") as handle:
                for line_no, line in enumerate(handle, start=1):
                    text = line.strip()
                    if text:
                        yield file_path, line_no, text
        except UnicodeDecodeError:
            raise _NotUtf8Error(file_path) from None


def _walk_chain(files: list[Path], want_seq: int = 0) -> _Chain:
    """Verify every record in *files* in order and collect the head."""
    count = 0
    prev_hash = GENESIS_HASH
    hash_at: str | None = None

    try:
        for file_path, line_no, text in _lines(files):
            where = f"{file_path.name}:{line_no}"
            result = _check_record(text, count, prev_hash, where)
            if result.error is not None:
                return _Chain(False, count, result.error, prev_hash, hash_at)
            prev_hash = result.record_hash
            count += 1
            if count == want_seq:
                hash_at = result.record_hash
    except _NotUtf8Error as exc:
        return _Chain(False, count, f"{exc.path.name}: file is not UTF-8", prev_hash, hash_at)
    return _Chain(True, count, None, prev_hash, hash_at)


@dataclass(frozen=True)
class _Checked:
    """One record's check: its hash, or the reason it failed."""

    record_hash: str
    error: str | None


def _check_record(text: str, count: int, prev_hash: str, where: str) -> _Checked:
    """Check one record line against the chain state."""

    def fail(reason: str) -> _Checked:
        return _Checked("", f"{where}: {reason}")

    try:
        record = json.loads(text)
    except json.JSONDecodeError as exc:
        return fail(f"invalid JSON ({exc})")
    if not isinstance(record, dict):
        return fail("record is not an object")
    seq = record.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq != count + 1:
        return fail(f"unexpected seq {seq}, expected {count + 1}")
    if record.get("prev_hash") != prev_hash:
        return fail("prev_hash mismatch")
    record_hash = record.get("record_hash")
    if not isinstance(record_hash, str) or len(record_hash) != 64:
        return fail("missing/invalid record_hash")
    unsigned = {key: value for key, value in record.items() if key != "record_hash"}
    if hash_object(unsigned) != record_hash:
        return fail("record_hash mismatch")
    return _Checked(record_hash, None)


def _walk_ledger(ledger_path: Path, want_seq: int = 0) -> _Chain:
    """Verify the chain at *ledger_path* (segments first), or explain why not."""
    if not ledger_path.exists():
        return _Chain(False, 0, "ledger file does not exist", GENESIS_HASH, None)
    if not ledger_path.is_file():
        return _Chain(False, 0, "ledger path is not a file", GENESIS_HASH, None)
    return _walk_chain(ledger_files(ledger_path), want_seq)


def _attest_path(ledger_path: Path) -> Path:
    """Return the path of the ``.attest`` sidecar beside *ledger_path*."""
    return ledger_path.with_suffix(".attest")


def read_attestation_file(path: str | Path) -> HeadAttestation | None:
    """Read a head attestation from *path*.

    Reading is not verifying: pass the result to a ``HeadVerifier`` before
    relying on it.

    Args:
        path: A ``.attest`` sidecar or a retained copy of one.

    Returns:
        The attestation, or None when the file is absent, is not JSON, or does
        not carry the attestation fields with the expected types.

    Raises:
        OSError: If the file exists but cannot be read.
    """
    try:
        text = Path(path).expanduser().read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except UnicodeDecodeError:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    max_seq = data.get("max_seq")
    head_record_hash = data.get("head_record_hash")
    recorded_at = data.get("recorded_at")
    trust_root_id = data.get("trust_root_id")
    signature = data.get("signature")
    ledger_id = data.get("ledger_id")
    if (
        not isinstance(max_seq, int)
        or isinstance(max_seq, bool)
        or not isinstance(head_record_hash, str)
        or not isinstance(recorded_at, str)
        or not isinstance(trust_root_id, str)
        or not trust_root_id
        or not isinstance(signature, str)
    ):
        return None
    if ledger_id is not None and (not isinstance(ledger_id, str) or not ledger_id):
        return None
    return HeadAttestation(
        max_seq=max_seq,
        head_record_hash=head_record_hash,
        recorded_at=recorded_at,
        trust_root_id=trust_root_id,
        signature=signature,
        ledger_id=ledger_id,
    )


def read_attestation(ledger_path: str | Path) -> HeadAttestation | None:
    """Read the ``.attest`` sidecar beside *ledger_path*.

    Args:
        ledger_path: The ledger whose sidecar to read.

    Returns:
        The attestation, or None when the sidecar is absent or malformed. See
        ``read_attestation_file``.

    Raises:
        OSError: If the sidecar exists but cannot be read.
    """
    return read_attestation_file(_attest_path(Path(ledger_path).expanduser().resolve()))


def _verify_head_attestation(
    attest_path: Path,
    chain: _Chain,
    verifier: HeadVerifier,
    attestation: HeadAttestation | None,
) -> tuple[bool, str | None]:
    """Check a verified chain head against its attestation."""
    if attestation is None:
        attestation = read_attestation_file(attest_path)
    if attestation is None:
        return False, "head attestation missing"
    if not verifier.verify_head(attestation):
        return False, "head attestation invalid (signature or trust root)"
    if chain.count < attestation.max_seq:
        return (
            False,
            f"ledger truncated: attested head seq {attestation.max_seq} is beyond "
            f"the current head (seq {chain.count})",
        )
    if chain.count > attestation.max_seq:
        return (
            False,
            f"head attestation stale: attested head seq {attestation.max_seq} is behind "
            f"the current head (seq {chain.count})",
        )
    if chain.head_hash != attestation.head_record_hash:
        if attestation.max_seq == 0:
            return False, "head attestation of an empty ledger does not name the genesis hash"
        return (
            False,
            f"head forgery: record at seq {attestation.max_seq} does not match "
            "the attested head hash",
        )
    return True, None


def verify_chain(
    path: str | Path,
    *,
    verifier: HeadVerifier | None = None,
    attestation: HeadAttestation | None = None,
) -> tuple[bool, int, str | None]:
    """Verify the hash chain, and with *verifier* the head attestation too.

    The chain check proves that no record changed, was removed from the
    middle, or was reordered, and that ``seq`` runs from 1 without a gap. It
    does not prove the tail is complete. With *verifier*, the head must also
    match a valid attestation: a head behind the attested seq fails as
    truncated, a head ahead of it fails as stale, a head at the attested seq
    with another hash fails as a forgery, and a missing attestation fails.

    Args:
        path: The active ledger file. Rotated segments beside it are read
            first.
        verifier: Verifier for the head attestation. None runs the bare chain
            check only.
        attestation: A caller-held attestation to check against instead of the
            ``.attest`` sidecar. Requires *verifier*.

    Returns:
        ``(ok, count, error)``: whether every check passed, the number of
        records verified, and the first failure or None.

    Raises:
        OSError: If a ledger file or the sidecar cannot be read.
    """
    ledger_path = Path(path).expanduser().resolve()
    if attestation is not None and verifier is None:
        return False, 0, "head verifier required when attestation is supplied"
    chain = _walk_ledger(ledger_path)
    if not chain.ok:
        return False, chain.count, chain.error
    if verifier is not None:
        head_ok, head_error = _verify_head_attestation(
            _attest_path(ledger_path), chain, verifier, attestation
        )
        if not head_ok:
            return False, chain.count, head_error
    return True, chain.count, None


def read_head(path: str | Path) -> tuple[int, str]:
    """Verify the chain and return its head.

    Args:
        path: The active ledger file.

    Returns:
        ``(max_seq, head_record_hash)`` of the last record.

    Raises:
        LedgerReadError: If the chain is invalid or the ledger is empty.
        OSError: If a ledger file cannot be read.
    """
    chain = _walk_ledger(Path(path).expanduser().resolve())
    if not chain.ok:
        raise LedgerReadError(f"cannot read head of invalid ledger: {chain.error}")
    if chain.count == 0:
        raise LedgerReadError("cannot read head of empty ledger")
    return chain.count, chain.head_hash


def _attestation_from_block(block: Mapping[str, Any]) -> HeadAttestation | None:
    """Rebuild a ``HeadAttestation`` from a six-key attestation block."""
    max_seq = block.get("max_seq")
    head_record_hash = block.get("head_record_hash")
    ledger_id = block.get("ledger_id")
    recorded_at = block.get("recorded_at")
    trust_root_id = block.get("trust_root_id")
    signature = block.get("signature")
    if (
        not isinstance(max_seq, int)
        or isinstance(max_seq, bool)
        or not isinstance(head_record_hash, str)
        or not isinstance(ledger_id, str)
        or not ledger_id
        or not isinstance(recorded_at, str)
        or not isinstance(trust_root_id, str)
        or not isinstance(signature, str)
    ):
        return None
    return HeadAttestation(
        max_seq=max_seq,
        head_record_hash=head_record_hash,
        recorded_at=recorded_at,
        trust_root_id=trust_root_id,
        signature=signature,
        ledger_id=ledger_id,
    )


def _latest_valid_witness(
    witness_ledger_path: Path, verifier: HeadVerifier, witnessed_ledger_id: str
) -> HeadAttestation | None:
    """Return the highest-seq witness attestation whose signature verifies."""
    best: HeadAttestation | None = None
    for _, _, text in _lines(ledger_files(witness_ledger_path)):
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict) or record.get("record_type") != "head_witness":
            continue
        if record.get("witnessed_ledger_id") != witnessed_ledger_id:
            continue
        block = record.get("attestation")
        if not isinstance(block, dict):
            continue
        attestation = _attestation_from_block(block)
        if (
            attestation is None
            or attestation.ledger_id != witnessed_ledger_id
            or not verifier.verify_head(attestation)
        ):
            continue
        if best is None or attestation.max_seq > best.max_seq:
            best = attestation
    return best


def verify_witnessed_head(
    ledger_path: str | Path,
    witness_ledger_path: str | Path,
    verifier: HeadVerifier,
    *,
    witnessed_ledger_id: str,
    witness_ledger_attestation: HeadAttestation | None = None,
) -> tuple[bool, str | None]:
    """Check a ledger against the head an independent witness recorded.

    A witness keeps its own ledger of ``head_witness`` records. Each one
    carries an attestation block that names a ledger (``ledger_id``) and the
    head the witness saw. This check first verifies the witness ledger under
    *verifier*, then takes the highest-seq witness record for
    *witnessed_ledger_id* whose signature verifies, and requires the ledger to
    verify and to sit exactly at that head. A head below the witnessed seq
    fails as a rollback, even when the ledger's own sidecar was rolled back
    with it. A head above it fails as a stale witness until the new head is
    witnessed.

    Args:
        ledger_path: The ledger whose head was witnessed.
        witness_ledger_path: The witness ledger.
        verifier: Verifier for the witness key. It checks the witness ledger's
            own head attestation and every witness record.
        witnessed_ledger_id: The ``ledger_id`` the witness records must name.
        witness_ledger_attestation: A caller-held head attestation for the
            witness ledger, checked instead of its ``.attest`` sidecar.

    Returns:
        ``(ok, error)``: whether the check passed, and the first failure or
        None.

    Raises:
        OSError: If a ledger file or a sidecar cannot be read.
    """
    resolved_ledger = Path(ledger_path).expanduser().resolve()
    witness_path = Path(witness_ledger_path).expanduser().resolve()

    if not witnessed_ledger_id:
        return False, "witnessed_ledger_id must be non-empty"

    witness_ok, _, witness_error = verify_chain(
        witness_path,
        verifier=verifier,
        attestation=witness_ledger_attestation,
    )
    if not witness_ok:
        return False, f"witness ledger invalid: {witness_error}"

    witnessed = _latest_valid_witness(witness_path, verifier, witnessed_ledger_id)
    if witnessed is None:
        return False, f"no valid head witness found for {witnessed_ledger_id}"

    chain = _walk_ledger(resolved_ledger)
    if not chain.ok:
        return False, f"witnessed ledger invalid: {chain.error}"
    if chain.count < witnessed.max_seq:
        return (
            False,
            f"rollback: head seq {chain.count} is behind witnessed seq {witnessed.max_seq}",
        )
    if chain.count > witnessed.max_seq:
        return (
            False,
            f"stale witness: current head seq {chain.count} is ahead of witnessed seq "
            f"{witnessed.max_seq}",
        )
    if chain.head_hash != witnessed.head_record_hash:
        return (
            False,
            f"head forgery: record at witnessed seq {witnessed.max_seq} does not "
            "match the witnessed head hash",
        )
    return True, None


def _is_digest(value: object) -> TypeGuard[str]:
    """Return True when *value* is 64 lower-case hexadecimal characters."""
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX_DIGITS


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
    attestation = _attestation_from_block(block)
    if attestation is None:
        return None, "checkpoint attestation is malformed"

    record = checkpoint["witness_record"]
    if not isinstance(record, Mapping):
        return None, "checkpoint witness_record must be an object"
    if record.get("record_type") != "head_witness":
        return None, "checkpoint witness_record is not a head_witness record"
    stored_hash = record.get("record_hash")
    if not _is_digest(stored_hash):
        return None, "checkpoint witness_record carries no record hash"
    # The record hash covers every other field the witness record carries, so
    # recomputing it here is what binds the witness attestation, the witnessed
    # ledger id, and anything a witness added beside them.
    unsigned = {key: value for key, value in record.items() if key != "record_hash"}
    if hash_object(unsigned) != stored_hash:
        return None, "checkpoint witness_record does not hash to its record_hash"
    witness_block = record.get("attestation")
    if not isinstance(witness_block, Mapping):
        return None, "checkpoint witness_record carries no attestation"
    witness_attestation = _attestation_from_block(witness_block)
    if witness_attestation is None:
        return None, "checkpoint witness attestation is malformed"
    if witness_attestation.ledger_id != record.get("witnessed_ledger_id"):
        return None, "checkpoint witness attestation names another ledger"

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
            witness_record_hash=stored_hash,
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
    parsed, error = _parse_checkpoint(checkpoint)
    if parsed is None:
        return False, error
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

    chain = _walk_ledger(Path(ledger_path).expanduser().resolve(), want_seq=parsed.seq)
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


__all__ = [
    "GENESIS_HASH",
    "LedgerReadError",
    "ledger_files",
    "read_attestation",
    "read_attestation_file",
    "read_head",
    "verify_chain",
    "verify_checkpoint",
    "verify_witnessed_head",
]
