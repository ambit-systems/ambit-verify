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

import errno
import math
import os
import stat
import unicodedata
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, TypeGuard

from .hashing import (
    MAX_JSON_NESTING,
    canonical_json_bytes,
    hash_object,
    strict_json_loads,
)
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
MAX_JSON_DOCUMENT_BYTES = 1024 * 1024
MAX_LEDGER_LINE_BYTES = 16 * 1024 * 1024
MAX_LEDGER_BYTES = 1024 * 1024 * 1024
MAX_LEDGER_PHYSICAL_LINES = 2_000_000
MAX_LEDGER_DIRECTORY_ENTRIES = 100_000
MAX_LEDGER_SEGMENTS = 10_000
MAX_LEDGER_RECORDS = 1_000_000
_DESCRIPTOR_ADMISSION_SUPPORTED = (
    hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY")
    and os.open in os.supports_dir_fd
    and os.scandir in os.supports_fd
)


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


def _segment_paths(ledger_path: Path, names: Iterator[str]) -> list[Path]:
    """Select rotation segments using the writer's ASCII-decimal grammar."""
    stem = ledger_path.stem
    suffix = ledger_path.suffix
    segments: list[tuple[int, Path]] = []
    entries_examined = 0
    for name in names:
        entries_examined += 1
        if entries_examined > MAX_LEDGER_DIRECTORY_ENTRIES:
            raise _InputLimitError(
                ledger_path,
                None,
                f"ledger directory exceeds {MAX_LEDGER_DIRECTORY_ENTRIES} entry limit",
            )
        if name == ledger_path.name:
            continue
        if not name.startswith(stem + ".") or not name.endswith(suffix):
            continue
        middle = name[len(stem) + 1 : -len(suffix)] if suffix else name[len(stem) + 1 :]
        if not middle or any(character < "0" or character > "9" for character in middle):
            continue
        if len(segments) >= MAX_LEDGER_SEGMENTS:
            raise _InputLimitError(
                ledger_path,
                None,
                f"ledger exceeds {MAX_LEDGER_SEGMENTS} segment limit",
            )
        segments.append((int(middle), ledger_path.parent / name))
    return [path for _, path in sorted(segments)] + [ledger_path]


def _descriptor_segment_paths(ledger_path: Path, directory_fd: int) -> list[Path]:
    """Discover ledger segments by streaming one admitted directory descriptor."""
    with os.scandir(directory_fd) as entries:
        return _segment_paths(ledger_path, (entry.name for entry in entries))


def ledger_files(ledger_path: str | Path) -> list[Path]:
    """Return ASCII-numbered rotation segments, then the active ledger."""
    path = Path(ledger_path).expanduser()
    with _open_directory(path.parent, path) as directory_fd:
        return _descriptor_segment_paths(path, directory_fd)


class _NotUtf8Error(Exception):
    """A ledger file is not UTF-8. ``path`` names it."""

    def __init__(self, path: Path) -> None:
        super().__init__(str(path))
        self.path = path


class _InputLimitError(Exception):
    """An input exceeded a verifier resource boundary."""

    def __init__(self, path: Path, line_no: int | None, reason: str) -> None:
        super().__init__(reason)
        self.path = path
        self.line_no = line_no
        self.reason = reason


def _terminal_safe(value: object) -> str:
    """Escape terminal controls, format characters, and surrogate code points."""
    text = str(value)
    return "".join(
        character
        if not unicodedata.category(character).startswith("C")
        else character.encode("unicode_escape").decode("ascii")
        for character in text
    )


def _require_descriptor_admission() -> None:
    if not _DESCRIPTOR_ADMISSION_SUPPORTED:
        raise OSError(
            errno.ENOTSUP,
            "secure no-follow filesystem admission is unavailable",
        )


@contextmanager
def _open_directory(path: Path, error_path: Path) -> Iterator[int]:
    """Open a lexical directory path without following any symlink component."""
    _require_descriptor_admission()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(os.sep if path.is_absolute() else ".", flags)
    try:
        for component in path.parts:
            if component in ("", ".", os.sep):
                continue
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise _InputLimitError(
                        error_path,
                        None,
                        "ledger directory contains a symbolic link or is not a directory",
                    ) from None
                raise
            os.close(descriptor)
            descriptor = next_descriptor
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _open_regular_file(
    path: Path,
    *,
    directory_fd: int | None = None,
    not_regular_reason: str = "ledger component is not a regular file",
) -> Iterator[BinaryIO]:
    """Open *path* once without following links or blocking on special files."""
    _require_descriptor_admission()
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    target: str | Path = path.name if directory_fd is not None else path
    try:
        descriptor = os.open(target, flags, dir_fd=directory_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise _InputLimitError(path, None, "ledger component is not a regular file") from None
        raise
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _InputLimitError(path, None, not_regular_reason)
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            yield handle
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_utf8_document(path: Path) -> str:
    lexical_path = path.expanduser()
    with (
        _open_directory(lexical_path.parent, lexical_path) as directory_fd,
        _open_regular_file(lexical_path, directory_fd=directory_fd) as handle,
    ):
        raw = handle.read(MAX_JSON_DOCUMENT_BYTES + 1)
    if len(raw) > MAX_JSON_DOCUMENT_BYTES:
        raise _InputLimitError(
            lexical_path, None, f"file exceeds {MAX_JSON_DOCUMENT_BYTES} byte limit"
        )
    return raw.decode("utf-8")


def _lines(
    files: list[Path],
    *,
    directory_fd: int | None = None,
    active_path: Path | None = None,
    active_handle: BinaryIO | None = None,
) -> Iterator[tuple[Path, int, str]]:
    """Yield bounded UTF-8 lines, opening each ledger component exactly once."""
    total_bytes = 0
    physical_lines = 0
    for file_path in files:
        try:
            handle_context = (
                nullcontext(active_handle)
                if active_handle is not None and file_path == active_path
                else _open_regular_file(file_path, directory_fd=directory_fd)
            )
            with handle_context as handle:
                line_no = 0
                while raw := handle.readline(MAX_LEDGER_LINE_BYTES + 1):
                    line_no += 1
                    physical_lines += 1
                    total_bytes += len(raw)
                    if len(raw) > MAX_LEDGER_LINE_BYTES:
                        raise _InputLimitError(
                            file_path,
                            line_no,
                            f"line exceeds {MAX_LEDGER_LINE_BYTES} byte limit",
                        )
                    if total_bytes > MAX_LEDGER_BYTES:
                        raise _InputLimitError(
                            file_path,
                            line_no,
                            f"ledger input exceeds {MAX_LEDGER_BYTES} byte limit",
                        )
                    if physical_lines > MAX_LEDGER_PHYSICAL_LINES:
                        raise _InputLimitError(
                            file_path,
                            line_no,
                            f"ledger exceeds {MAX_LEDGER_PHYSICAL_LINES} physical line limit",
                        )
                    stripped = raw.strip()
                    if stripped:
                        yield file_path, line_no, stripped.decode("utf-8")
        except UnicodeDecodeError:
            raise _NotUtf8Error(file_path) from None


def _walk_chain(
    files: list[Path],
    want_seq: int = 0,
    record_visitor: Callable[[dict[str, Any]], None] | None = None,
    *,
    directory_fd: int | None = None,
    active_path: Path | None = None,
    active_handle: BinaryIO | None = None,
) -> _Chain:
    """Verify every record in *files* in order and collect the head."""
    count = 0
    prev_hash = GENESIS_HASH
    hash_at: str | None = None

    try:
        for file_path, line_no, text in _lines(
            files,
            directory_fd=directory_fd,
            active_path=active_path,
            active_handle=active_handle,
        ):
            where = f"{_terminal_safe(file_path.name)}:{line_no}"
            if count >= MAX_LEDGER_RECORDS:
                return _Chain(
                    False,
                    count,
                    f"{where}: ledger exceeds {MAX_LEDGER_RECORDS} record limit",
                    prev_hash,
                    hash_at,
                )
            result = _check_record(text, count, prev_hash, where)
            if result.error is not None:
                return _Chain(False, count, result.error, prev_hash, hash_at)
            if result.record is None:
                return _Chain(
                    False,
                    count,
                    f"{where}: verified record unavailable",
                    prev_hash,
                    hash_at,
                )
            if record_visitor is not None:
                record_visitor(result.record)
            prev_hash = result.record_hash
            count += 1
            if count == want_seq:
                hash_at = result.record_hash
    except _NotUtf8Error as exc:
        return _Chain(
            False,
            count,
            f"{_terminal_safe(exc.path.name)}: file is not UTF-8",
            prev_hash,
            hash_at,
        )
    except _InputLimitError as exc:
        name = _terminal_safe(exc.path.name)
        where = name if exc.line_no is None else f"{name}:{exc.line_no}"
        return _Chain(False, count, f"{where}: {exc.reason}", prev_hash, hash_at)
    return _Chain(True, count, None, prev_hash, hash_at)


@dataclass(frozen=True)
class _Checked:
    """One record's check: its hash and parsed object, or the reason it failed."""

    record_hash: str
    error: str | None
    record: dict[str, Any] | None


def _check_record(text: str, count: int, prev_hash: str, where: str) -> _Checked:
    """Check one record line against the chain state."""

    def fail(reason: str) -> _Checked:
        return _Checked("", f"{where}: {reason}", None)

    try:
        record = strict_json_loads(text)
    except (ValueError, RecursionError) as exc:
        return fail(f"invalid JSON ({_terminal_safe(exc)})")
    if not isinstance(record, dict):
        return fail("record is not an object")
    seq = record.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq != count + 1:
        return fail(f"unexpected seq {_terminal_safe(seq)}, expected {count + 1}")
    if record.get("prev_hash") != prev_hash:
        return fail("prev_hash mismatch")
    record_hash = record.get("record_hash")
    if not _is_digest(record_hash):
        return fail("missing/invalid record_hash")
    unsigned = {key: value for key, value in record.items() if key != "record_hash"}
    if hash_object(unsigned) != record_hash:
        return fail("record_hash mismatch")
    return _Checked(record_hash, None, record)


def _walk_ledger(
    ledger_path: Path,
    want_seq: int = 0,
    record_visitor: Callable[[dict[str, Any]], None] | None = None,
) -> _Chain:
    """Verify one lexical ledger path through one directory descriptor."""
    lexical_path = ledger_path.expanduser()
    try:
        with (
            _open_directory(lexical_path.parent, lexical_path) as directory_fd,
            _open_regular_file(
                lexical_path,
                directory_fd=directory_fd,
                not_regular_reason="ledger path is not a file",
            ) as active_handle,
        ):
            files = _descriptor_segment_paths(lexical_path, directory_fd)
            return _walk_chain(
                files,
                want_seq,
                record_visitor,
                directory_fd=directory_fd,
                active_path=lexical_path,
                active_handle=active_handle,
            )
    except FileNotFoundError:
        return _Chain(False, 0, "ledger file does not exist", GENESIS_HASH, None)
    except _InputLimitError as exc:
        if exc.reason == "ledger path is not a file":
            error = exc.reason
        else:
            error = f"{_terminal_safe(exc.path.name)}: {exc.reason}"
        return _Chain(False, 0, error, GENESIS_HASH, None)


def read_verified_records(
    path: str | Path,
) -> tuple[bool, tuple[dict[str, Any], ...], str | None]:
    """Read all records only after validating their complete hash chain.

    The returned records come from the same parse used for hash validation,
    avoiding a second read in which the ledger could change between integrity
    checking and semantic inspection.

    Args:
        path: The active ledger file. Rotated segments beside it are read first.

    Returns:
        ``(ok, records, error)``. Callers must not interpret ``records`` unless
        ``ok`` is true.

    Raises:
        OSError: If a ledger file cannot be read.
    """
    ledger_path = Path(path).expanduser()
    records: list[dict[str, Any]] = []
    chain = _walk_ledger(ledger_path, record_visitor=records.append)
    if not chain.ok:
        return False, (), chain.error
    return True, tuple(records), None


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
    chain = _walk_ledger(Path(path).expanduser())
    if not chain.ok:
        raise LedgerReadError(f"cannot read head of invalid ledger: {chain.error}")
    if chain.count == 0:
        raise LedgerReadError("cannot read head of empty ledger")
    return chain.count, chain.head_hash


def _is_digest(value: object) -> TypeGuard[str]:
    """Return True when *value* is 64 lower-case hexadecimal characters."""
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX_DIGITS


def _is_non_empty_string(value: object) -> TypeGuard[str]:
    """Return True when *value* is a non-empty string."""
    return isinstance(value, str) and bool(value)


def _checkpoint_string_cost(value: str, maximum: int) -> int:
    """Return a bounded-input cost while rejecting unpaired surrogates."""
    cost = 2
    index = 0
    while index < len(value):
        codepoint = ord(value[index])
        if 0xD800 <= codepoint <= 0xDBFF:
            if index + 1 >= len(value) or not (0xDC00 <= ord(value[index + 1]) <= 0xDFFF):
                raise ValueError("checkpoint contains an unpaired surrogate")
            cost += 4
            index += 2
        elif 0xDC00 <= codepoint <= 0xDFFF:
            raise ValueError("checkpoint contains an unpaired surrogate")
        else:
            cost += len(value[index].encode("utf-8"))
            index += 1
        if cost > maximum:
            raise ValueError(f"checkpoint exceeds {MAX_JSON_DOCUMENT_BYTES} byte/value limit")
    return cost


def _project_checkpoint_value(
    value: object,
    *,
    depth: int,
    active: set[int],
    remaining: list[int],
) -> Any:
    """Copy one bounded value into the strict JSON-native checkpoint domain."""

    def consume(cost: int) -> None:
        remaining[0] -= cost
        if remaining[0] < 0:
            raise ValueError(f"checkpoint exceeds {MAX_JSON_DOCUMENT_BYTES} byte/value limit")

    consume(1)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value.bit_length() > remaining[0] * 4:
            raise ValueError(f"checkpoint exceeds {MAX_JSON_DOCUMENT_BYTES} byte/value limit")
        consume(len(str(value)))
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("checkpoint contains a non-finite number")
        consume(len(repr(value)))
        return value
    if isinstance(value, str):
        consume(_checkpoint_string_cost(value, remaining[0]))
        return value
    if not isinstance(value, (Mapping, list, tuple)):
        raise TypeError("checkpoint contains a non-JSON value")
    if depth >= MAX_JSON_NESTING:
        raise ValueError(f"checkpoint nesting exceeds {MAX_JSON_NESTING} levels")
    identity = id(value)
    if identity in active:
        raise ValueError("checkpoint contains a cycle")
    active.add(identity)
    try:
        if isinstance(value, Mapping):
            projected: dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("checkpoint object key is not a string")
                consume(_checkpoint_string_cost(key, remaining[0]))
                projected[key] = _project_checkpoint_value(
                    item,
                    depth=depth + 1,
                    active=active,
                    remaining=remaining,
                )
            return projected
        return [
            _project_checkpoint_value(
                item,
                depth=depth + 1,
                active=active,
                remaining=remaining,
            )
            for item in value
        ]
    finally:
        active.remove(identity)


def _checkpoint_snapshot(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    """Materialize one immutable, bounded JSON-native checkpoint snapshot."""
    projected = _project_checkpoint_value(
        checkpoint,
        depth=0,
        active=set(),
        remaining=[MAX_JSON_DOCUMENT_BYTES],
    )
    if not isinstance(projected, dict):
        raise TypeError("checkpoint is not an object")
    if len(canonical_json_bytes(projected)) > MAX_JSON_DOCUMENT_BYTES:
        raise ValueError(f"checkpoint exceeds {MAX_JSON_DOCUMENT_BYTES} byte limit")
    return projected


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
    if not _is_non_empty_string(block.get("ledger_id")):
        return None, "checkpoint attestation ledger_id must be a non-empty string"
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
    witnessed_ledger_id = record.get("witnessed_ledger_id")
    if not _is_non_empty_string(witnessed_ledger_id):
        return (
            None,
            "checkpoint witness_record witnessed_ledger_id must be a non-empty string",
        )
    if not _is_non_empty_string(witness_block.get("ledger_id")):
        return None, "checkpoint witness attestation ledger_id must be a non-empty string"
    witness_attestation = _attestation_from_block(witness_block)
    if witness_attestation is None:
        return None, "checkpoint witness attestation is malformed"
    if witness_attestation.ledger_id != witnessed_ledger_id:
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


# Placed after the primitives above, not at module top: head_attestation_checks
# and witness import them from this module, so this module can only import
# back once they exist. cli.py and ambit_verify/__init__.py resolve these
# names from here.
from .head_attestation_checks import (  # noqa: E402
    _attestation_from_block,
    read_attestation,
    read_attestation_file,
    verify_chain,
)
from .witness import verify_witnessed_head  # noqa: E402

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
