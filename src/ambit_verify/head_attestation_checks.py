# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Reading a head attestation and checking it against a walked chain.

``head_attestation.py`` defines what a head attestation is and how its
signature is verified. This module reads one from disk (a ``.attest``
sidecar or a retained copy) and checks it against the head of a chain that
``verify.py`` has already walked: a head behind the attested seq fails as
truncated, a head ahead of it fails as stale, and a head at the attested seq
with another hash fails as a forgery.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .hashing import strict_json_loads
from .head_attestation import ATTESTATION_BLOCK_KEYS, HeadAttestation, HeadVerifier
from .verify import _Chain, _InputLimitError, _is_digest, _read_utf8_document, _walk_ledger

_ATTESTATION_REQUIRED_KEYS = frozenset(
    {"max_seq", "head_record_hash", "recorded_at", "trust_root_id", "signature"}
)
_ATTESTATION_KEYS = _ATTESTATION_REQUIRED_KEYS | {"ledger_id"}


def _attest_path(ledger_path: Path) -> Path:
    """Return the path of the ``.attest`` sidecar beside *ledger_path*."""
    return ledger_path.with_suffix(".attest")


def _attestation_is_well_formed(attestation: HeadAttestation, *, require_ledger_id: bool) -> bool:
    return (
        isinstance(attestation.max_seq, int)
        and not isinstance(attestation.max_seq, bool)
        and attestation.max_seq >= 0
        and _is_digest(attestation.head_record_hash)
        and isinstance(attestation.recorded_at, str)
        and bool(attestation.recorded_at)
        and isinstance(attestation.trust_root_id, str)
        and bool(attestation.trust_root_id)
        and isinstance(attestation.signature, str)
        and bool(attestation.signature)
        and (
            (isinstance(attestation.ledger_id, str) and bool(attestation.ledger_id))
            if require_ledger_id
            else (
                attestation.ledger_id is None
                or (isinstance(attestation.ledger_id, str) and bool(attestation.ledger_id))
            )
        )
    )


def _attestation_from_mapping(
    data: Mapping[str, Any], *, require_ledger_id: bool
) -> HeadAttestation | None:
    keys = set(data)
    expected = ATTESTATION_BLOCK_KEYS if require_ledger_id else _ATTESTATION_KEYS
    required = ATTESTATION_BLOCK_KEYS if require_ledger_id else _ATTESTATION_REQUIRED_KEYS
    if keys - expected or not required <= keys:
        return None
    max_seq: object = data.get("max_seq")
    head_record_hash: object = data.get("head_record_hash")
    recorded_at: object = data.get("recorded_at")
    trust_root_id: object = data.get("trust_root_id")
    signature: object = data.get("signature")
    ledger_id: object = data.get("ledger_id")
    if (
        not isinstance(max_seq, int)
        or isinstance(max_seq, bool)
        or max_seq < 0
        or not _is_digest(head_record_hash)
        or not isinstance(recorded_at, str)
        or not recorded_at
        or not isinstance(trust_root_id, str)
        or not trust_root_id
        or not isinstance(signature, str)
        or not signature
    ):
        return None
    parsed_ledger_id: str | None
    if isinstance(ledger_id, str) and ledger_id:
        parsed_ledger_id = ledger_id
    elif ledger_id is None and not require_ledger_id:
        parsed_ledger_id = None
    else:
        return None
    return HeadAttestation(
        max_seq=max_seq,
        head_record_hash=head_record_hash,
        recorded_at=recorded_at,
        trust_root_id=trust_root_id,
        signature=signature,
        ledger_id=parsed_ledger_id,
    )


def _attestation_from_block(block: Mapping[str, Any]) -> HeadAttestation | None:
    """Rebuild a ``HeadAttestation`` from an exact six-key attestation block."""
    return _attestation_from_mapping(block, require_ledger_id=True)


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
    resolved = Path(path).expanduser()
    try:
        text = _read_utf8_document(resolved)
    except FileNotFoundError:
        return None
    except UnicodeDecodeError, _InputLimitError:
        return None
    try:
        data = strict_json_loads(text)
    except ValueError, RecursionError:
        return None
    if not isinstance(data, Mapping):
        return None
    return _attestation_from_mapping(data, require_ledger_id=False)


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
    return read_attestation_file(_attest_path(Path(ledger_path).expanduser()))


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
    if not _attestation_is_well_formed(attestation, require_ledger_id=False):
        return False, "head attestation malformed"
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
    _chain: _Chain | None = None,
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
    ledger_path = Path(path).expanduser()
    if attestation is not None and verifier is None:
        return False, 0, "head verifier required when attestation is supplied"
    chain = _chain if _chain is not None else _walk_ledger(ledger_path)
    if not chain.ok:
        return False, chain.count, chain.error
    if verifier is not None:
        head_ok, head_error = _verify_head_attestation(
            _attest_path(ledger_path), chain, verifier, attestation
        )
        if not head_ok:
            return False, chain.count, head_error
    return True, chain.count, None
