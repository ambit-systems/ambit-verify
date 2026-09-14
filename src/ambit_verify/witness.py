# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Checking a ledger against the head an independent witness recorded.

A witness keeps its own ledger of ``head_witness`` records, each naming a
ledger id and the head the witness saw for it. This module reads that ledger
under a witness key and compares the named ledger's actual head against what
the witness attested: a head below the witnessed seq is a rollback, a head
above it is a stale witness, and conflicting witness records at the same seq
are an equivocation.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .head_attestation import HeadAttestation, HeadVerifier
from .head_attestation_checks import _attest_path, _attestation_from_block, _verify_head_attestation
from .verify import _Chain, _walk_ledger


def _walk_witness_ledger(
    witness_path: Path,
    verifier: HeadVerifier,
    witnessed_ledger_id: str,
) -> tuple[_Chain, HeadAttestation | None, int | None]:
    best: HeadAttestation | None = None
    equivocation_seq: int | None = None

    def inspect(record: dict[str, Any]) -> None:
        nonlocal best, equivocation_seq
        if record.get("record_type") != "head_witness":
            return
        if record.get("witnessed_ledger_id") != witnessed_ledger_id:
            return
        block = record.get("attestation")
        if not isinstance(block, Mapping):
            return
        attestation = _attestation_from_block(block)
        if (
            attestation is None
            or attestation.ledger_id != witnessed_ledger_id
            or not verifier.verify_head(attestation)
        ):
            return
        if best is None or attestation.max_seq > best.max_seq:
            best = attestation
            equivocation_seq = None
        elif (
            attestation.max_seq == best.max_seq
            and attestation.head_record_hash != best.head_record_hash
        ):
            equivocation_seq = attestation.max_seq

    chain = _walk_ledger(witness_path, record_visitor=inspect)
    return chain, best, equivocation_seq


def verify_witnessed_head(
    ledger_path: str | Path,
    witness_ledger_path: str | Path,
    verifier: HeadVerifier,
    *,
    witnessed_ledger_id: str,
    witness_ledger_attestation: HeadAttestation | None = None,
    _chain: _Chain | None = None,
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
    resolved_ledger = Path(ledger_path).expanduser()
    witness_path = Path(witness_ledger_path).expanduser()

    if not isinstance(witnessed_ledger_id, str) or not witnessed_ledger_id:
        return False, "witnessed_ledger_id must be non-empty"

    witness_chain, witnessed, equivocation_seq = _walk_witness_ledger(
        witness_path, verifier, witnessed_ledger_id
    )
    if not witness_chain.ok:
        return False, f"witness ledger invalid: {witness_chain.error}"
    head_ok, head_error = _verify_head_attestation(
        _attest_path(witness_path),
        witness_chain,
        verifier,
        witness_ledger_attestation,
    )
    if not head_ok:
        return False, f"witness ledger invalid: {head_error}"
    if equivocation_seq is not None:
        return False, f"witness equivocation at seq {equivocation_seq}"
    if witnessed is None:
        return False, f"no valid head witness found for {witnessed_ledger_id}"

    chain = _chain if _chain is not None else _walk_ledger(resolved_ledger)
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
