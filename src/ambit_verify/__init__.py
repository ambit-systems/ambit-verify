# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Standalone verifier for Ambit hash-chained evidence ledgers.

Reads a JSONL ledger and checks every record hash and the chain between
records. With a public key it also checks the head attestation, a witness
ledger, or a countersigned checkpoint. Nothing here writes a ledger or signs
one.

Three parties appear in the checks:

- The writer appends records and attests the ledger head with its key. In an
  Ambit deployment this is the Authority plane.
- The witness records, in a ledger of its own, the heads it saw and attests
  that ledger with a second key. In an Ambit deployment this is the
  Observatory plane.
- The holder keeps a checkpoint (one head, the writer's attestation, the
  witness record) countersigned with a third key that neither of the other
  parties holds.

The Ed25519 verifiers hold public keys only. ``HmacHeadVerifier`` holds the
shared secret a reference deployment attests with; that secret can also sign,
so a pass under it proves nothing against the writer.
"""

from __future__ import annotations

from .hashing import canonical_json_bytes, hash_object
from .head_attestation import (
    CheckpointVerifier,
    HeadAttestation,
    HeadVerifier,
    HmacHeadVerifier,
    attestation_block,
    attestation_payload,
    checkpoint_payload,
)
from .head_attestation_ed25519 import Ed25519CountersignVerifier, Ed25519HeadVerifier
from .verify import (
    GENESIS_HASH,
    LedgerReadError,
    ledger_files,
    read_attestation,
    read_attestation_file,
    read_head,
    verify_chain,
    verify_checkpoint,
    verify_witnessed_head,
)

__version__ = "0.1.0"

__all__ = [
    "GENESIS_HASH",
    "CheckpointVerifier",
    "Ed25519CountersignVerifier",
    "Ed25519HeadVerifier",
    "HeadAttestation",
    "HeadVerifier",
    "HmacHeadVerifier",
    "LedgerReadError",
    "__version__",
    "attestation_block",
    "attestation_payload",
    "canonical_json_bytes",
    "checkpoint_payload",
    "hash_object",
    "ledger_files",
    "read_attestation",
    "read_attestation_file",
    "read_head",
    "verify_chain",
    "verify_checkpoint",
    "verify_witnessed_head",
]
