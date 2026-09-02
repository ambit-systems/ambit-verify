# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""``ambit-verify``: verify a ledger from the command line.

Exit codes: 0 when every requested check passes, 1 when a check fails,
2 for a usage or I/O problem. Stdout carries exactly one line:
``PASS count=N`` or ``FAIL: <reason>``.

Usage errors (bad flag combinations, keys that are not 32 hex bytes, empty
ids, named files that do not exist) are raised by the parser before any
verification runs.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .head_attestation import HeadAttestation, HeadVerifier
from .head_attestation_ed25519 import Ed25519CountersignVerifier, Ed25519HeadVerifier
from .verify import (
    read_attestation,
    read_attestation_file,
    verify_chain,
    verify_checkpoint,
    verify_witnessed_head,
)


class _CheckError(Exception):
    """One check failed. The message is the ``FAIL:`` reason."""


def _hex_key(value: str) -> bytes:
    try:
        key = bytes.fromhex(value)
    except ValueError:
        raise argparse.ArgumentTypeError("not hexadecimal") from None
    if len(key) != 32:
        raise argparse.ArgumentTypeError(f"must be 32 bytes ({len(key)} given)")
    return key


def _existing_file(value: str) -> Path:
    path = Path(value)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"file does not exist: {value}")
    return path


def _non_empty(value: str) -> str:
    if not value:
        raise argparse.ArgumentTypeError("must not be empty")
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ambit-verify",
        description=(
            "Verify an Ambit evidence ledger: every record hash, the chain between "
            "records, and optionally the head attestation, a witness ledger, or a "
            "countersigned checkpoint."
        ),
    )
    parser.add_argument("ledger", type=_existing_file, help="path to the ledger (JSONL)")
    parser.add_argument(
        "--attestation",
        type=_existing_file,
        metavar="PATH",
        help="head attestation to check (default: the .attest sidecar beside LEDGER)",
    )
    parser.add_argument(
        "--public-key",
        type=_hex_key,
        metavar="HEX",
        help="Ed25519 public key (32 bytes, hex) of the ledger's head attestor",
    )
    parser.add_argument(
        "--trust-root-id",
        type=_non_empty,
        metavar="ID",
        help="trust root id the head attestation must name (default: the id it carries)",
    )
    parser.add_argument(
        "--witness",
        type=_existing_file,
        metavar="PATH",
        help="witness ledger (JSONL) holding head_witness records for LEDGER",
    )
    parser.add_argument(
        "--witnessed-ledger-id",
        type=_non_empty,
        metavar="ID",
        help="ledger id the witness records name (required with --witness)",
    )
    parser.add_argument(
        "--witness-public-key",
        type=_hex_key,
        metavar="HEX",
        help="Ed25519 public key (32 bytes, hex) of the witness (with --witness or --checkpoint)",
    )
    parser.add_argument(
        "--witness-trust-root-id",
        type=_non_empty,
        metavar="ID",
        help="trust root id the witness attestations must name (default: the id they carry)",
    )
    parser.add_argument(
        "--checkpoint",
        type=_existing_file,
        metavar="PATH",
        help="countersigned checkpoint (JSON) to check LEDGER against",
    )
    parser.add_argument(
        "--countersign-public-key",
        type=_hex_key,
        metavar="HEX",
        help="Ed25519 public key (32 bytes, hex) of the checkpoint countersigner",
    )
    return parser


def _check_flags(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.attestation is not None and args.public_key is None:
        parser.error("--attestation requires --public-key")
    if args.trust_root_id is not None and args.public_key is None:
        parser.error("--trust-root-id requires --public-key")
    if args.witness is not None:
        if args.witnessed_ledger_id is None:
            parser.error("--witness requires --witnessed-ledger-id")
        if args.witness_public_key is None:
            parser.error("--witness requires --witness-public-key")
    if args.checkpoint is not None:
        if args.witness_public_key is None:
            parser.error("--checkpoint requires --witness-public-key")
        if args.countersign_public_key is None:
            parser.error("--checkpoint requires --countersign-public-key")
    if args.witness is None and args.checkpoint is None:
        if args.witness_public_key is not None:
            parser.error("--witness-public-key requires --witness or --checkpoint")
        if args.witness_trust_root_id is not None:
            parser.error("--witness-trust-root-id requires --witness or --checkpoint")
    if args.witness is None and args.witnessed_ledger_id is not None:
        parser.error("--witnessed-ledger-id requires --witness")
    if args.countersign_public_key is not None and args.checkpoint is None:
        parser.error("--countersign-public-key requires --checkpoint")


def _trust_root_of(block: object) -> str | None:
    if not isinstance(block, Mapping):
        return None
    trust_root_id = block.get("trust_root_id")
    return trust_root_id if isinstance(trust_root_id, str) and trust_root_id else None


def _head_check(args: argparse.Namespace) -> tuple[HeadVerifier, HeadAttestation]:
    """Return the verifier and attestation for the head check."""
    if args.attestation is not None:
        attestation = read_attestation_file(args.attestation)
        if attestation is None:
            raise _CheckError("head attestation malformed")
    else:
        attestation = read_attestation(args.ledger)
        if attestation is None:
            raise _CheckError("head attestation missing")
    trust_root_id = args.trust_root_id or attestation.trust_root_id
    return Ed25519HeadVerifier(public_key=args.public_key, trust_root_id=trust_root_id), attestation


def _witness_check(args: argparse.Namespace) -> None:
    """Run the witness check."""
    trust_root_id = args.witness_trust_root_id
    if trust_root_id is None:
        sidecar = read_attestation(args.witness)
        if sidecar is None:
            raise _CheckError("witness: witness ledger invalid: head attestation missing")
        trust_root_id = sidecar.trust_root_id
    verifier = Ed25519HeadVerifier(public_key=args.witness_public_key, trust_root_id=trust_root_id)
    ok, error = verify_witnessed_head(
        args.ledger,
        args.witness,
        verifier,
        witnessed_ledger_id=args.witnessed_ledger_id,
    )
    if not ok:
        raise _CheckError(f"witness: {error}")


def _checkpoint_check(args: argparse.Namespace) -> None:
    """Run the checkpoint check."""
    try:
        checkpoint: Any = json.loads(args.checkpoint.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        raise _CheckError("checkpoint: checkpoint file is not UTF-8") from None
    except json.JSONDecodeError as exc:
        raise _CheckError(f"checkpoint: checkpoint is not valid JSON ({exc})") from None
    if not isinstance(checkpoint, Mapping):
        raise _CheckError("checkpoint: checkpoint is not an object")

    witness_record = checkpoint.get("witness_record")
    witness_trust_root_id = args.witness_trust_root_id or _trust_root_of(
        witness_record.get("attestation") if isinstance(witness_record, Mapping) else None
    )
    if witness_trust_root_id is None:
        raise _CheckError("checkpoint: checkpoint witness attestation names no trust root")

    authority_verifier: HeadVerifier | None = None
    if args.public_key is not None:
        authority_trust_root_id = args.trust_root_id or _trust_root_of(
            checkpoint.get("attestation")
        )
        if authority_trust_root_id is None:
            raise _CheckError("checkpoint: checkpoint attestation names no trust root")
        authority_verifier = Ed25519HeadVerifier(
            public_key=args.public_key, trust_root_id=authority_trust_root_id
        )

    ok, error = verify_checkpoint(
        args.ledger,
        checkpoint,
        witness_verifier=Ed25519HeadVerifier(
            public_key=args.witness_public_key, trust_root_id=witness_trust_root_id
        ),
        countersign_verifier=Ed25519CountersignVerifier(public_key=args.countersign_public_key),
        authority_verifier=authority_verifier,
    )
    if not ok:
        raise _CheckError(f"checkpoint: {error}")


def _verify(args: argparse.Namespace) -> int:
    """Run every requested check in order and return the record count."""
    if args.public_key is not None:
        verifier, attestation = _head_check(args)
        ok, count, error = verify_chain(args.ledger, verifier=verifier, attestation=attestation)
    else:
        ok, count, error = verify_chain(args.ledger)
    if not ok:
        raise _CheckError(error or "verification failed")
    if args.witness is not None:
        _witness_check(args)
    if args.checkpoint is not None:
        _checkpoint_check(args)
    return count


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ``ambit-verify`` command.

    Args:
        argv: Command-line arguments without the program name. None reads
            ``sys.argv``.

    Returns:
        0 when every requested check passed, 1 when a check failed, 2 on an
        OS error while reading a file.

    Raises:
        SystemExit: With code 2 on a usage error, raised by the parser before
            any verification runs.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    _check_flags(parser, args)
    try:
        count = _verify(args)
    except _CheckError as exc:
        print(f"FAIL: {exc}")
        return 1
    except OSError as exc:
        print(f"ambit-verify: error: {exc}", file=sys.stderr)
        return 2
    print(f"PASS count={count}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
