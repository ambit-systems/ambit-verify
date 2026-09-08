# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""``ambit-verify``: verify a ledger from the command line.

Exit codes: 0 when every requested check passes, 1 when a check fails,
2 for a usage or I/O problem. Stdout carries exactly one line:
``PASS count=N`` or ``FAIL: <reason>``.

Usage errors (bad flag combinations, keys that are not 32 hex bytes, and empty
ids) are raised by the parser before any verification runs.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

from .hashing import strict_json_loads
from .head_attestation import HeadAttestation, HeadVerifier
from .head_attestation_ed25519 import Ed25519CountersignVerifier, Ed25519HeadVerifier
from .verify import (
    _Chain,
    _InputLimitError,
    _read_utf8_document,
    _terminal_safe,
    _walk_ledger,
    read_attestation,
    read_attestation_file,
    verify_chain,
    verify_checkpoint,
    verify_witnessed_head,
)


class _TerminalSafeArgumentParser(argparse.ArgumentParser):
    """Escape attacker-controlled argv in usage failures."""

    def error(self, message: str) -> NoReturn:
        super().error(_terminal_safe(message))


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


def _non_empty(value: str) -> str:
    if not value:
        raise argparse.ArgumentTypeError("must not be empty")
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = _TerminalSafeArgumentParser(
        prog="ambit-verify",
        description=(
            "Verify an Ambit evidence ledger: every record hash, the chain between "
            "records, and optionally the head attestation, a witness ledger, or a "
            "countersigned checkpoint."
        ),
    )
    parser.add_argument("ledger", type=Path, help="path to the ledger (JSONL)")
    parser.add_argument(
        "--attestation",
        type=Path,
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
        type=Path,
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
        type=Path,
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


def _witness_check(args: argparse.Namespace, chain: _Chain) -> None:
    """Run the witness check against the invocation's ledger snapshot."""
    sidecar = read_attestation(args.witness)
    if sidecar is None:
        raise _CheckError("witness: witness ledger invalid: head attestation missing")
    trust_root_id = args.witness_trust_root_id or sidecar.trust_root_id
    verifier = Ed25519HeadVerifier(public_key=args.witness_public_key, trust_root_id=trust_root_id)
    ok, error = verify_witnessed_head(
        args.ledger,
        args.witness,
        verifier,
        witnessed_ledger_id=args.witnessed_ledger_id,
        witness_ledger_attestation=sidecar,
        _chain=chain,
    )
    if not ok:
        raise _CheckError(f"witness: {error}")


def _read_checkpoint(path: Path) -> Mapping[str, Any]:
    try:
        text = _read_utf8_document(path)
    except UnicodeDecodeError:
        raise _CheckError("checkpoint: checkpoint file is not UTF-8") from None
    except _InputLimitError as exc:
        raise _CheckError(f"checkpoint: {exc.reason}") from None
    try:
        checkpoint: Any = strict_json_loads(text)
    except (ValueError, RecursionError) as exc:
        raise _CheckError(f"checkpoint: checkpoint is not valid JSON ({exc})") from None
    if not isinstance(checkpoint, Mapping):
        raise _CheckError("checkpoint: checkpoint is not an object")
    return checkpoint


def _checkpoint_check(
    args: argparse.Namespace, checkpoint: Mapping[str, Any], chain: _Chain
) -> None:
    """Run the checkpoint check against the invocation's ledger snapshot."""
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
        _chain=chain,
    )
    if not ok:
        raise _CheckError(f"checkpoint: {error}")


def _verify(args: argparse.Namespace) -> int:
    """Run every requested check against one ledger snapshot."""
    checkpoint: Mapping[str, Any] | None = None
    checkpoint_failure: _CheckError | OSError | None = None
    want_seq = 0
    if args.checkpoint is not None:
        try:
            checkpoint = _read_checkpoint(args.checkpoint)
        except (_CheckError, OSError) as exc:
            checkpoint_failure = exc
        if checkpoint is not None:
            candidate = checkpoint.get("seq")
            if isinstance(candidate, int) and not isinstance(candidate, bool) and candidate > 0:
                want_seq = candidate

    chain = _walk_ledger(Path(args.ledger).expanduser(), want_seq=want_seq)
    if args.public_key is not None:
        verifier, attestation = _head_check(args)
        ok, count, error = verify_chain(
            args.ledger, verifier=verifier, attestation=attestation, _chain=chain
        )
    else:
        ok, count, error = verify_chain(args.ledger, _chain=chain)
    if not ok:
        raise _CheckError(error or "verification failed")
    if args.witness is not None:
        _witness_check(args, chain)
    if args.checkpoint is not None:
        if checkpoint_failure is not None:
            raise checkpoint_failure
        if checkpoint is None:
            raise _CheckError("checkpoint: checkpoint is unavailable")
        _checkpoint_check(args, checkpoint, chain)
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
        print(f"FAIL: {_terminal_safe(exc)}")
        return 1
    except OSError as exc:
        print(f"ambit-verify: error: {_terminal_safe(exc)}", file=sys.stderr)
        return 2
    print(f"PASS count={count}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
