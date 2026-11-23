# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""``ambit-verify``: verify a ledger from the command line.

Exit codes: 0 when every requested check passes, 1 when a check fails,
2 for a usage or I/O problem. Stdout carries exactly one line:
``PASS count=N`` or ``FAIL: <reason>``.

With ``--report json`` stdout carries one JSON object with a result per claim
instead. The exit codes do not change.

Usage errors (bad flag combinations, keys that are not 32 hex bytes, and empty
ids) are raised by the parser before any verification runs.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

from .capacity import CapacityResult, cross_check_with_replay, recompute_capacity
from .cli_report import FAIL, NOT_CHECKED, PASS, ClaimOutcome, build_report
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
    parser.add_argument(
        "--admission-roots",
        type=Path,
        metavar="PATH",
        help="admission trust roots (JSON, by adapter) for the capacity cross-check",
    )
    parser.add_argument(
        "--quantity-policy",
        type=Path,
        metavar="PATH",
        help="generic quantity policy (JSON) for the capacity cross-check",
    )
    parser.add_argument(
        "--report",
        choices=("text", "json"),
        default="text",
        help="output format: one PASS/FAIL line (text) or one JSON object per claim (json)",
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
    if (args.admission_roots is None) != (args.quantity_policy is None):
        parser.error("--admission-roots and --quantity-policy are used together")


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


_HASH_FAILURES = ("record_hash mismatch", "missing/invalid record_hash")


def _chain_outcomes(chain: _Chain) -> dict[str, ClaimOutcome]:
    """Split the one-pass ledger walk into the record-hash and chain claims."""
    if chain.ok:
        return {"record_hashes": ClaimOutcome(PASS), "chain": ClaimOutcome(PASS)}
    reason = chain.error or "verification failed"
    # The walk stops at the first bad record and reports it as one message. A hash
    # failure ends with one of the two hash messages. Any other reason is a chain failure.
    claim = "record_hashes" if reason.endswith(_HASH_FAILURES) else "chain"
    return {claim: ClaimOutcome(FAIL, reason)}


def _verify(args: argparse.Namespace, outcomes: dict[str, ClaimOutcome]) -> int:
    """Run every requested check against one ledger snapshot.

    Each claim that runs adds its outcome to *outcomes*, in the order the checks run.
    """
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

    cross_check = args.admission_roots is not None
    kept: list[dict[str, Any]] = []

    def keep(record: dict[str, Any]) -> None:
        if cross_check or record.get("record_type") in ("decision", "consumption"):
            kept.append(record)

    chain = _walk_ledger(Path(args.ledger).expanduser(), want_seq=want_seq, record_visitor=keep)
    outcomes.update(_chain_outcomes(chain))
    if args.public_key is not None:
        try:
            verifier, attestation = _head_check(args)
        except _CheckError as exc:
            outcomes["head_attestation"] = ClaimOutcome(FAIL, str(exc))
            raise
        ok, count, error = verify_chain(
            args.ledger, verifier=verifier, attestation=attestation, _chain=chain
        )
        if ok:
            outcomes["head_attestation"] = ClaimOutcome(PASS)
    else:
        ok, count, error = verify_chain(args.ledger, _chain=chain)
    if not ok:
        reason = error or "verification failed"
        if chain.ok:
            outcomes["head_attestation"] = ClaimOutcome(FAIL, reason)
        raise _CheckError(reason)
    if args.witness is not None:
        _record(outcomes, "witness", lambda: _witness_check(args, chain))
    if args.checkpoint is not None:
        if checkpoint_failure is not None:
            raise checkpoint_failure
        if checkpoint is None:
            raise _CheckError("checkpoint: checkpoint is unavailable")
        _record(outcomes, "checkpoint", lambda: _checkpoint_check(args, checkpoint, chain))
    _capacity_claim(args, kept, outcomes)
    return count


_TIER_1_DETAIL = (
    "recomputed from the ledger alone; bound and quantities as stated by the ledger; "
    "not cross-checked against signed credentials"
)
_TIER_2_DETAIL = (
    "recomputed from the ledger; bound and quantities cross-checked against signed "
    "credentials by lifecycle replay"
)


def _read_json_object(path: Path) -> Mapping[str, Any]:
    try:
        value: Any = strict_json_loads(_read_utf8_document(path))
    except (UnicodeDecodeError, _InputLimitError, ValueError, RecursionError) as exc:
        raise _CheckError(f"{path.name} is not a valid JSON document ({exc})") from None
    if not isinstance(value, Mapping):
        raise _CheckError(f"{path.name} is not a JSON object")
    return value


def _capacity_claim(
    args: argparse.Namespace, records: list[dict[str, Any]], outcomes: dict[str, ClaimOutcome]
) -> None:
    """Record the capacity claim. A failure is recorded and raised."""
    result = recompute_capacity(records)
    if result.result == NOT_CHECKED:
        outcomes["capacity"] = ClaimOutcome(NOT_CHECKED, result.detail)
        return
    if result.result == FAIL:
        outcomes["capacity"] = ClaimOutcome(FAIL, result.detail)
        raise _CheckError(f"capacity: {result.detail}")
    accounts = tuple(account.as_dict() for account in result.accounts)
    detail = _TIER_1_DETAIL
    if args.admission_roots is not None:
        detail = _tier_2_detail(args, records, result, outcomes)
    outcomes["capacity"] = ClaimOutcome(PASS, detail, accounts)


def _tier_2_detail(
    args: argparse.Namespace,
    records: list[dict[str, Any]],
    result: CapacityResult,
    outcomes: dict[str, ClaimOutcome],
) -> str:
    """Run the replay cross-check. Return the detail of the passing claim."""
    if args.public_key is None:
        return f"{_TIER_1_DETAIL}; cross-check not run: it needs --public-key"
    try:
        roots = _read_json_object(args.admission_roots)
        policy = _read_json_object(args.quantity_policy)
    except (_CheckError, OSError) as exc:
        return f"{_TIER_1_DETAIL}; cross-check not run: {_terminal_safe(exc)}"
    mismatch = cross_check_with_replay(
        records,
        result.accounts,
        admission_trust_roots_by_adapter=roots,
        generic_quantity_policy=policy,
        enforcement_point_public_key=args.public_key.hex(),
    )
    if mismatch is not None:
        outcomes["capacity"] = ClaimOutcome(FAIL, f"cross-check: {mismatch}")
        raise _CheckError(f"capacity: cross-check: {mismatch}")
    return _TIER_2_DETAIL


def _record(outcomes: dict[str, ClaimOutcome], claim: str, check: Callable[[], None]) -> None:
    """Run *check* and record its outcome. A failure is recorded and raised again."""
    try:
        check()
    except _CheckError as exc:
        outcomes[claim] = ClaimOutcome(FAIL, str(exc))
        raise
    outcomes[claim] = ClaimOutcome(PASS)


def _requested_claims(args: argparse.Namespace) -> set[str]:
    """Return the claims the command line asks for beyond the ledger walk."""
    requested = set()
    if args.public_key is not None:
        requested.add("head_attestation")
    if args.witness is not None:
        requested.add("witness")
    if args.checkpoint is not None:
        requested.add("checkpoint")
    return requested


def _json_report(args: argparse.Namespace, outcomes: dict[str, ClaimOutcome]) -> str:
    """Render the report. A requested claim that never ran is ``not_checked`` with a reason."""
    for claim in (_requested_claims(args) | {"capacity"}) - outcomes.keys():
        outcomes[claim] = ClaimOutcome(NOT_CHECKED, "not run: an earlier claim failed")
    report = build_report(str(args.ledger), outcomes)
    return json.dumps(report, ensure_ascii=True, allow_nan=False)


def _credential_command(argv: Sequence[str]) -> int:
    """Check public retained artifacts against independently supplied roots."""
    command = argv[0]
    parser = _TerminalSafeArgumentParser(prog=f"ambit-verify {command}")
    parser.add_argument("artifact", type=Path)
    if command == "execution":
        parser.add_argument("--admission-roots", type=Path, required=True)
        parser.add_argument("--registration-roots", type=Path, required=True)
        parser.add_argument("--head", type=Path, required=True)
        parser.add_argument("--domain", required=True, type=_non_empty)
        parser.add_argument("--ledger-id", required=True, type=_non_empty)
        parser.add_argument("--operation-id", required=True, type=_non_empty)
    else:
        parser.add_argument("--trust", type=Path, required=True)
        if command == "admission":
            parser.add_argument("--domain", required=True, type=_non_empty)
            parser.add_argument("--ledger-id", required=True, type=_non_empty)
            parser.add_argument("--at", required=True, help="timezone-aware comparison timestamp")
            parser.add_argument("--minimum-version", type=int, default=1)
            parser.add_argument("--previous-hash")
    args = parser.parse_args(argv[1:])
    try:
        if command == "execution":
            from .execution_evidence import verify_execution_bundle

            bundle = strict_json_loads(_read_utf8_document(args.artifact))
            admission_roots = strict_json_loads(_read_utf8_document(args.admission_roots))
            registration_roots = strict_json_loads(_read_utf8_document(args.registration_roots))
            expected_head = strict_json_loads(_read_utf8_document(args.head))
            if not (
                isinstance(bundle, Mapping)
                and isinstance(admission_roots, Mapping)
                and isinstance(registration_roots, Mapping)
                and isinstance(expected_head, Mapping)
            ):
                raise ValueError("execution bundle, roots, and head must be JSON objects")
            execution_result = verify_execution_bundle(
                bundle,
                admission_trust_roots_by_adapter=admission_roots,
                enforcement_point_registration_public_keys=registration_roots,
                expected_domain=args.domain,
                expected_ledger_id=args.ledger_id,
                expected_head=expected_head,
                operation_id=args.operation_id,
            )
            report: dict[str, Any] = {
                "profile": "canonical_operation",
                "valid": execution_result.valid,
                "checks": dict(sorted(execution_result.checks.items())),
                "errors": list(execution_result.errors),
                "limits": [
                    "does not trust bundled roots and establishes only the caller-pinned prefix"
                ],
            }
            if execution_result.foreign_dispatch_hash is not None:
                report["foreign_dispatch_hash"] = execution_result.foreign_dispatch_hash
                report["foreign_evidence_form"] = execution_result.foreign_evidence_form
            if execution_result.evidence_class is not None:
                report["evidence_class"] = execution_result.evidence_class
        else:
            trust = strict_json_loads(_read_utf8_document(args.trust))
            if not isinstance(trust, Mapping):
                raise ValueError("trust document must be an object")
            if command == "admission":
                from .admission import verify_authority_admission

                roots = trust.get("admission_trust_roots")
                if not isinstance(roots, Mapping):
                    raise ValueError("trust document lacks admission_trust_roots")
                result = verify_authority_admission(
                    _read_utf8_document(args.artifact).strip(),
                    admission_trust_roots=roots,
                    expected_domain=args.domain,
                    expected_ledger_id=args.ledger_id,
                    at=datetime.fromisoformat(args.at.replace("Z", "+00:00")),
                    minimum_version=args.minimum_version,
                    expected_previous_hash=args.previous_hash,
                )
                report = {
                    "profile": "signed_authority_admission",
                    "valid": result.valid,
                    "errors": list(result.errors),
                    "admission_hash": result.admission.admission_hash if result.admission else None,
                    "version": result.admission.version if result.admission else None,
                    "limits": [
                        "does not verify execution, current revocation, "
                        "or committed resource effects"
                    ],
                }
            else:
                from .ratification_bundle import GRANT_FILE, verify_ratification_bundle

                credential_roots = trust.get("credential_trust_roots")
                revocation_roots = trust.get("revocation_attestation_public_keys")
                enrollment_roots = trust.get("credential_registration_public_keys")
                if not isinstance(credential_roots, Mapping) or not isinstance(
                    revocation_roots, Mapping
                ):
                    raise ValueError("trust document lacks credential or revocation roots")
                if enrollment_roots is not None and not isinstance(enrollment_roots, Mapping):
                    raise ValueError("credential_registration_public_keys must be an object")
                bundle = verify_ratification_bundle(
                    args.artifact,
                    trust_roots=credential_roots,
                    revocation_trust_roots=revocation_roots,
                    registration_public_keys=enrollment_roots,
                )
                report = {
                    "profile": "issued_grant"
                    if (args.artifact / GRANT_FILE).exists()
                    else "ratification",
                    "valid": bundle.ok,
                    "checks": {
                        name: {"valid": check.ok, "reason": check.reason}
                        for name, check in bundle.checks
                    },
                    "errors": bundle.failures,
                    "limits": [
                        "does not establish independently admitted origin or actual execution"
                    ],
                }
    except OSError as exc:
        print(f"ambit-verify: error: {_terminal_safe(exc)}", file=sys.stderr)
        return 2
    except (_InputLimitError, ValueError, RecursionError) as exc:
        report = {"profile": command, "valid": False, "errors": [_terminal_safe(exc)]}
    print(json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return 0 if report["valid"] else 1


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
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in {"admission", "ratification", "execution"}:
        return _credential_command(arguments)
    parser = _build_parser()
    args = parser.parse_args(arguments)
    _check_flags(parser, args)
    outcomes: dict[str, ClaimOutcome] = {}
    try:
        count = _verify(args, outcomes)
    except _CheckError as exc:
        if args.report == "json":
            print(_json_report(args, outcomes))
        else:
            print(f"FAIL: {_terminal_safe(exc)}")
        return 1
    except OSError as exc:
        print(f"ambit-verify: error: {_terminal_safe(exc)}", file=sys.stderr)
        return 2
    print(_json_report(args, outcomes) if args.report == "json" else f"PASS count={count}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
