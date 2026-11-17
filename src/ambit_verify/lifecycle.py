# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Pure replay of a complete canonical execution prefix, including unresolved work.

The semantic entry point needs an authenticated snapshot from its caller. The
bundle entry point also checks the registered point and caller-pinned head.
Neither entry point executes policy or proves an unobserved external effect.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any

from .credential_registration import verify_enforcement_point_registration
from .execution_evidence import _records, _replay_prefix
from .hashing import canonical_iso
from .head_attestation import ATTESTATION_BLOCK_KEYS, HeadAttestation
from .head_attestation_ed25519 import Ed25519HeadVerifier
from .issuance_replay import replay_issuance_records
from .lifecycle_fences import replay_fence_records
from .lifecycle_models import (
    LIFECYCLE_PROFILE,
    AccountReplayState,
    ConsumedIdentifierState,
    ExecutionPrefixVerification,
    OperationReplayState,
    RecordCoverage,
)
from .lifecycle_records import OperationLinks, dispatch_token_hash, validate_lifecycle_links
from .revocation_replay import replay_revocation_records
from .verify import GENESIS_HASH


def _hash(record: Mapping[str, Any] | None) -> str | None:
    value = record.get("record_hash") if record is not None else None
    return value if isinstance(value, str) else None


def _operations(
    links: Mapping[tuple[str, str], OperationLinks], projection: Mapping[str, Any]
) -> tuple[OperationReplayState, ...]:
    result = []
    for (domain, operation), item in sorted(links.items()):
        state = str(projection["operation_states"][operation])
        if state == "pending":
            state = "counterparty_pending"
        elif state == "fenced" and item.start is not None:
            state = "started"
        descriptor = item.decision["consumption"]["operation"]
        result.append(
            OperationReplayState(
                domain_id=domain,
                operation_id=operation,
                descriptor=MappingProxyType(dict(descriptor)),
                actor_id=str(item.decision["actor_id"]),
                state=state,
                decision_hash=str(item.decision["record_hash"]),
                intent_hash=_hash(item.intent),
                dispatch_record_hash=_hash(item.fence),
                dispatch_token_hash=dispatch_token_hash(item),
                start_hash=_hash(item.start),
                transport_hashes=tuple(str(record["record_hash"]) for record in item.transports),
                settlement_hash=_hash(item.settlement),
                reservation_ids=tuple(projection["operation_reservations"].get(operation, ())),
            )
        )
    return tuple(result)


def _accounts(projection: Mapping[str, Any]) -> tuple[AccountReplayState, ...]:
    result = []
    for key, (_charged, ceiling) in sorted(
        projection["charged"].items(), key=lambda item: repr(item[0])
    ):
        pending = committed = released = 0
        for account_key, amount, _operation, state in projection["reservations"].values():
            if account_key != key:
                continue
            if state == "committed":
                committed += amount
            elif state == "released":
                released += amount
            else:
                pending += amount
        if pending + committed != _charged:
            raise ValueError("replayed account totals disagree with reservation states")
        result.append(
            AccountReplayState(
                key[0],
                key[1],
                key[2],
                key[3],
                key[4],
                key[5],
                str(ceiling),
                str(pending),
                str(committed),
                str(released),
            )
        )
    return tuple(result)


def replay_execution_prefix(
    records: Sequence[Mapping[str, Any]],
    *,
    admission_trust_roots_by_adapter: Mapping[str, Mapping[str, Any]],
    expected_domain: str,
    expected_ledger_id: str,
    enforcement_point_id: str,
    enforcement_point_public_key: str,
    revocation_policy: Mapping[str, Any] | None = None,
    generic_quantity_policy: Mapping[str, Any] | None = None,
    profile: str = LIFECYCLE_PROFILE,
) -> ExecutionPrefixVerification:
    """Check lifecycle and accounting semantics of an authenticated complete prefix.

    The caller must first authenticate the complete snapshot and its point.
    Unknown record semantics remain explicit and prevent complete coverage.
    A valid unresolved operation remains charged. An authenticated genesis
    prefix is healthy but is not a nonempty qualification workload.
    """
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        return ExecutionPrefixVerification(
            False, False, errors=("prefix records must be a sequence",)
        )
    coverage = tuple(
        RecordCoverage(
            record.get("seq", index)
            if isinstance(record, Mapping) and type(record.get("seq")) is int
            else index,
            str(record.get("record_type", "unknown"))
            if isinstance(record, Mapping)
            else "invalid_record",
            str(record["event"]) if isinstance(record, Mapping) and "event" in record else None,
            "not_established",
            "prefix validation did not complete",
        )
        for index, record in enumerate(records, 1)
    )
    try:
        if profile != LIFECYCLE_PROFILE:
            raise ValueError("unsupported lifecycle replay profile")
        if not all(
            isinstance(value, str) and value
            for value in (
                expected_domain,
                expected_ledger_id,
                enforcement_point_id,
                enforcement_point_public_key,
            )
        ):
            raise ValueError("lifecycle replay needs explicit domain, ledger and point identity")
        if len(bytes.fromhex(enforcement_point_public_key)) != 32:
            raise ValueError("lifecycle point key must be an Ed25519 public key")
        if records:
            _records(
                list(records),
                expected_head={"seq": len(records), "record_hash": records[-1].get("record_hash")},
            )
        links, coverage = validate_lifecycle_links(
            records,
            expected_domain=expected_domain,
            expected_ledger_id=expected_ledger_id,
            enforcement_point_id=enforcement_point_id,
            enforcement_point_public_key=enforcement_point_public_key,
        )
        projection = _replay_prefix(
            records,
            retained_decisions={
                str(record["record_hash"]): record
                for record in records
                if record.get("record_type") == "decision"
            },
            admission_trust_roots_by_adapter=admission_trust_roots_by_adapter,
            expected_domain=expected_domain,
            expected_ledger_id=expected_ledger_id,
            enforcement_point_id=enforcement_point_id,
            enforcement_point_public_key=enforcement_point_public_key,
            allow_unconsumed_dry_runs=True,
            strict_lifecycle=True,
            generic_quantity_policy=generic_quantity_policy,
        )
        issuance_coverage, issuances = replay_issuance_records(
            records,
            admission_trust_roots_by_adapter=admission_trust_roots_by_adapter,
            expected_domain=expected_domain,
            expected_ledger_id=expected_ledger_id,
            enforcement_point_id=enforcement_point_id,
        )
        revocation_coverage = replay_revocation_records(records, revocation_policy)
        fence_coverage = replay_fence_records(
            records,
            policy=revocation_policy,
            enforcement_point_public_key=enforcement_point_public_key,
            expected_domain=expected_domain,
            expected_ledger_id=expected_ledger_id,
            enforcement_point_id=enforcement_point_id,
        )
        revocation_coverage.update(fence_coverage)
        coverage = tuple(
            revocation_coverage.get(row.seq, issuance_coverage.get(row.seq, row))
            for row in coverage
        )
        operations, accounts = _operations(links, projection), _accounts(projection)
        identifiers = tuple(
            ConsumedIdentifierState(namespace, identifier, canonical_iso(expiry))
            for (namespace, identifier), expiry in sorted(projection["consumed"].items())
        )
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return ExecutionPrefixVerification(False, False, coverage, errors=(str(error),))
    return ExecutionPrefixVerification(
        True,
        all(row.status == "valid" for row in coverage),
        coverage,
        operations,
        accounts,
        identifiers,
        issuances=issuances,
    )


def verify_execution_prefix(
    bundle: Mapping[str, Any],
    *,
    admission_trust_roots_by_adapter: Mapping[str, Mapping[str, Any]],
    enforcement_point_registration_public_keys: Mapping[str, str],
    expected_domain: str,
    expected_ledger_id: str,
    expected_head: Mapping[str, Any],
    revocation_policy: Mapping[str, Any] | None = None,
    generic_quantity_policy: Mapping[str, Any] | None = None,
    profile: str = LIFECYCLE_PROFILE,
) -> ExecutionPrefixVerification:
    """Authenticate a complete bundle before replaying its lifecycle prefix."""
    try:
        if (
            set(bundle)
            != {
                "schema_version",
                "profile",
                "records",
                "head_attestation",
                "enforcement_point_registration",
            }
            or type(bundle.get("schema_version")) is not int
            or bundle.get("schema_version") != 1
            or bundle.get("profile") != "canonical-operation/1"
        ):
            raise ValueError("canonical execution bundle schema is invalid")
        if not isinstance(expected_head, Mapping):
            raise ValueError("caller-pinned expected head must be an object")
        records = bundle["records"]
        if records == []:
            if type(expected_head.get("seq")) is not int or dict(expected_head) != {
                "seq": 0,
                "record_hash": GENESIS_HASH,
            }:
                raise ValueError("empty prefix does not match the caller-pinned genesis")
        else:
            records = _records(records, expected_head=expected_head)
        registration = verify_enforcement_point_registration(
            bundle["enforcement_point_registration"],
            registration_public_keys=enforcement_point_registration_public_keys,
        )
        raw = bundle["head_attestation"]
        if not isinstance(raw, Mapping) or set(raw) != ATTESTATION_BLOCK_KEYS:
            raise ValueError("head attestation schema is invalid")
        attestation = HeadAttestation(**dict(raw))
        if (
            type(attestation.max_seq) is not int
            or registration.ledger_id != expected_ledger_id
            or attestation.ledger_id != expected_ledger_id
            or attestation.max_seq != expected_head["seq"]
            or attestation.head_record_hash != expected_head["record_hash"]
            or not Ed25519HeadVerifier(
                public_key=bytes.fromhex(registration.public_key),
                trust_root_id=registration.trust_root_id,
            ).verify_head(attestation)
        ):
            raise ValueError("registered signed head does not bind the caller-pinned snapshot")
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return ExecutionPrefixVerification(False, False, errors=(str(error),))
    return replay_execution_prefix(
        records,
        admission_trust_roots_by_adapter=admission_trust_roots_by_adapter,
        expected_domain=expected_domain,
        expected_ledger_id=expected_ledger_id,
        enforcement_point_id=registration.enforcement_point_id,
        enforcement_point_public_key=registration.public_key,
        revocation_policy=revocation_policy,
        generic_quantity_policy=generic_quantity_policy,
        profile=profile,
    )
