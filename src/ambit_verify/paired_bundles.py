# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Paired verification of an organisation A bundle and an organisation B bundle."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .execution_evidence import verify_execution_bundle
from .hashing import sha256_hex

_BUNDLE_FIELDS = (
    "schema_version",
    "profile",
    "records",
    "head_attestation",
    "enforcement_point_registration",
)


@dataclass(frozen=True, slots=True)
class ExecutionBundleTrust:
    """The caller-pinned inputs for one ``verify_execution_bundle`` call."""

    admission_trust_roots_by_adapter: Mapping[str, Mapping[str, Any]]
    enforcement_point_registration_public_keys: Mapping[str, str]
    expected_domain: str
    expected_ledger_id: str
    expected_head: Mapping[str, Any]
    operation_id: str


@dataclass(frozen=True, slots=True)
class PairedBundleVerification:
    """Result for one A bundle and one B bundle.

    ``a_dispatch`` and ``a_dispatch_hash`` are set only when the pair is valid.
    ``evidence_form`` is the form of the B clearance evidence, or ``None``.
    """

    valid: bool
    a_errors: tuple[str, ...] = ()
    b_errors: tuple[str, ...] = ()
    paired_dispatch_equal: bool = False
    a_dispatch: str | None = None
    a_dispatch_hash: str | None = None
    evidence_form: str | None = None


def _side(
    bundle: Mapping[str, Any], trust: ExecutionBundleTrust
) -> tuple[bool, tuple[str, ...], str | None]:
    if not isinstance(bundle, Mapping) or any(name not in bundle for name in _BUNDLE_FIELDS):
        return False, ("execution bundle fields are missing",), None
    result = verify_execution_bundle(
        {name: bundle[name] for name in _BUNDLE_FIELDS},
        admission_trust_roots_by_adapter=trust.admission_trust_roots_by_adapter,
        enforcement_point_registration_public_keys=trust.enforcement_point_registration_public_keys,
        expected_domain=trust.expected_domain,
        expected_ledger_id=trust.expected_ledger_id,
        expected_head=trust.expected_head,
        operation_id=trust.operation_id,
    )
    return bool(result.valid), tuple(result.errors), result.foreign_evidence_form


def _fenced_records(bundle: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    records = bundle.get("records") if isinstance(bundle, Mapping) else None
    if not isinstance(records, list):
        return []
    return [
        record
        for record in records
        if isinstance(record, Mapping) and record.get("event") == "dispatch_fenced"
    ]


def _a_dispatch(bundle: Mapping[str, Any]) -> str | None:
    for record in _fenced_records(bundle):
        token = record.get("dispatch_token")
        return token if isinstance(token, str) else None
    return None


def _b_foreign_dispatch(bundle: Mapping[str, Any]) -> object:
    for record in _fenced_records(bundle):
        claims = record.get("dispatch_claims")
        dependency = claims.get("foreign_dependency") if isinstance(claims, Mapping) else None
        return dependency.get("dispatch") if isinstance(dependency, Mapping) else None
    return None


def verify_paired_execution_bundles(
    a_bundle: Mapping[str, Any],
    b_bundle: Mapping[str, Any],
    *,
    a_trust: ExecutionBundleTrust,
    b_trust: ExecutionBundleTrust,
) -> PairedBundleVerification:
    """Verify an A bundle and a B bundle and join them on the A dispatch.

    Each side must verify under its own caller-pinned inputs. The ``dispatch_token``
    of A's ``dispatch_fenced`` record must equal the A dispatch that B's
    ``dispatch_fenced`` record names in ``dispatch_claims.foreign_dependency``.
    """
    a_ok, a_errors, _ = _side(a_bundle, a_trust)
    b_ok, b_errors, evidence_form = _side(b_bundle, b_trust)
    a_dispatch = _a_dispatch(a_bundle)
    paired = isinstance(a_dispatch, str) and a_dispatch == _b_foreign_dispatch(b_bundle)
    valid = a_ok and b_ok and paired
    verified = a_dispatch if valid and isinstance(a_dispatch, str) else None
    return PairedBundleVerification(
        valid=valid,
        a_errors=a_errors,
        b_errors=b_errors,
        paired_dispatch_equal=paired,
        a_dispatch=verified,
        a_dispatch_hash=sha256_hex(verified.encode("utf-8")) if verified is not None else None,
        evidence_form=evidence_form if valid else None,
    )


__all__ = [
    "ExecutionBundleTrust",
    "PairedBundleVerification",
    "verify_paired_execution_bundles",
]
