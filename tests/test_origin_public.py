# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Public-only verification of a retained admitted-origin bundle."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ambit_verify import (
    verify_admitted_origin,
    verify_authority_admission,
    verify_ratification_bundle,
)

GRANT_FILE = "grant.slip"

_FIXTURE = Path(__file__).parent / "fixtures" / "origin"


def _fixture() -> tuple[dict[str, bytes], dict[str, object], dict[str, object]]:
    caller_trust = json.loads((_FIXTURE / "origin-caller-trust.json").read_text(encoding="utf-8"))
    metadata = json.loads((_FIXTURE / "metadata.json").read_text(encoding="utf-8"))
    names = (
        "entry.json",
        "candidate.json",
        "ratification.slip",
        "ratifier-leaf.slip",
        "ratifier-parent-0.slip",
        "status-0.json",
        "status-1.json",
        "grant.slip",
        "trust_roots.json",
    )
    artifacts = {name: (_FIXTURE / name).read_bytes() for name in names}
    return artifacts, caller_trust, metadata


def _admit(token_name: str, caller_trust: dict[str, object], metadata: dict[str, object]):
    result = verify_authority_admission(
        (_FIXTURE / token_name).read_text(encoding="utf-8").strip(),
        admission_trust_roots=caller_trust["admission_trust_roots"],
        expected_domain=metadata["domain"],
        expected_ledger_id=metadata["ledger_id"],
        at=datetime.fromisoformat(metadata["at"]),
    )
    assert result.valid and result.admission is not None
    return result.admission


def test_complete_retained_origin_is_accepted_by_public_verifiers() -> None:
    artifacts, caller_trust, metadata = _fixture()
    admission = _admit("admission.slip", caller_trust, metadata)
    bundle = verify_ratification_bundle(
        artifacts,
        trust_roots=caller_trust["credential_trust_roots"],
        revocation_trust_roots=caller_trust["revocation_attestation_public_keys"],
        registration_public_keys=caller_trust["credential_registration_public_keys"],
    )
    assert bundle.ok
    origin = artifacts[GRANT_FILE].decode("utf-8").strip()
    admitted = verify_admitted_origin(origin, artifacts, admission=admission)
    assert admitted.valid


def test_ratification_only_bundle_is_weaker_than_admitted_issued_origin() -> None:
    artifacts, caller_trust, metadata = _fixture()
    admission = _admit("admission.slip", caller_trust, metadata)
    ratification_only_artifacts = {
        name: value for name, value in artifacts.items() if name != GRANT_FILE
    }
    ratification_only = verify_ratification_bundle(
        ratification_only_artifacts,
        trust_roots=caller_trust["credential_trust_roots"],
        revocation_trust_roots=caller_trust["revocation_attestation_public_keys"],
        registration_public_keys=caller_trust["credential_registration_public_keys"],
    )
    assert ratification_only.ok
    assert ratification_only.grant.ok
    origin = artifacts[GRANT_FILE].decode("utf-8").strip()
    refused = verify_admitted_origin(origin, ratification_only_artifacts, admission=admission)
    assert not refused.valid


def test_wrong_audience_admission_is_refused_against_complete_origin_bundle() -> None:
    artifacts, caller_trust, metadata = _fixture()
    wrong_audience_admission = _admit("wrong-audience-admission.slip", caller_trust, metadata)
    origin = artifacts[GRANT_FILE].decode("utf-8").strip()
    refused = verify_admitted_origin(origin, artifacts, admission=wrong_audience_admission)
    assert not refused.valid
