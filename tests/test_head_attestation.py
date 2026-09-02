# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for head attestation under the HMAC verifier, and for the attestation readers.

A bare hash chain pins only its genesis, so a party with write access can
remove the tail or replace it with a self-consistent one that ``verify_chain``
accepts. Head attestation anchors the head so the same verifier detects it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ambit_verify import (
    GENESIS_HASH,
    HeadAttestation,
    HmacHeadVerifier,
    read_attestation,
    read_attestation_file,
    verify_chain,
)
from ledger_fixtures import TS, HmacHeadSigner, append, attest_head, filled, score, truncate


def _signer() -> HmacHeadSigner:
    return HmacHeadSigner(secret="head-secret", trust_root_id="trust-root-1")


def _verifier() -> HmacHeadVerifier:
    return HmacHeadVerifier(secret="head-secret", trust_root_id="trust-root-1")


def test_attest_then_verify_intact(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 5)
    attestation = attest_head(path, _signer())

    assert attestation.max_seq == 5
    ok, count, error = verify_chain(path, verifier=_verifier())
    assert ok, error
    assert count == 5


def test_truncation_detected(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 5)
    attest_head(path, _signer())

    truncate(path, 4)

    bare_ok, _, _ = verify_chain(path)
    assert bare_ok

    ok, _, error = verify_chain(path, verifier=_verifier())
    assert not ok
    assert error is not None and "truncat" in error.lower()


def test_external_attestation_detects_sidecar_rollback(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 3)
    attest_head(path, _signer())
    rolled_back_sidecar = path.with_suffix(".attest").read_text(encoding="utf-8")

    append(path, score(4))
    latest_attestation = attest_head(path, _signer())

    truncate(path, 3)
    path.with_suffix(".attest").write_text(rolled_back_sidecar, encoding="utf-8")

    sidecar_ok, _, sidecar_error = verify_chain(path, verifier=_verifier())
    assert sidecar_ok, sidecar_error

    ok, _, error = verify_chain(path, verifier=_verifier(), attestation=latest_attestation)
    assert not ok
    assert error is not None and "truncat" in error.lower()


def test_append_after_attestation_fails_as_stale_head(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 3)
    attest_head(path, _signer())

    append(path, score(4))

    ok, _, error = verify_chain(path, verifier=_verifier())
    assert not ok
    assert error is not None and "stale" in error.lower()


def test_forge_after_truncate_detected(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 5)
    attest_head(path, _signer())

    truncate(path, 4)
    append(path, score(99))

    bare_ok, bare_count, _ = verify_chain(path)
    assert bare_ok and bare_count == 5

    ok, _, error = verify_chain(path, verifier=_verifier())
    assert not ok
    assert error is not None and "forg" in error.lower()


def test_signature_tamper_detected(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 3)
    attest_head(path, _signer())

    attest_path = path.with_suffix(".attest")
    blob = attest_path.read_text(encoding="utf-8").replace("hmac-sha256:", "hmac-sha256:dead")
    attest_path.write_text(blob, encoding="utf-8")

    ok, _, error = verify_chain(path, verifier=_verifier())
    assert not ok
    assert error is not None and "invalid" in error.lower()


def test_missing_attestation_fails_closed(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 3)
    ok, _, error = verify_chain(path, verifier=_verifier())
    assert not ok
    assert error == "head attestation missing"


def test_attestation_without_verifier_is_refused(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 3)
    attestation = attest_head(path, _signer())
    ok, _, error = verify_chain(path, attestation=attestation)
    assert not ok
    assert error == "head verifier required when attestation is supplied"


def test_trust_root_mismatch_detected(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 3)
    attest_head(path, _signer())

    other = HmacHeadVerifier(secret="head-secret", trust_root_id="trust-root-2")
    ok, _, error = verify_chain(path, verifier=other)
    assert not ok
    assert error is not None


def test_wrong_secret_detected(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 3)
    attest_head(path, _signer())

    wrong = HmacHeadVerifier(secret="not-the-secret", trust_root_id="trust-root-1")
    ok, _, error = verify_chain(path, verifier=wrong)
    assert not ok
    assert error is not None


def test_verifier_requires_a_secret_and_a_trust_root() -> None:
    with pytest.raises(ValueError, match="secret"):
        HmacHeadVerifier(secret="", trust_root_id="trust-root-1")
    with pytest.raises(ValueError, match="trust_root_id"):
        HmacHeadVerifier(secret="head-secret", trust_root_id="")


def test_attestation_of_an_empty_ledger_verifies(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    path.write_text("", encoding="utf-8")
    attestation = attest_head(path, _signer())
    assert attestation.max_seq == 0
    assert attestation.head_record_hash == GENESIS_HASH
    assert verify_chain(path, verifier=_verifier()) == (True, 0, None)


def test_attestation_of_an_empty_ledger_must_name_the_genesis_hash(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    path.write_text("", encoding="utf-8")
    attestation = _signer().sign_head(0, "f" * 64, TS)

    ok, count, error = verify_chain(path, verifier=_verifier(), attestation=attestation)
    assert (ok, count) == (False, 0)
    assert error == "head attestation of an empty ledger does not name the genesis hash"


def test_read_attestation_is_none_without_a_sidecar(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 2)
    assert read_attestation(path) is None


@pytest.mark.parametrize(
    "content",
    [
        '{"max_seq": "2"}',
        "not json",
        "[1]",
        '{"max_seq": 2, "head_record_hash": "ab", "recorded_at": "t", "trust_root_id": "",'
        ' "signature": "hmac-sha256:00"}',
        '{"max_seq": 2, "head_record_hash": "ab", "recorded_at": "t", "trust_root_id": "r",'
        ' "signature": "hmac-sha256:00", "ledger_id": ""}',
    ],
    ids=["wrong_type", "not_json", "not_an_object", "empty_trust_root", "empty_ledger_id"],
)
def test_read_attestation_is_none_for_a_malformed_sidecar(tmp_path: Path, content: str) -> None:
    path = filled(tmp_path / "ledger.jsonl", 2)
    path.with_suffix(".attest").write_text(content, encoding="utf-8")
    assert read_attestation(path) is None


def test_read_attestation_file_reads_a_retained_copy(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 2)
    attestation = attest_head(path, _signer(), ledger_id="named")
    retained = tmp_path / "retained.json"
    path.with_suffix(".attest").rename(retained)

    assert read_attestation(path) is None
    assert read_attestation_file(retained) == attestation
    assert isinstance(attestation, HeadAttestation)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_read_attestation_file_raises_on_an_unreadable_file(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 2)
    attest_head(path, _signer())
    sidecar = path.with_suffix(".attest")
    sidecar.chmod(0)
    try:
        with pytest.raises(PermissionError):
            read_attestation_file(sidecar)
    finally:
        sidecar.chmod(0o600)
