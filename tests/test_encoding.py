# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Files that are not UTF-8, numbers that are not integers, signatures that are not ASCII."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ambit_verify import GENESIS_HASH, HeadAttestation, HmacHeadVerifier, hash_object, verify_chain
from ambit_verify.cli import main


def _record(seq: int, prev_hash: str, **fields: object) -> dict[str, object]:
    body: dict[str, object] = {"seq": seq, "prev_hash": prev_hash, **fields}
    return {**body, "record_hash": hash_object(body)}


def test_non_utf8_ledger_fails_with_the_file_name(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b'\xff{"seq": 1}\n')
    assert verify_chain(ledger) == (False, 0, "ledger.jsonl: file is not UTF-8")


def test_non_utf8_ledger_is_one_fail_line(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b'\xff{"seq": 1}\n')
    assert main([str(ledger)]) == 1
    assert capsys.readouterr().out == "FAIL: ledger.jsonl: file is not UTF-8\n"


def test_non_utf8_attestation_is_malformed(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(json.dumps(_record(1, GENESIS_HASH)) + "\n")
    (tmp_path / "ledger.attest").write_bytes(b"\xff")
    assert main([str(ledger), "--public-key", "00" * 32]) == 1
    assert capsys.readouterr().out == "FAIL: head attestation missing\n"


def test_non_utf8_checkpoint_is_a_fail_line(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(json.dumps(_record(1, GENESIS_HASH)) + "\n")
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_bytes(b"\xff")
    code = main(
        [
            str(ledger),
            "--checkpoint",
            str(checkpoint),
            "--witness-public-key",
            "00" * 32,
            "--countersign-public-key",
            "00" * 32,
        ]
    )
    assert code == 1
    assert capsys.readouterr().out == "FAIL: checkpoint: checkpoint file is not UTF-8\n"


def test_float_seq_is_not_an_integer(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(json.dumps(_record(1.0, GENESIS_HASH)) + "\n")  # type: ignore[arg-type]
    assert verify_chain(ledger) == (False, 0, "ledger.jsonl:1: unexpected seq 1.0, expected 1")


def test_non_ascii_hmac_signature_is_false_not_an_error() -> None:
    verifier = HmacHeadVerifier(secret="s", trust_root_id="t")
    attestation = HeadAttestation(
        max_seq=0,
        head_record_hash=GENESIS_HASH,
        recorded_at="x",
        trust_root_id="t",
        signature="hmac-sha256:\u00e9",
    )
    assert verifier.verify_head(attestation) is False
