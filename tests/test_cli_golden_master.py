# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Golden-master lock on ``ambit-verify``'s stdout, stderr, and exit code.

Pins the CLI's observable behaviour on the shipped sample ledger and on the
tampered, truncated, wrong-key, witness, and checkpoint cases before any
structural change. Every fixture here is deterministic: no timestamp, hash,
or path leaks into stdout or stderr, so no masking is required.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from ambit_verify import attestation_block, checkpoint_payload, hash_object, read_head
from ambit_verify.cli import main
from ledger_fixtures import (
    TS,
    Ed25519Countersigner,
    Ed25519HeadSigner,
    append,
    attest_head,
    filled,
    generate_keypair,
    score,
    truncate,
)

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "five-receipts"
SAMPLE_PUBLIC_KEY = (SAMPLE / "evidence.jsonl.attest-public-key").read_text().strip()
LEDGER_ID = "authority-prod"


def _run(capsys: pytest.CaptureFixture[str], *argv: str | Path) -> tuple[int, str, str]:
    """Invoke ``main`` and capture its exit code, stdout, and stderr."""
    code = main([str(arg) for arg in argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_sample_ledger_passes(capsys: pytest.CaptureFixture[str]) -> None:
    assert _run(capsys, SAMPLE / "evidence.jsonl", "--public-key", SAMPLE_PUBLIC_KEY) == (
        0,
        "PASS count=9\n",
        "",
    )


def test_sample_ledger_tampered_record_fails(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "evidence.jsonl"
    lines = (SAMPLE / "evidence.jsonl").read_text().splitlines()
    record = json.loads(lines[2])
    record["timestamp_utc"] = "2000-01-01T00:00:00.000Z"
    lines[2] = json.dumps(record, separators=(",", ":"), sort_keys=True)
    ledger.write_text("\n".join(lines) + "\n")

    assert _run(capsys, ledger) == (1, "FAIL: evidence.jsonl:3: record_hash mismatch\n", "")


def test_sample_ledger_truncated_tail_fails_on_head(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "evidence.jsonl"
    lines = (SAMPLE / "evidence.jsonl").read_text().splitlines()
    ledger.write_text("\n".join(lines[:-1]) + "\n")
    shutil.copy(SAMPLE / "evidence.attest", tmp_path / "evidence.attest")

    assert _run(capsys, ledger) == (0, "PASS count=8\n", "")
    code, out, err = _run(capsys, ledger, "--public-key", SAMPLE_PUBLIC_KEY)
    assert code == 1
    assert out == (
        "FAIL: ledger truncated: attested head seq 9 is beyond the current head (seq 8)\n"
    )
    assert err == ""


def test_bare_chain_pass(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 4)
    assert _run(capsys, path) == (0, "PASS count=4\n", "")


def test_wrong_key_fails_closed(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    private_key, _ = generate_keypair()
    _, other_public = generate_keypair()
    path = filled(tmp_path / "ledger.jsonl", 3)
    attest_head(path, Ed25519HeadSigner(private_key=private_key, trust_root_id="customer-1"))

    assert _run(capsys, path, "--public-key", other_public.hex()) == (
        1,
        "FAIL: head attestation invalid (signature or trust root)\n",
        "",
    )


def test_missing_ledger_is_a_controlled_failure(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    assert _run(capsys, tmp_path / "absent.jsonl") == (1, "FAIL: ledger file does not exist\n", "")


def test_directory_as_ledger_is_a_controlled_failure(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    assert _run(capsys, tmp_path) == (1, "FAIL: ledger path is not a file\n", "")


def test_usage_error_exits_2_with_no_stdout(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 1)
    with pytest.raises(SystemExit) as raised:
        main([str(path), "--attestation", "x.json"])
    assert raised.value.code == 2


class _Planes:
    def __init__(self) -> None:
        authority_private, self.authority_public = generate_keypair()
        witness_private, self.witness_public = generate_keypair()
        counter_private, self.counter_public = generate_keypair()
        self.authority_signer = Ed25519HeadSigner(
            private_key=authority_private, trust_root_id="authority-1"
        )
        self.witness_signer = Ed25519HeadSigner(
            private_key=witness_private, trust_root_id="observatory-1"
        )
        self.countersigner = Ed25519Countersigner(
            private_key=counter_private, trust_root_id="holder-1"
        )


def _witness(planes: _Planes, witness_path: Path, authority_path: Path) -> dict[str, object]:
    seq, head_hash = read_head(authority_path)
    attestation = planes.witness_signer.sign_head(seq, head_hash, TS, ledger_id=LEDGER_ID)
    record = append(
        witness_path,
        {
            "record_type": "head_witness",
            "witnessed_ledger_id": LEDGER_ID,
            "attestation": attestation_block(attestation),
        },
    )
    attest_head(witness_path, planes.witness_signer)
    return record


def _checkpoint(planes: _Planes, tmp_path: Path, authority_path: Path) -> Path:
    seq, head_hash = read_head(authority_path)
    attestation = planes.authority_signer.sign_head(seq, head_hash, TS, ledger_id=LEDGER_ID)
    witness_record = _witness(planes, tmp_path / "witness.jsonl", authority_path)
    block = attestation_block(attestation)
    payload = checkpoint_payload(
        seq=seq,
        record_hash=head_hash,
        attestation_hash=hash_object(block),
        witness_record_hash=str(witness_record["record_hash"]),
    )
    checkpoint = {
        "seq": seq,
        "record_hash": head_hash,
        "attestation": block,
        "witness_record": witness_record,
        "countersignature": planes.countersigner.sign_countersignature(payload),
    }
    path = tmp_path / "checkpoint.json"
    path.write_text(json.dumps(checkpoint), encoding="utf-8")
    return path


def test_witness_pass_and_rollback(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = filled(tmp_path / "authority.jsonl", 4)
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)
    argv = (
        authority_path,
        "--witness",
        witness_path,
        "--witnessed-ledger-id",
        LEDGER_ID,
        "--witness-public-key",
        planes.witness_public.hex(),
    )

    assert _run(capsys, *argv) == (0, "PASS count=4\n", "")

    truncate(authority_path, 2)
    assert _run(capsys, *argv) == (
        1,
        "FAIL: witness: rollback: head seq 2 is behind witnessed seq 4\n",
        "",
    )


def test_checkpoint_pass_and_rollback(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = filled(tmp_path / "authority.jsonl", 5)
    checkpoint_path = _checkpoint(planes, tmp_path, authority_path)
    argv = (
        authority_path,
        "--checkpoint",
        checkpoint_path,
        "--witness-public-key",
        planes.witness_public.hex(),
        "--countersign-public-key",
        planes.counter_public.hex(),
    )

    assert _run(capsys, *argv) == (0, "PASS count=5\n", "")

    truncate(authority_path, 3)
    for i in range(90, 94):
        append(authority_path, score(i))
    assert _run(capsys, *argv) == (
        1,
        "FAIL: checkpoint: rollback: the record at seq 5 is not the checkpointed record\n",
        "",
    )


def test_checkpoint_wrong_countersign_key_fails(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    planes = _Planes()
    authority_path = filled(tmp_path / "authority.jsonl", 5)
    checkpoint_path = _checkpoint(planes, tmp_path, authority_path)
    _, other_public = generate_keypair()

    code, out, err = _run(
        capsys,
        authority_path,
        "--checkpoint",
        checkpoint_path,
        "--witness-public-key",
        planes.witness_public.hex(),
        "--countersign-public-key",
        other_public.hex(),
    )
    assert code == 1
    assert (
        out == "FAIL: checkpoint: checkpoint countersignature invalid (signature or trust root)\n"
    )
    assert err == ""
