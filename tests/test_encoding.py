# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Files that are not UTF-8, numbers that are not integers, signatures that are not ASCII."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import ambit_verify.verify as verify_module
from ambit_verify import (
    GENESIS_HASH,
    Ed25519CountersignVerifier,
    Ed25519HeadVerifier,
    HeadAttestation,
    HmacHeadVerifier,
    LedgerReadError,
    hash_object,
    ledger_files,
    read_attestation_file,
    read_head,
    read_verified_records,
    verify_chain,
)
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


def test_unpaired_surrogate_hmac_signature_is_false_not_an_error() -> None:
    verifier = HmacHeadVerifier(secret="s", trust_root_id="t")
    attestation = HeadAttestation(
        max_seq=0,
        head_record_hash=GENESIS_HASH,
        recorded_at="x",
        trust_root_id="t",
        signature="hmac-sha256:\ud800",
    )
    assert verifier.verify_head(attestation) is False


def test_unpaired_surrogate_ed25519_signatures_are_false_not_errors() -> None:
    head = Ed25519HeadVerifier(public_key=b"\0" * 32, trust_root_id="t")
    attestation = HeadAttestation(
        max_seq=0,
        head_record_hash=GENESIS_HASH,
        recorded_at="x",
        trust_root_id="t",
        signature="ed25519:\ud800",
    )
    assert head.verify_head(attestation) is False

    checkpoint = Ed25519CountersignVerifier(public_key=b"\0" * 32)
    assert checkpoint.verify_countersignature(b"payload", "ed25519:\ud800") is False


def test_duplicate_attestation_field_is_malformed(tmp_path: Path) -> None:
    path = tmp_path / "retained.attest"
    path.write_text(
        '{"max_seq":0,"max_seq":1,"head_record_hash":"'
        + GENESIS_HASH
        + '","recorded_at":"x","trust_root_id":"t","signature":"hmac-sha256:'
        + "0" * 64
        + '"}',
        encoding="utf-8",
    )
    assert read_attestation_file(path) is None


def test_checkpoint_duplicate_field_is_a_controlled_fail_line(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(json.dumps(_record(1, GENESIS_HASH)) + "\n")
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text('{"seq":1,"seq":2}', encoding="utf-8")

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
    assert capsys.readouterr().out.startswith(
        "FAIL: checkpoint: checkpoint is not valid JSON (duplicate object key"
    )


def test_ledger_line_limit_fails_before_unbounded_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(verify_module, "MAX_LEDGER_LINE_BYTES", 128)
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b" " * 129 + b"\n")

    assert verify_chain(ledger) == (
        False,
        0,
        "ledger.jsonl:1: line exceeds 128 byte limit",
    )


def test_ledger_aggregate_byte_limit_counts_blank_input(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(verify_module, "MAX_LEDGER_BYTES", 10)
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b" " * 10 + b"\n")

    assert verify_chain(ledger) == (
        False,
        0,
        "ledger.jsonl:1: ledger input exceeds 10 byte limit",
    )


def test_ledger_physical_line_limit_counts_blank_lines(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(verify_module, "MAX_LEDGER_PHYSICAL_LINES", 1)
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("\n\n", encoding="utf-8")

    assert verify_chain(ledger) == (
        False,
        0,
        "ledger.jsonl:2: ledger exceeds 1 physical line limit",
    )


def test_ledger_segment_limit_is_controlled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(verify_module, "MAX_LEDGER_SEGMENTS", 1)
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    (tmp_path / "ledger.1.jsonl").write_text("", encoding="utf-8")
    (tmp_path / "ledger.2.jsonl").write_text("", encoding="utf-8")

    assert verify_chain(ledger) == (
        False,
        0,
        "ledger.jsonl: ledger exceeds 1 segment limit",
    )


def test_ledger_directory_entry_limit_stops_streaming_enumeration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(verify_module, "MAX_LEDGER_DIRECTORY_ENTRIES", 2)
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(json.dumps(_record(1, GENESIS_HASH)) + "\n", encoding="utf-8")
    for index in range(3):
        (tmp_path / f"unrelated-{index}").write_text("", encoding="utf-8")

    original_scandir = os.scandir

    class _BoundedScandir:
        def __init__(self, iterator: os.ScandirIterator[str]) -> None:
            self.iterator = iterator
            self.examined = 0

        def __enter__(self) -> _BoundedScandir:
            return self

        def __exit__(self, *_args: object) -> None:
            self.iterator.close()

        def __iter__(self) -> _BoundedScandir:
            return self

        def __next__(self) -> os.DirEntry[str]:
            self.examined += 1
            assert self.examined <= 3
            return next(self.iterator)

    observed: _BoundedScandir | None = None

    def bounded_scandir(directory_fd: int) -> _BoundedScandir:
        nonlocal observed
        observed = _BoundedScandir(original_scandir(directory_fd))
        return observed

    monkeypatch.setattr(verify_module.os, "scandir", bounded_scandir)
    assert verify_chain(ledger) == (
        False,
        0,
        "ledger.jsonl: ledger directory exceeds 2 entry limit",
    )
    assert observed is not None
    assert observed.examined == 3


def test_public_ledger_files_stops_descriptor_stream_at_directory_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(verify_module, "MAX_LEDGER_DIRECTORY_ENTRIES", 2)
    for index in range(3):
        (tmp_path / f"unrelated-{index}").write_text("", encoding="utf-8")

    original_scandir = os.scandir

    class _BoundedScandir:
        def __init__(self, iterator: os.ScandirIterator[str]) -> None:
            self.iterator = iterator
            self.examined = 0

        def __enter__(self) -> _BoundedScandir:
            return self

        def __exit__(self, *_args: object) -> None:
            self.iterator.close()

        def __iter__(self) -> _BoundedScandir:
            return self

        def __next__(self) -> os.DirEntry[str]:
            self.examined += 1
            assert self.examined <= 3
            return next(self.iterator)

    observed: _BoundedScandir | None = None

    def bounded_scandir(directory_fd: int) -> _BoundedScandir:
        nonlocal observed
        observed = _BoundedScandir(original_scandir(directory_fd))
        return observed

    monkeypatch.setattr(verify_module.os, "scandir", bounded_scandir)
    with pytest.raises(
        verify_module._InputLimitError,
        match="ledger directory exceeds 2 entry limit",
    ):
        ledger_files(tmp_path / "ledger.jsonl")
    assert observed is not None
    assert observed.examined == 3


def test_public_ledger_files_rejects_a_symlinked_parent(tmp_path: Path) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    linked_directory = tmp_path / "linked"
    linked_directory.symlink_to(real_directory, target_is_directory=True)

    with pytest.raises(
        verify_module._InputLimitError,
        match="ledger directory contains a symbolic link or is not a directory",
    ):
        ledger_files(linked_directory / "ledger.jsonl")


def test_public_ledger_files_expands_home_and_orders_segments(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in ("ledger.jsonl", "ledger.2.jsonl", "ledger.1.jsonl"):
        (home / name).write_text("", encoding="utf-8")

    assert ledger_files("~/ledger.jsonl") == [
        home / "ledger.1.jsonl",
        home / "ledger.2.jsonl",
        home / "ledger.jsonl",
    ]


def test_fifo_segment_is_rejected_without_blocking(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    os.mkfifo(tmp_path / "ledger.1.jsonl")

    assert verify_chain(ledger) == (
        False,
        0,
        "ledger.1.jsonl: ledger component is not a regular file",
    )


def test_symlink_segment_outside_ledger_directory_is_rejected(tmp_path: Path) -> None:
    ledger_dir = tmp_path / "ledger"
    ledger_dir.mkdir()
    ledger = ledger_dir / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    outside = tmp_path / "outside.jsonl"
    outside.write_text("", encoding="utf-8")
    (ledger_dir / "ledger.1.jsonl").symlink_to(outside)

    assert verify_chain(ledger) == (
        False,
        0,
        "ledger.1.jsonl: ledger component is not a regular file",
    )


def test_unicode_digit_lookalike_is_not_a_rotation_segment(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    (tmp_path / "ledger.².jsonl").write_text("not JSON\n", encoding="utf-8")

    assert verify_chain(ledger) == (True, 0, None)
    assert main([str(ledger)]) == 0
    assert capsys.readouterr().out == "PASS count=0\n"


def test_active_ledger_symlink_is_rejected_by_public_readers(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    outside = tmp_path / "outside.jsonl"
    outside.write_text(json.dumps(_record(1, GENESIS_HASH)) + "\n", encoding="utf-8")
    ledger_dir = tmp_path / "ledger"
    ledger_dir.mkdir()
    ledger = ledger_dir / "ledger.jsonl"
    ledger.symlink_to(outside)
    error = "ledger.jsonl: ledger component is not a regular file"

    assert verify_chain(ledger) == (False, 0, error)
    assert read_verified_records(ledger) == (False, (), error)
    with pytest.raises(LedgerReadError, match="ledger component is not a regular file"):
        read_head(ledger)
    assert main([str(ledger)]) == 1
    assert capsys.readouterr().out == f"FAIL: {error}\n"


def test_ledger_directory_symlink_is_rejected(tmp_path: Path) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    ledger = real_directory / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    linked_directory = tmp_path / "linked"
    linked_directory.symlink_to(real_directory, target_is_directory=True)

    assert verify_chain(linked_directory / ledger.name) == (
        False,
        0,
        "ledger.jsonl: ledger directory contains a symbolic link or is not a directory",
    )


def test_cli_failure_escapes_terminal_controls_and_format_characters(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger\u202e\n.jsonl"
    ledger.write_text(
        json.dumps({"seq": "\x1b\r\n", "prev_hash": GENESIS_HASH, "record_hash": "0" * 64}) + "\n",
        encoding="utf-8",
    )

    assert main([str(ledger)]) == 1
    output = capsys.readouterr().out
    assert output == (r"FAIL: ledger\u202e\n.jsonl:1: unexpected seq \x1b\r\n, expected 1" + "\n")


def test_cli_rejects_unpaired_surrogate_json_as_one_safe_fail_line(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(
        json.dumps(
            {
                "seq": 1,
                "prev_hash": GENESIS_HASH,
                "value": "\ud800",
                "record_hash": "0" * 64,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    assert main([str(ledger)]) == 1
    assert capsys.readouterr().out == (
        "FAIL: ledger.jsonl:1: invalid JSON (unpaired surrogate in JSON string)\n"
    )


def test_cli_usage_error_escapes_attacker_controlled_argv(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    malicious_option = "--bad\x1b\r\n\u202e\ud800"

    with pytest.raises(SystemExit) as raised:
        main([str(ledger), malicious_option])

    assert raised.value.code == 2
    error = capsys.readouterr().err
    assert r"--bad\x1b\r\n\u202e\ud800" in error
    assert "\x1b" not in error
    assert "\u202e" not in error
    assert "\ud800" not in error


def test_active_ledger_is_consumed_from_its_checked_descriptor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(json.dumps(_record(1, GENESIS_HASH)) + "\n", encoding="utf-8")
    outside = tmp_path / "outside.jsonl"
    outside.write_text("not JSON\n", encoding="utf-8")
    original_scandir = os.scandir

    def replace_after_open(directory_fd: int) -> os.ScandirIterator[str]:
        entries = original_scandir(directory_fd)
        ledger.unlink()
        ledger.symlink_to(outside)
        return entries

    monkeypatch.setattr(verify_module.os, "scandir", replace_after_open)
    assert verify_chain(ledger) == (True, 1, None)


def test_ledger_record_limit_is_controlled(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(verify_module, "MAX_LEDGER_RECORDS", 1)
    ledger = tmp_path / "ledger.jsonl"
    first = _record(1, GENESIS_HASH)
    second = _record(2, str(first["record_hash"]))
    ledger.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n", encoding="utf-8")

    assert verify_chain(ledger) == (
        False,
        1,
        "ledger.jsonl:2: ledger exceeds 1 record limit",
    )


def test_checkpoint_document_limit_is_a_controlled_fail_line(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(verify_module, "MAX_JSON_DOCUMENT_BYTES", 32)
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(json.dumps(_record(1, GENESIS_HASH)) + "\n")
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text('{"padding":"' + "x" * 32 + '"}', encoding="utf-8")

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
    assert capsys.readouterr().out == "FAIL: checkpoint: file exceeds 32 byte limit\n"
