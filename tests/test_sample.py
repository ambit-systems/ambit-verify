# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""The shipped sample ledger behaves as the README says it does."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from ambit_verify.cli import main

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "five-receipts"
PUBLIC_KEY = (SAMPLE / "evidence.jsonl.attest-public-key").read_text().strip()


def _run(capsys: pytest.CaptureFixture[str], *argv: str | Path) -> tuple[int, str]:
    code = main([str(arg) for arg in argv])
    return code, capsys.readouterr().out


def test_sample_passes_chain_and_head(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = _run(capsys, SAMPLE / "evidence.jsonl", "--public-key", PUBLIC_KEY)
    assert (code, out) == (0, "PASS count=9\n")


def test_one_changed_value_names_the_record(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "evidence.jsonl"
    lines = (SAMPLE / "evidence.jsonl").read_text().splitlines()
    record = json.loads(lines[2])
    assert "timestamp_utc" in record
    record["timestamp_utc"] = "2000-01-01T00:00:00.000Z"
    lines[2] = json.dumps(record, separators=(",", ":"), sort_keys=True)
    ledger.write_text("\n".join(lines) + "\n")
    code, out = _run(capsys, ledger)
    assert code == 1
    assert out == "FAIL: evidence.jsonl:3: record_hash mismatch\n"


def test_removed_tail_passes_bare_chain_and_fails_head(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "evidence.jsonl"
    lines = (SAMPLE / "evidence.jsonl").read_text().splitlines()
    ledger.write_text("\n".join(lines[:-1]) + "\n")
    shutil.copy(SAMPLE / "evidence.attest", tmp_path / "evidence.attest")
    assert _run(capsys, ledger) == (0, "PASS count=8\n")
    code, out = _run(capsys, ledger, "--public-key", PUBLIC_KEY)
    assert code == 1
    assert out.startswith("FAIL: ledger truncated: attested head seq 9")
