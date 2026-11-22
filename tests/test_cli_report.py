# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``ambit-verify --report json`` and its pure report builder."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from ambit_verify.cli import main
from ambit_verify.cli_report import CLAIMS, ClaimOutcome, build_report

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "five-receipts"
LEDGER = SAMPLE / "evidence.jsonl"
KEY = (SAMPLE / "evidence.jsonl.attest-public-key").read_text().strip()


def _run(capsys: pytest.CaptureFixture[str], *argv: str | Path) -> tuple[int, str, str]:
    code = main([str(arg) for arg in argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _results(report: dict[str, Any]) -> dict[str, str]:
    return {claim["claim"]: claim["result"] for claim in report["claims"]}


def test_build_report_all_pass() -> None:
    outcomes = {name: ClaimOutcome("pass") for name in CLAIMS}
    report = build_report("l.jsonl", outcomes)
    assert report["ledger"] == "l.jsonl"
    assert report["result"] == "pass"
    assert [claim["claim"] for claim in report["claims"]] == list(CLAIMS)
    assert all(claim["detail"] is None for claim in report["claims"])


def test_build_report_one_fail_fails_the_whole() -> None:
    outcomes = {
        "record_hashes": ClaimOutcome("pass"),
        "chain": ClaimOutcome("fail", "l.jsonl:2: prev_hash mismatch"),
    }
    report = build_report("l.jsonl", outcomes)
    assert report["result"] == "fail"
    assert report["claims"][1] == {
        "claim": "chain",
        "result": "fail",
        "detail": "l.jsonl:2: prev_hash mismatch",
    }


def test_build_report_missing_claims_are_not_checked() -> None:
    report = build_report("l.jsonl", {"chain": ClaimOutcome("pass")})
    assert report["result"] == "pass"
    assert _results(report) == {
        "record_hashes": "not_checked",
        "chain": "pass",
        "head_attestation": "not_checked",
        "witness": "not_checked",
        "checkpoint": "not_checked",
    }


def test_text_output_for_sample_is_unchanged(capsys: pytest.CaptureFixture[str]) -> None:
    # Expected values were captured from the command before --report existed.
    assert _run(capsys, LEDGER, "--public-key", KEY) == (0, "PASS count=9\n", "")
    assert _run(capsys, LEDGER) == (0, "PASS count=9\n", "")
    assert _run(capsys, LEDGER, "--report", "text", "--public-key", KEY) == (
        0,
        "PASS count=9\n",
        "",
    )


def test_json_report_for_sample_with_head_attestation(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _run(capsys, LEDGER, "--public-key", KEY, "--report", "json")
    assert (code, err) == (0, "")
    assert out.count("\n") == 1
    report = json.loads(out)
    assert report["ledger"] == str(LEDGER)
    assert report["result"] == "pass"
    assert _results(report) == {
        "record_hashes": "pass",
        "chain": "pass",
        "head_attestation": "pass",
        "witness": "not_checked",
        "checkpoint": "not_checked",
    }


def test_json_report_for_sample_without_key(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run(capsys, LEDGER, "--report", "json")
    assert code == 0
    assert _results(json.loads(out))["head_attestation"] == "not_checked"


def test_json_report_for_missing_attestation_fails_head(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "evidence.jsonl"
    shutil.copy(LEDGER, ledger)
    code, out, _ = _run(capsys, ledger, "--public-key", KEY, "--report", "json")
    text_code, text_out, _ = _run(capsys, ledger, "--public-key", KEY)
    assert code == text_code == 1
    assert text_out == "FAIL: head attestation missing\n"
    report = json.loads(out)
    assert _results(report)["head_attestation"] == "fail"
    assert report["claims"][2]["detail"] == "head attestation missing"


def test_tampered_record_fails_in_both_modes(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "evidence.jsonl"
    shutil.copy(LEDGER, ledger)
    shutil.copy(SAMPLE / "evidence.attest", tmp_path / "evidence.attest")
    data = ledger.read_bytes()
    index = data.index(b'"actor_id":"agent-1"') + len(b'"actor_id":"agent-')
    ledger.write_bytes(data[:index] + b"2" + data[index + 1 :])
    code, out, _ = _run(capsys, ledger, "--public-key", KEY, "--report", "json")
    text_code, text_out, _ = _run(capsys, ledger, "--public-key", KEY)
    assert code == text_code == 1
    report = json.loads(out)
    assert report["result"] == "fail"
    failed = [claim for claim in report["claims"] if claim["result"] == "fail"]
    assert len(failed) == 1
    assert failed[0]["claim"] == "record_hashes"
    assert text_out == f"FAIL: {failed[0]['detail']}\n"
    assert _results(report)["head_attestation"] == "not_checked"


def test_broken_chain_link_is_reported_as_chain(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = tmp_path / "evidence.jsonl"
    lines = LEDGER.read_text().splitlines(keepends=True)
    ledger.write_text("".join(lines[:1] + lines[2:]))
    code, out, _ = _run(capsys, ledger, "--report", "json")
    assert code == 1
    assert _results(json.loads(out))["chain"] == "fail"


def test_usage_error_still_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main([str(LEDGER), "--report", "xml"])
    assert exc.value.code == 2
    capsys.readouterr()
