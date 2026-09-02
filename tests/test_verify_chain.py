# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for bare-chain verification: record hashes, links, segments, and the head read."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ambit_verify import GENESIS_HASH, LedgerReadError, hash_object, read_head, verify_chain
from ledger_fixtures import append, filled, score


def test_intact_chain_passes(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 5)
    assert verify_chain(path) == (True, 5, None)


def test_empty_file_passes_with_zero_records(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    path.write_text("", encoding="utf-8")
    assert verify_chain(path) == (True, 0, None)


def test_missing_file_fails(tmp_path: Path) -> None:
    assert verify_chain(tmp_path / "absent.jsonl") == (False, 0, "ledger file does not exist")


def test_directory_fails(tmp_path: Path) -> None:
    assert verify_chain(tmp_path) == (False, 0, "ledger path is not a file")


def test_blank_lines_are_skipped(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 2)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n" + lines[0] + "\n\n" + lines[1] + "\n\n", encoding="utf-8")
    assert verify_chain(path) == (True, 2, None)


def test_edited_field_breaks_the_record_hash(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 3)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("agent-2", "agent-x")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, count, error = verify_chain(path)
    assert not ok
    assert count == 1
    assert error == "ledger.jsonl:2: record_hash mismatch"


def test_removed_middle_record_breaks_the_chain(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 3)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")

    ok, count, error = verify_chain(path)
    assert not ok
    assert count == 1
    assert error == "ledger.jsonl:2: unexpected seq 3, expected 2"


def test_rewritten_prev_hash_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    append(path, score(1))
    second = dict(score(2))
    second["seq"] = 2
    second["prev_hash"] = "f" * 64
    second["record_hash"] = "0" * 64
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(second) + "\n")

    ok, count, error = verify_chain(path)
    assert not ok
    assert count == 1
    assert error == "ledger.jsonl:2: prev_hash mismatch"


def test_truncated_tail_passes_the_bare_chain(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 5)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
    assert verify_chain(path) == (True, 3, None)


@pytest.mark.parametrize(
    ("line", "error"),
    [
        ("{not json", "ledger.jsonl:2: invalid JSON"),
        ("[1, 2]", "ledger.jsonl:2: record is not an object"),
        ('{"seq": 2, "prev_hash": "x"}', "ledger.jsonl:2: prev_hash mismatch"),
    ],
)
def test_malformed_line_fails_with_position(tmp_path: Path, line: str, error: str) -> None:
    path = filled(tmp_path / "ledger.jsonl", 1)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")

    ok, count, actual = verify_chain(path)
    assert not ok
    assert count == 1
    assert actual is not None and actual.startswith(error)


def test_seq_true_is_not_seq_one(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    record = {"seq": True, "prev_hash": GENESIS_HASH}
    record["record_hash"] = hash_object(record)
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    assert verify_chain(path) == (False, 0, "ledger.jsonl:1: unexpected seq True, expected 1")


def test_missing_record_hash_fails(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 1)
    head = json.loads(path.read_text(encoding="utf-8"))
    record = {"seq": 2, "prev_hash": head["record_hash"], "record_hash": "short"}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")

    ok, _, error = verify_chain(path)
    assert not ok
    assert error == "ledger.jsonl:2: missing/invalid record_hash"


def test_rotated_segments_verify_in_order_before_the_active_file(tmp_path: Path) -> None:
    active = tmp_path / "ledger.jsonl"
    filled(active, 6)
    lines = active.read_text(encoding="utf-8").splitlines()
    (tmp_path / "ledger.2.jsonl").write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    (tmp_path / "ledger.4.jsonl").write_text("\n".join(lines[2:4]) + "\n", encoding="utf-8")
    active.write_text("\n".join(lines[4:]) + "\n", encoding="utf-8")
    # Not a segment of this ledger: the middle is not an integer.
    (tmp_path / "ledger.notes.jsonl").write_text("garbage\n", encoding="utf-8")

    assert verify_chain(active) == (True, 6, None)
    assert read_head(active) == (6, json.loads(lines[5])["record_hash"])


def test_gap_between_segments_fails_at_the_active_file(tmp_path: Path) -> None:
    active = tmp_path / "ledger.jsonl"
    filled(active, 6)
    lines = active.read_text(encoding="utf-8").splitlines()
    (tmp_path / "ledger.2.jsonl").write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    active.write_text("\n".join(lines[4:]) + "\n", encoding="utf-8")

    assert verify_chain(active) == (False, 2, "ledger.jsonl:1: unexpected seq 5, expected 3")


def test_broken_segment_fails_at_the_segment(tmp_path: Path) -> None:
    active = tmp_path / "ledger.jsonl"
    filled(active, 4)
    lines = active.read_text(encoding="utf-8").splitlines()
    (tmp_path / "ledger.2.jsonl").write_text(
        lines[0] + "\n" + lines[1].replace("agent-2", "agent-x") + "\n", encoding="utf-8"
    )
    active.write_text("\n".join(lines[2:]) + "\n", encoding="utf-8")

    ok, count, error = verify_chain(active)
    assert not ok
    assert count == 1
    assert error == "ledger.2.jsonl:2: record_hash mismatch"


def test_read_head_returns_the_verified_head(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 3)
    last = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    assert read_head(path) == (3, last["record_hash"])


def test_read_head_refuses_an_empty_ledger(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    path.write_text("", encoding="utf-8")
    with pytest.raises(LedgerReadError, match="empty"):
        read_head(path)


def test_read_head_refuses_a_broken_ledger(tmp_path: Path) -> None:
    path = filled(tmp_path / "ledger.jsonl", 2)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("agent-1", "agent-x")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(LedgerReadError, match="invalid ledger"):
        read_head(path)
