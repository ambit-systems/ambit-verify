# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the ``capacity`` claim: ledger-only recomputation and the replay cross-check."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from ambit_verify import CapacityResult, recompute_capacity
from ambit_verify.capacity import NO_ACCOUNTS_DETAIL, cross_check_with_replay
from ambit_verify.cli import main
from test_lifecycle_prefix import rechain

FIXTURES = Path(__file__).with_name("fixtures")
SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "five-receipts"


def sibling() -> list[dict[str, Any]]:
    path = FIXTURES / "controlled_cumulative_sibling_v6" / "execution-bundle.json"
    return json.loads(path.read_text())["records"]


def numeric(case: str) -> dict[str, Any]:
    return json.loads((FIXTURES / "generic_numeric_v1" / f"{case}.json").read_text())


def write_ledger(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records))
    return path


def accounts_of(result: CapacityResult) -> dict[tuple[str, str], tuple[str, ...]]:
    return {
        (a.scope_id, a.kind): (
            a.ceiling_amount_scaled,
            a.committed_amount_scaled,
            a.held_amount_scaled,
            a.released_amount_scaled,
        )
        for a in result.accounts
    }


def test_settled_ledger_passes_with_committed_totals() -> None:
    result = recompute_capacity(sibling())
    assert result.result == "pass", result.detail
    by_scope = {a.scope: a for a in result.accounts if a.scope == "entry"}
    entry = by_scope["entry"]
    assert (entry.ceiling_amount_scaled, entry.committed_amount_scaled) == ("100", "61")
    assert (entry.held_amount_scaled, entry.released_amount_scaled) == ("0", "0")
    assert all(a.held_amount_scaled == "0" for a in result.accounts)


def test_unsettled_reservation_is_held() -> None:
    result = recompute_capacity(numeric("case-001")["bundle"]["records"])
    assert result.result == "pass"
    (account,) = result.accounts
    assert (account.held_amount_scaled, account.committed_amount_scaled) == ("59", "0")


def test_release_settlement_moves_held_to_released() -> None:
    result = recompute_capacity(numeric("case-002")["bundle"]["records"])
    assert result.result == "pass"
    (account,) = result.accounts
    assert (account.held_amount_scaled, account.committed_amount_scaled) == ("0", "0")
    assert account.released_amount_scaled == "59"


@pytest.mark.parametrize("path", [("controlled_lifecycle_v6", "execution-bundle.json")])
def test_ledger_without_cumulative_records_is_not_checked(path: tuple[str, str]) -> None:
    records = json.loads((FIXTURES.joinpath(*path)).read_text())["records"]
    result = recompute_capacity(records)
    assert (result.result, result.detail) == ("not_checked", NO_ACCOUNTS_DETAIL)


def test_settlement_without_authorized_decision_fails() -> None:
    records = [r for r in sibling() if r["seq"] != 10]
    result = recompute_capacity(records)
    assert result.result == "fail"
    assert result.seq == 15
    assert "no authorized decision" in (result.detail or "")


def test_second_settlement_fails() -> None:
    records = sibling()
    records.insert(15, copy.deepcopy(records[14]))
    result = recompute_capacity(rechain(records))
    assert result.result == "fail"
    assert result.seq == 16
    assert "second settlement" in (result.detail or "")


def test_repeated_reservation_id_fails() -> None:
    records = sibling()
    first = records[9]["consumption"]["accounts"][0]["reservation_id"]
    records[16]["consumption"]["accounts"][0]["reservation_id"] = first
    result = recompute_capacity(rechain(records))
    assert result.result == "fail"
    assert result.seq == 17
    assert "repeated" in (result.detail or "")


def test_overspend_by_amount_fails_with_key_and_seq() -> None:
    records = sibling()
    for row in records[16]["consumption"]["accounts"]:
        if row["scope"] == "entry":
            row["amount_scaled"] = "41"
    result = recompute_capacity(rechain(records))
    assert result.result == "fail"
    assert result.seq == 17
    assert result.window is not None and result.window[1] == "entry"
    assert "exceed the ceiling" in (result.detail or "")
    assert "seq 17" in (result.detail or "")


def test_lowered_ceiling_fails() -> None:
    records = sibling()
    for row in records[9]["consumption"]["accounts"]:
        if row["scope"] == "entry":
            row["ceiling_amount_scaled"] = "50"
    result = recompute_capacity(rechain(records))
    assert result.result == "fail"
    assert result.seq == 10


def test_ceiling_change_inside_a_window_fails() -> None:
    records = sibling()
    for row in records[16]["consumption"]["accounts"]:
        if row["scope"] == "entry":
            row["ceiling_amount_scaled"] = "200"
    result = recompute_capacity(rechain(records))
    assert result.result == "fail"
    assert result.seq == 17
    assert "ceiling changes" in (result.detail or "")


def test_tier_2_equals_tier_1_totals() -> None:
    case = numeric("case-003")
    records = case["bundle"]["records"]
    context = case["context"]
    registration = case["bundle"]["enforcement_point_registration"]
    from ambit_verify.credential_registration import verify_enforcement_point_registration

    point = verify_enforcement_point_registration(
        registration,
        registration_public_keys=context["enforcement_point_registration_public_keys"],
    )
    tier1 = recompute_capacity(records)
    assert tier1.result == "pass"
    mismatch = cross_check_with_replay(
        records,
        tier1.accounts,
        admission_trust_roots_by_adapter=context["admission_trust_roots_by_adapter"],
        generic_quantity_policy=context["generic_quantity_policy"],
        enforcement_point_public_key=point.public_key,
    )
    assert mismatch is None
    # A tampered total disagrees with the replay.
    shifted = list(tier1.accounts)
    shifted[0] = type(shifted[0])(*shifted[0].key, "80", "1", "59", "0")
    assert (
        cross_check_with_replay(
            records,
            shifted,
            admission_trust_roots_by_adapter=context["admission_trust_roots_by_adapter"],
            generic_quantity_policy=context["generic_quantity_policy"],
            enforcement_point_public_key=point.public_key,
        )
        is not None
    )


def run(capsys: pytest.CaptureFixture[str], *argv: str | Path) -> tuple[int, str]:
    code = main([str(a) for a in argv])
    return code, capsys.readouterr().out


def capacity_claim(out: str) -> dict[str, Any]:
    return next(c for c in json.loads(out)["claims"] if c["claim"] == "capacity")


def test_cli_report_includes_capacity_accounts(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = write_ledger(tmp_path / "evidence.jsonl", sibling())
    code, out = run(capsys, ledger, "--report", "json")
    assert code == 0
    claim = capacity_claim(out)
    assert claim["result"] == "pass"
    assert "not cross-checked against signed credentials" in claim["detail"]
    assert "bound and quantities as stated by the ledger" in claim["detail"]
    assert {a["committed_amount_scaled"] for a in claim["accounts"] if a["scope"] == "entry"} == {
        "61"
    }
    assert run(capsys, ledger)[0] == 0


def test_cli_overspend_exits_1(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    records = sibling()
    for row in records[16]["consumption"]["accounts"]:
        if row["scope"] == "entry":
            row["amount_scaled"] = "41"
    ledger = write_ledger(tmp_path / "evidence.jsonl", rechain(records))
    code, out = run(capsys, ledger, "--report", "json")
    assert code == 1
    claim = capacity_claim(out)
    assert claim["result"] == "fail"
    assert "seq 17" in claim["detail"]
    assert json.loads(out)["result"] == "fail"
    code, text = run(capsys, ledger)
    assert code == 1 and text.startswith("FAIL: capacity: ")


def test_cli_ledger_without_accounts_is_not_checked(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, SAMPLE / "evidence.jsonl", "--report", "json")
    assert code == 0
    claim = capacity_claim(out)
    assert (claim["result"], claim["detail"]) == ("not_checked", NO_ACCOUNTS_DETAIL)
    assert "accounts" not in claim


def test_cli_cross_check_flags_come_together(tmp_path: Path) -> None:
    roots = tmp_path / "roots.json"
    roots.write_text("{}")
    with pytest.raises(SystemExit) as raised:
        main([str(SAMPLE / "evidence.jsonl"), "--admission-roots", str(roots)])
    assert raised.value.code == 2


def test_cli_cross_check_without_valid_inputs_is_not_run(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ledger = write_ledger(tmp_path / "evidence.jsonl", sibling())
    missing = tmp_path / "absent.json"
    code, out = run(
        capsys,
        ledger,
        "--admission-roots",
        missing,
        "--quantity-policy",
        missing,
        "--report",
        "json",
    )
    assert code == 0
    claim = capacity_claim(out)
    assert claim["result"] == "pass"
    assert "cross-check not run" in claim["detail"]


SHARED = FIXTURES / "shared_budget_v1"


def shared_args() -> list[str | Path]:
    key = (SHARED / "head-public-key.txt").read_text().strip()
    return [
        SHARED / "evidence.jsonl",
        "--attestation",
        SHARED / "evidence.attest",
        "--public-key",
        key,
        "--report",
        "json",
    ]


def test_real_shared_budget_ledger_passes_tier_1(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, *shared_args())
    assert code == 0
    claim = capacity_claim(out)
    assert claim["result"] == "pass"
    (entry,) = [a for a in claim["accounts"] if a["scope"] == "entry"]
    assert entry["ceiling_amount_scaled"] == "3"
    assert entry["committed_amount_scaled"] == "3"
    assert entry["held_amount_scaled"] == "0"
    assert all(a["held_amount_scaled"] == "0" for a in claim["accounts"])


def test_real_shared_budget_ledger_passes_tier_2(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(
        capsys,
        *shared_args(),
        "--admission-roots",
        SHARED / "admission-roots.json",
        "--quantity-policy",
        SHARED / "quantity-policy.json",
    )
    assert code == 0
    claim = capacity_claim(out)
    assert claim["result"] == "pass"
    assert "cross-checked against signed credentials" in claim["detail"]
    assert "not cross-checked" not in claim["detail"]


def test_real_ledger_with_wrong_quantity_policy_fails_cross_check(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    policy = json.loads((SHARED / "quantity-policy.json").read_text())
    policy["argument_quantity_by_action"]["write"]["argument"] = "other"
    wrong = tmp_path / "policy.json"
    wrong.write_text(json.dumps(policy))
    code, out = run(
        capsys,
        *shared_args(),
        "--admission-roots",
        SHARED / "admission-roots.json",
        "--quantity-policy",
        wrong,
    )
    assert code == 1
    assert capacity_claim(out)["result"] == "fail"
