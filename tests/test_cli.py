# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the ``ambit-verify`` command: output lines and exit codes."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

import ambit_verify.cli as cli_module
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

LEDGER_ID = "authority-prod"


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main([str(arg) for arg in argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _usage_error(capsys: pytest.CaptureFixture[str], *argv: str) -> str:
    with pytest.raises(SystemExit) as exc:
        main([str(arg) for arg in argv])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    return captured.err


def test_bare_chain_pass(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = filled(tmp_path / "ledger.jsonl", 4)
    assert _run(capsys, path) == (0, "PASS count=4\n", "")


def test_execution_command_uses_only_independent_trust_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = Path(__file__).with_name("fixtures") / "controlled_lifecycle_v6"
    bundle = fixture / "execution-bundle.json"
    trust = json.loads((fixture / "caller-trust.json").read_text(encoding="utf-8"))
    admission_roots = tmp_path / "admission-roots.json"
    registration_roots = tmp_path / "registration-roots.json"
    expected_head = tmp_path / "head.json"
    admission_roots.write_text(
        json.dumps(trust["admission_trust_roots_by_adapter"]), encoding="utf-8"
    )
    registration_roots.write_text(
        json.dumps(trust["enforcement_point_registration_public_keys"]), encoding="utf-8"
    )
    expected_head.write_text(json.dumps(trust["expected_head"]), encoding="utf-8")

    code, out, err = _run(
        capsys,
        "execution",
        bundle,
        "--admission-roots",
        admission_roots,
        "--registration-roots",
        registration_roots,
        "--head",
        expected_head,
        "--domain",
        trust["expected_domain"],
        "--ledger-id",
        trust["expected_ledger_id"],
        "--operation-id",
        trust["operation_id"],
    )

    report = json.loads(out)
    assert code == 0 and err == ""
    assert report["valid"] is True
    assert set(report["checks"].values()) == {"valid"}


def test_bare_chain_fail(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = filled(tmp_path / "ledger.jsonl", 3)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[2] = lines[2].replace("agent-3", "agent-x")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert _run(capsys, path) == (1, "FAIL: ledger.jsonl:3: record_hash mismatch\n", "")


def test_missing_ledger_is_a_controlled_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run(capsys, tmp_path / "absent.jsonl") == (
        1,
        "FAIL: ledger file does not exist\n",
        "",
    )


def test_directory_ledger_is_a_controlled_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run(capsys, tmp_path) == (1, "FAIL: ledger path is not a file\n", "")


def test_head_attestation_from_sidecar(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    private_key, public_key = generate_keypair()
    path = filled(tmp_path / "ledger.jsonl", 3)
    attest_head(path, Ed25519HeadSigner(private_key=private_key, trust_root_id="customer-1"))

    assert _run(capsys, path, "--public-key", public_key.hex()) == (0, "PASS count=3\n", "")
    assert _run(
        capsys, path, "--public-key", public_key.hex(), "--trust-root-id", "customer-1"
    ) == (0, "PASS count=3\n", "")


def test_head_attestation_from_named_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    private_key, public_key = generate_keypair()
    path = filled(tmp_path / "ledger.jsonl", 3)
    attest_head(path, Ed25519HeadSigner(private_key=private_key, trust_root_id="customer-1"))
    retained = tmp_path / "retained.json"
    path.with_suffix(".attest").rename(retained)

    assert _run(capsys, path, "--attestation", retained, "--public-key", public_key.hex()) == (
        0,
        "PASS count=3\n",
        "",
    )
    truncate(path, 2)
    code, out, _ = _run(capsys, path, "--attestation", retained, "--public-key", public_key.hex())
    assert code == 1
    assert out.startswith("FAIL: ledger truncated")


def test_head_attestation_missing_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, public_key = generate_keypair()
    path = filled(tmp_path / "ledger.jsonl", 3)
    assert _run(capsys, path, "--public-key", public_key.hex()) == (
        1,
        "FAIL: head attestation missing\n",
        "",
    )


def test_head_attestation_wrong_key_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    private_key, _ = generate_keypair()
    _, other_public = generate_keypair()
    path = filled(tmp_path / "ledger.jsonl", 3)
    attest_head(path, Ed25519HeadSigner(private_key=private_key, trust_root_id="customer-1"))

    assert _run(capsys, path, "--public-key", other_public.hex()) == (
        1,
        "FAIL: head attestation invalid (signature or trust root)\n",
        "",
    )


def test_pinned_trust_root_mismatch_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    private_key, public_key = generate_keypair()
    path = filled(tmp_path / "ledger.jsonl", 3)
    attest_head(path, Ed25519HeadSigner(private_key=private_key, trust_root_id="customer-1"))

    code, out, _ = _run(
        capsys, path, "--public-key", public_key.hex(), "--trust-root-id", "customer-2"
    )
    assert code == 1
    assert out == "FAIL: head attestation invalid (signature or trust root)\n"


def test_malformed_attestation_file_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, public_key = generate_keypair()
    path = filled(tmp_path / "ledger.jsonl", 3)
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    assert _run(capsys, path, "--attestation", bad, "--public-key", public_key.hex()) == (
        1,
        "FAIL: head attestation malformed\n",
        "",
    )


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (("--public-key", "zz"), "argument --public-key: not hexadecimal"),
        (("--public-key", "abcd"), "argument --public-key: must be 32 bytes (2 given)"),
        (("--witness-public-key", "zz"), "argument --witness-public-key: not hexadecimal"),
        (("--countersign-public-key", "zz"), "argument --countersign-public-key: not hexadecimal"),
        (("--trust-root-id", ""), "argument --trust-root-id: must not be empty"),
        (("--witness-trust-root-id", ""), "argument --witness-trust-root-id: must not be empty"),
        (("--witnessed-ledger-id", ""), "argument --witnessed-ledger-id: must not be empty"),
        (("--attestation", "x.json"), "--attestation requires --public-key"),
        (("--trust-root-id", "x"), "--trust-root-id requires --public-key"),
        (("--witness", "w.jsonl"), "--witness requires --witnessed-ledger-id"),
        (
            ("--witness", "w.jsonl", "--witnessed-ledger-id", "x"),
            "--witness requires --witness-public-key",
        ),
        (("--checkpoint", "c.json"), "--checkpoint requires --witness-public-key"),
        (
            ("--checkpoint", "c.json", "--witness-public-key", "00" * 32),
            "--checkpoint requires --countersign-public-key",
        ),
        (("--witness-public-key", "00" * 32), "--witness-public-key requires --witness"),
        (("--witnessed-ledger-id", "x"), "--witnessed-ledger-id requires --witness"),
        (("--countersign-public-key", "00" * 32), "--countersign-public-key requires --checkpoint"),
    ],
)
def test_usage_errors_exit_2_before_any_verification(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], argv: tuple[str, ...], message: str
) -> None:
    # The chain is broken: a check that ran would report FAIL, exit 1.
    path = filled(tmp_path / "ledger.jsonl", 1)
    path.write_text(path.read_text(encoding="utf-8").replace("agent-1", "agent-x"))
    for name in ("x.json", "w.jsonl", "c.json"):
        (tmp_path / name).write_text("", encoding="utf-8")
    argv = tuple(
        str(tmp_path / arg) if arg in ("x.json", "w.jsonl", "c.json") else arg for arg in argv
    )
    err = _usage_error(capsys, path, *argv)
    assert message in err


def test_named_attestation_file_is_admitted_by_the_verifier(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, public_key = generate_keypair()
    path = filled(tmp_path / "ledger.jsonl", 1)
    assert _run(
        capsys,
        path,
        "--attestation",
        tmp_path / "absent.json",
        "--public-key",
        public_key.hex(),
    ) == (1, "FAIL: head attestation malformed\n", "")


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_unreadable_sidecar_is_an_os_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    private_key, public_key = generate_keypair()
    path = filled(tmp_path / "ledger.jsonl", 2)
    attest_head(path, Ed25519HeadSigner(private_key=private_key, trust_root_id="customer-1"))
    sidecar = path.with_suffix(".attest")
    sidecar.chmod(0)
    try:
        code, out, err = _run(capsys, path, "--public-key", public_key.hex())
    finally:
        sidecar.chmod(0o600)
    assert (code, out) == (2, "")
    assert err.startswith("ambit-verify: error:") and "Permission denied" in err


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


def _witness(planes: _Planes, witness_path: Path, authority_path: Path) -> dict[str, Any]:
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


def test_combined_checks_share_one_ledger_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    planes = _Planes()
    authority_path = filled(tmp_path / "authority.jsonl", 1)
    authority_at_one = authority_path.read_bytes()
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)
    witness_at_one = witness_path.read_bytes()
    witness_attestation_at_one = witness_path.with_suffix(".attest").read_bytes()
    append(authority_path, score(2))
    _witness(planes, witness_path, authority_path)

    original_walk = cli_module._walk_ledger
    swapped = False

    def swapping_walk(path: Path, want_seq: int = 0) -> Any:
        nonlocal swapped
        chain = original_walk(path, want_seq)
        if not swapped and path == authority_path.resolve():
            swapped = True
            authority_path.write_bytes(authority_at_one)
            witness_path.write_bytes(witness_at_one)
            witness_path.with_suffix(".attest").write_bytes(witness_attestation_at_one)
        return chain

    monkeypatch.setattr(cli_module, "_walk_ledger", swapping_walk)
    code, out, err = _run(
        capsys,
        authority_path,
        "--witness",
        witness_path,
        "--witnessed-ledger-id",
        LEDGER_ID,
        "--witness-public-key",
        planes.witness_public.hex(),
    )
    assert code == 1
    assert out.startswith("FAIL: witness: stale witness:")
    assert err == ""


def test_witness_pass_and_rollback(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
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
    assert _run(capsys, *argv, "--witness-trust-root-id", "observatory-1") == (
        0,
        "PASS count=4\n",
        "",
    )

    truncate(authority_path, 2)
    assert _run(capsys, *argv) == (
        1,
        "FAIL: witness: rollback: head seq 2 is behind witnessed seq 4\n",
        "",
    )


def test_witness_ledger_without_attestation_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    planes = _Planes()
    authority_path = filled(tmp_path / "authority.jsonl", 2)
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)
    witness_path.with_suffix(".attest").unlink()

    code, out, _ = _run(
        capsys,
        authority_path,
        "--witness",
        witness_path,
        "--witnessed-ledger-id",
        LEDGER_ID,
        "--witness-public-key",
        planes.witness_public.hex(),
    )
    assert (code, out) == (1, "FAIL: witness: witness ledger invalid: head attestation missing\n")


def test_witness_sidecar_with_an_empty_trust_root_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    planes = _Planes()
    authority_path = filled(tmp_path / "authority.jsonl", 2)
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)
    sidecar = witness_path.with_suffix(".attest")
    blob = json.loads(sidecar.read_text(encoding="utf-8"))
    blob["trust_root_id"] = ""
    sidecar.write_text(json.dumps(blob), encoding="utf-8")

    code, out, err = _run(
        capsys,
        authority_path,
        "--witness",
        witness_path,
        "--witnessed-ledger-id",
        LEDGER_ID,
        "--witness-public-key",
        planes.witness_public.hex(),
    )
    assert (code, out, err) == (
        1,
        "FAIL: witness: witness ledger invalid: head attestation missing\n",
        "",
    )


def test_witness_and_checkpoint_together(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    planes = _Planes()
    authority_path = filled(tmp_path / "authority.jsonl", 3)
    checkpoint_path = _checkpoint(planes, tmp_path, authority_path)
    attest_head(authority_path, planes.authority_signer, ledger_id=LEDGER_ID)
    argv = (
        authority_path,
        "--public-key",
        planes.authority_public.hex(),
        "--witness",
        tmp_path / "witness.jsonl",
        "--witnessed-ledger-id",
        LEDGER_ID,
        "--witness-public-key",
        planes.witness_public.hex(),
        "--checkpoint",
        checkpoint_path,
        "--countersign-public-key",
        planes.counter_public.hex(),
    )

    assert _run(capsys, *argv) == (0, "PASS count=3\n", "")
    assert _run(capsys, *argv, "--witness-trust-root-id", "observatory-1") == (
        0,
        "PASS count=3\n",
        "",
    )
    code, out, _ = _run(capsys, *argv, "--witness-trust-root-id", "observatory-2")
    assert (code, out) == (
        1,
        "FAIL: witness: witness ledger invalid: "
        "head attestation invalid (signature or trust root)\n",
    )


def test_checkpoint_with_a_pinned_witness_trust_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    planes = _Planes()
    authority_path = filled(tmp_path / "authority.jsonl", 3)
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

    assert _run(capsys, *argv, "--witness-trust-root-id", "observatory-1") == (
        0,
        "PASS count=3\n",
        "",
    )
    assert _run(capsys, *argv, "--witness-trust-root-id", "observatory-2") == (
        1,
        "FAIL: checkpoint: checkpoint witness record invalid (signature or trust root)\n",
        "",
    )


def test_public_key_with_checkpoint_also_checks_the_sidecar(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    planes = _Planes()
    authority_path = filled(tmp_path / "authority.jsonl", 3)
    checkpoint_path = _checkpoint(planes, tmp_path, authority_path)

    code, out, _ = _run(
        capsys,
        authority_path,
        "--public-key",
        planes.authority_public.hex(),
        "--checkpoint",
        checkpoint_path,
        "--witness-public-key",
        planes.witness_public.hex(),
        "--countersign-public-key",
        planes.counter_public.hex(),
    )
    assert (code, out) == (1, "FAIL: head attestation missing\n")


def test_checkpoint_pass_and_rollback(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
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

    append(authority_path, score(6))
    assert _run(capsys, *argv) == (0, "PASS count=6\n", "")

    truncate(authority_path, 3)
    for i in range(90, 94):
        append(authority_path, score(i))
    assert _run(capsys, *argv) == (
        1,
        "FAIL: checkpoint: rollback: the record at seq 5 is not the checkpointed record\n",
        "",
    )


def test_checkpoint_with_authority_key_checks_the_attestation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    planes = _Planes()
    authority_path = filled(tmp_path / "authority.jsonl", 5)
    checkpoint_path = _checkpoint(planes, tmp_path, authority_path)
    attest_head(authority_path, planes.authority_signer, ledger_id=LEDGER_ID)
    argv = (
        authority_path,
        "--checkpoint",
        checkpoint_path,
        "--witness-public-key",
        planes.witness_public.hex(),
        "--countersign-public-key",
        planes.counter_public.hex(),
    )

    assert _run(capsys, *argv, "--public-key", planes.authority_public.hex()) == (
        0,
        "PASS count=5\n",
        "",
    )

    _, other_public = generate_keypair()
    code, out, _ = _run(capsys, *argv, "--public-key", other_public.hex())
    assert code == 1
    assert out == "FAIL: head attestation invalid (signature or trust root)\n"


def test_checkpoint_wrong_countersign_key_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    planes = _Planes()
    authority_path = filled(tmp_path / "authority.jsonl", 5)
    checkpoint_path = _checkpoint(planes, tmp_path, authority_path)
    _, other_public = generate_keypair()

    code, out, _ = _run(
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


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("not json", "checkpoint is not valid JSON"),
        ("[1]", "checkpoint is not an object"),
        ('{"seq": 1}', "checkpoint witness attestation names no trust root"),
    ],
)
def test_checkpoint_file_shape_failures(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str, reason: str
) -> None:
    planes = _Planes()
    authority_path = filled(tmp_path / "authority.jsonl", 2)
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text(content, encoding="utf-8")

    code, out, _ = _run(
        capsys,
        authority_path,
        "--checkpoint",
        checkpoint_path,
        "--witness-public-key",
        planes.witness_public.hex(),
        "--countersign-public-key",
        planes.counter_public.hex(),
    )
    assert code == 1
    assert out.startswith(f"FAIL: checkpoint: {reason}")


def test_chain_failure_wins_over_later_checks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    planes = _Planes()
    authority_path = filled(tmp_path / "authority.jsonl", 3)
    checkpoint_path = _checkpoint(planes, tmp_path, authority_path)
    lines = authority_path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("agent-1", "agent-x")
    authority_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    code, out, _ = _run(
        capsys,
        authority_path,
        "--checkpoint",
        checkpoint_path,
        "--witness-public-key",
        planes.witness_public.hex(),
        "--countersign-public-key",
        planes.counter_public.hex(),
    )
    assert (code, out) == (1, "FAIL: authority.jsonl:1: record_hash mismatch\n")
