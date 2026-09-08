# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the witness check and the holder-retained checkpoint.

``verify_witnessed_head`` compares a ledger against the highest witness the
witness ledger holds. Both ledgers are live, so a party who can write to both
can roll the ledger back, append again, and have the new head witnessed; the
witness check then passes on the rewritten history.

A checkpoint closes that. It is one head (``seq`` and ``record_hash``) with
the writer's attestation, the witness record, and a countersignature by a key
neither the writer nor the witness holds. Its holder keeps the file. A ledger
that no longer carries that record at that seq fails, whatever the two live
ledgers now agree on.
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

import ambit_verify.verify as verify_module
from ambit_verify import (
    Ed25519CountersignVerifier,
    Ed25519HeadVerifier,
    attestation_block,
    checkpoint_payload,
    hash_object,
    read_attestation,
    read_head,
    verify_checkpoint,
    verify_witnessed_head,
)
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


class _Planes:
    """The three keys a checkpoint needs: the writer, the witness, and the holder."""

    def __init__(self) -> None:
        authority_private, authority_public = generate_keypair()
        witness_private, witness_public = generate_keypair()
        counter_private, counter_public = generate_keypair()
        self.authority_signer = Ed25519HeadSigner(
            private_key=authority_private, trust_root_id="authority-1"
        )
        self.authority_verifier = Ed25519HeadVerifier(
            public_key=authority_public, trust_root_id="authority-1"
        )
        self.witness_signer = Ed25519HeadSigner(
            private_key=witness_private, trust_root_id="observatory-1"
        )
        self.witness_verifier = Ed25519HeadVerifier(
            public_key=witness_public, trust_root_id="observatory-1"
        )
        self.countersigner = Ed25519Countersigner(
            private_key=counter_private, trust_root_id="holder-1"
        )
        self.countersign_verifier = Ed25519CountersignVerifier(public_key=counter_public)


def _authority(tmp_path: Path, n: int) -> Path:
    return filled(tmp_path / "authority.jsonl", n)


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
    attest_head(witness_path, planes.witness_signer, ledger_id="observatory-ledger")
    return record


def _checkpoint(planes: _Planes, witness_path: Path, authority_path: Path) -> dict[str, Any]:
    seq, head_hash = read_head(authority_path)
    attestation = planes.authority_signer.sign_head(seq, head_hash, TS, ledger_id=LEDGER_ID)
    witness_record = _witness(planes, witness_path, authority_path)
    block = attestation_block(attestation)
    payload = checkpoint_payload(
        seq=seq,
        record_hash=head_hash,
        attestation_hash=hash_object(block),
        witness_record_hash=str(witness_record["record_hash"]),
    )
    return {
        "seq": seq,
        "record_hash": head_hash,
        "attestation": block,
        "witness_record": witness_record,
        "countersignature": planes.countersigner.sign_countersignature(payload),
    }


def _verify(planes: _Planes, authority_path: Path, checkpoint: Any) -> tuple[bool, str | None]:
    return verify_checkpoint(
        authority_path,
        checkpoint,
        witness_verifier=planes.witness_verifier,
        countersign_verifier=planes.countersign_verifier,
        authority_verifier=planes.authority_verifier,
    )


def test_witnessed_head_accepts_an_intact_ledger(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 3)
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)

    ok, error = verify_witnessed_head(
        authority_path, witness_path, planes.witness_verifier, witnessed_ledger_id=LEDGER_ID
    )
    assert ok, error


def test_witness_and_checkpoint_reject_active_ledger_symlinks(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 1)
    witness_path = tmp_path / "witness.jsonl"
    checkpoint = _checkpoint(planes, witness_path, authority_path)
    links = tmp_path / "links"
    links.mkdir()
    authority_link = links / authority_path.name
    authority_link.symlink_to(authority_path)

    ok, error = verify_witnessed_head(
        authority_link,
        witness_path,
        planes.witness_verifier,
        witnessed_ledger_id=LEDGER_ID,
    )
    assert not ok
    assert error == (
        "witnessed ledger invalid: authority.jsonl: ledger component is not a regular file"
    )

    ok, error = _verify(planes, authority_link, checkpoint)
    assert not ok
    assert error == "ledger invalid: authority.jsonl: ledger component is not a regular file"

    witness_link = links / witness_path.name
    witness_link.symlink_to(witness_path)
    ok, error = verify_witnessed_head(
        authority_path,
        witness_link,
        planes.witness_verifier,
        witnessed_ledger_id=LEDGER_ID,
        witness_ledger_attestation=read_attestation(witness_path),
    )
    assert not ok
    assert error == "witness ledger invalid: witness.jsonl: ledger component is not a regular file"


def test_witnessed_head_takes_the_highest_valid_witness(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 2)
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)
    append(authority_path, score(3))
    _witness(planes, witness_path, authority_path)

    ok, error = verify_witnessed_head(
        authority_path, witness_path, planes.witness_verifier, witnessed_ledger_id=LEDGER_ID
    )
    assert ok, error


def test_witnessed_head_detects_rollback(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)
    truncate(authority_path, 3)

    ok, error = verify_witnessed_head(
        authority_path, witness_path, planes.witness_verifier, witnessed_ledger_id=LEDGER_ID
    )
    assert not ok
    assert error is not None and "rollback" in error.lower()


def test_witnessed_head_fails_closed_on_appends_after_the_witness(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 3)
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)
    append(authority_path, score(4))

    ok, error = verify_witnessed_head(
        authority_path, witness_path, planes.witness_verifier, witnessed_ledger_id=LEDGER_ID
    )
    assert not ok
    assert error is not None and "stale witness" in error.lower()


def test_witnessed_head_detects_a_forged_head(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 3)
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)
    truncate(authority_path, 2)
    append(authority_path, score(99))

    ok, error = verify_witnessed_head(
        authority_path, witness_path, planes.witness_verifier, witnessed_ledger_id=LEDGER_ID
    )
    assert not ok
    assert error is not None and "forgery" in error.lower()


def test_witnessed_head_takes_a_caller_held_witness_attestation(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 3)
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)
    retained = read_attestation(witness_path)
    assert retained is not None
    witness_path.with_suffix(".attest").unlink()

    ok, error = verify_witnessed_head(
        authority_path,
        witness_path,
        planes.witness_verifier,
        witnessed_ledger_id=LEDGER_ID,
        witness_ledger_attestation=retained,
    )
    assert ok, error

    append(authority_path, score(4))
    _witness(planes, witness_path, authority_path)
    ok, error = verify_witnessed_head(
        authority_path,
        witness_path,
        planes.witness_verifier,
        witnessed_ledger_id=LEDGER_ID,
        witness_ledger_attestation=retained,
    )
    assert not ok
    assert error is not None and error.startswith("witness ledger invalid: head attestation stale")


def test_witnessed_head_requires_a_witness_for_that_ledger_id(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 3)
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)

    ok, error = verify_witnessed_head(
        authority_path, witness_path, planes.witness_verifier, witnessed_ledger_id="other"
    )
    assert not ok
    assert error == "no valid head witness found for other"

    ok, error = verify_witnessed_head(
        authority_path, witness_path, planes.witness_verifier, witnessed_ledger_id=""
    )
    assert not ok
    assert error == "witnessed_ledger_id must be non-empty"


def test_witnessed_head_requires_an_attested_witness_ledger(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 3)
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)
    witness_path.with_suffix(".attest").unlink()

    ok, error = verify_witnessed_head(
        authority_path, witness_path, planes.witness_verifier, witnessed_ledger_id=LEDGER_ID
    )
    assert not ok
    assert error == "witness ledger invalid: head attestation missing"


def test_witnessed_head_ignores_witnesses_under_another_key(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 3)
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)

    _, other_public = generate_keypair()
    other = Ed25519HeadVerifier(public_key=other_public, trust_root_id="observatory-1")
    ok, error = verify_witnessed_head(
        authority_path, witness_path, other, witnessed_ledger_id=LEDGER_ID
    )
    assert not ok
    assert error is not None and "witness ledger invalid" in error


def test_witness_selection_uses_the_authenticated_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 1)
    authority_at_one = authority_path.read_bytes()
    witness_path = tmp_path / "witness.jsonl"
    _witness(planes, witness_path, authority_path)
    witness_at_one = witness_path.read_bytes()
    append(authority_path, score(2))
    _witness(planes, witness_path, authority_path)

    original_lines = verify_module._lines
    calls = 0

    def swapping_lines(files: list[Path], **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        yield from original_lines(files, **kwargs)
        if calls == 1:
            witness_path.write_bytes(witness_at_one)
            authority_path.write_bytes(authority_at_one)

    monkeypatch.setattr(verify_module, "_lines", swapping_lines)
    ok, error = verify_witnessed_head(
        authority_path,
        witness_path,
        planes.witness_verifier,
        witnessed_ledger_id=LEDGER_ID,
    )
    assert not ok
    assert error is not None and "rollback" in error.lower()


@pytest.mark.parametrize("reverse", [False, True], ids=["first_matches", "second_matches"])
def test_equal_sequence_conflicting_witnesses_fail_as_equivocation(
    tmp_path: Path, reverse: bool
) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 1)
    witness_path = tmp_path / "witness.jsonl"
    seq, head_hash = read_head(authority_path)
    matching = planes.witness_signer.sign_head(seq, head_hash, TS, ledger_id=LEDGER_ID)
    conflicting = planes.witness_signer.sign_head(seq, "f" * 64, TS, ledger_id=LEDGER_ID)
    attestations = [matching, conflicting]
    if reverse:
        attestations.reverse()
    for attestation in attestations:
        append(
            witness_path,
            {
                "record_type": "head_witness",
                "witnessed_ledger_id": LEDGER_ID,
                "attestation": attestation_block(attestation),
            },
        )
    attest_head(witness_path, planes.witness_signer, ledger_id="observatory-ledger")

    ok, error = verify_witnessed_head(
        authority_path,
        witness_path,
        planes.witness_verifier,
        witnessed_ledger_id=LEDGER_ID,
    )
    assert not ok
    assert error == f"witness equivocation at seq {seq}"


def test_intact_ledger_passes(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)

    ok, error = _verify(planes, authority_path, checkpoint)
    assert ok, error


def test_checkpoint_over_a_ledger_that_attested_its_own_head_passes(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    attest_head(authority_path, planes.authority_signer, ledger_id=LEDGER_ID)

    attestation = read_attestation(authority_path)
    assert attestation is not None
    witness_record = _witness(planes, tmp_path / "witness.jsonl", authority_path)
    block = attestation_block(attestation)
    checkpoint = {
        "seq": attestation.max_seq,
        "record_hash": attestation.head_record_hash,
        "attestation": block,
        "witness_record": witness_record,
        "countersignature": planes.countersigner.sign_countersignature(
            checkpoint_payload(
                seq=attestation.max_seq,
                record_hash=attestation.head_record_hash,
                attestation_hash=hash_object(block),
                witness_record_hash=str(witness_record["record_hash"]),
            )
        ),
    }

    ok, error = _verify(planes, authority_path, checkpoint)
    assert ok, error


def test_checkpoint_requires_one_signed_ledger_identity(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)
    attestation = planes.authority_signer.sign_head(
        checkpoint["seq"],
        checkpoint["record_hash"],
        TS,
        ledger_id="another-ledger",
    )
    authority_block = attestation_block(attestation)
    checkpoint["attestation"] = authority_block
    checkpoint["countersignature"] = planes.countersigner.sign_countersignature(
        checkpoint_payload(
            seq=checkpoint["seq"],
            record_hash=checkpoint["record_hash"],
            attestation_hash=hash_object(authority_block),
            witness_record_hash=checkpoint["witness_record"]["record_hash"],
        )
    )

    ok, error = _verify(planes, authority_path, checkpoint)
    assert not ok
    assert error == "checkpoint attestations name different ledgers"


@pytest.mark.parametrize(
    ("missing_identity", "expected_error"),
    [
        (
            "all",
            "checkpoint attestation ledger_id must be a non-empty string",
        ),
        (
            "authority",
            "checkpoint attestation ledger_id must be a non-empty string",
        ),
        (
            "witness_attestation",
            "checkpoint witness attestation ledger_id must be a non-empty string",
        ),
        (
            "witness_record",
            "checkpoint witness_record witnessed_ledger_id must be a non-empty string",
        ),
    ],
)
def test_checkpoint_requires_each_ledger_identity_even_when_signatures_are_valid(
    missing_identity: str, expected_error: str, tmp_path: Path
) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)

    if missing_identity in {"all", "authority"}:
        authority_attestation = planes.authority_signer.sign_head(
            checkpoint["seq"],
            checkpoint["record_hash"],
            TS,
            ledger_id=None,
        )
        checkpoint["attestation"] = attestation_block(authority_attestation)

    witness_record = checkpoint["witness_record"]
    if missing_identity in {"all", "witness_attestation"}:
        witness_attestation = planes.witness_signer.sign_head(
            checkpoint["seq"],
            checkpoint["record_hash"],
            TS,
            ledger_id=None,
        )
        witness_record["attestation"] = attestation_block(witness_attestation)
    if missing_identity in {"all", "witness_record"}:
        witness_record.pop("witnessed_ledger_id")
    witness_unsigned = {key: value for key, value in witness_record.items() if key != "record_hash"}
    witness_record["record_hash"] = hash_object(witness_unsigned)

    checkpoint["countersignature"] = planes.countersigner.sign_countersignature(
        checkpoint_payload(
            seq=checkpoint["seq"],
            record_hash=checkpoint["record_hash"],
            attestation_hash=hash_object(checkpoint["attestation"]),
            witness_record_hash=checkpoint["witness_record"]["record_hash"],
        )
    )

    assert _verify(planes, authority_path, checkpoint) == (False, expected_error)


def test_appended_only_ledger_passes(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)

    append(authority_path, score(6))
    append(authority_path, score(7))

    ok, error = _verify(planes, authority_path, checkpoint)
    assert ok, error


def test_truncated_ledger_fails(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)

    truncate(authority_path, 3)

    ok, error = _verify(planes, authority_path, checkpoint)
    assert not ok
    assert error is not None and "truncat" in error.lower()


def test_rolled_back_and_re_appended_ledger_fails(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)

    truncate(authority_path, 3)
    for i in range(90, 94):
        append(authority_path, score(i))

    ok, error = _verify(planes, authority_path, checkpoint)
    assert not ok
    assert error is not None and "rollback" in error.lower()


def test_witnessed_head_alone_accepts_the_rolled_back_ledger(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    witness_path = tmp_path / "witness.jsonl"
    checkpoint = _checkpoint(planes, witness_path, authority_path)

    truncate(authority_path, 3)
    for i in range(90, 94):
        append(authority_path, score(i))
    _witness(planes, witness_path, authority_path)

    witnessed_ok, witnessed_error = verify_witnessed_head(
        authority_path,
        witness_path,
        planes.witness_verifier,
        witnessed_ledger_id=LEDGER_ID,
    )
    assert witnessed_ok, witnessed_error

    ok, error = _verify(planes, authority_path, checkpoint)
    assert not ok
    assert error is not None and "rollback" in error.lower()


def test_forged_record_at_the_checkpoint_seq_fails(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)

    truncate(authority_path, 4)
    append(authority_path, score(99))

    ok, error = _verify(planes, authority_path, checkpoint)
    assert not ok
    assert error is not None and "rollback" in error.lower()


def test_broken_chain_fails(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)

    lines = authority_path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("agent-2", "agent-x")
    authority_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, error = _verify(planes, authority_path, checkpoint)
    assert not ok
    assert error is not None and "ledger invalid" in error.lower()


def test_missing_ledger_fails(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)

    ok, error = _verify(planes, tmp_path / "absent.jsonl", checkpoint)
    assert not ok
    assert error is not None


def test_wrong_witness_key_fails(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)

    _, other_public = generate_keypair()
    ok, error = verify_checkpoint(
        authority_path,
        checkpoint,
        witness_verifier=Ed25519HeadVerifier(
            public_key=other_public, trust_root_id="observatory-1"
        ),
        countersign_verifier=planes.countersign_verifier,
        authority_verifier=planes.authority_verifier,
    )
    assert not ok
    assert error is not None and "witness" in error.lower()


def test_wrong_countersign_key_fails(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)

    _, other_public = generate_keypair()
    ok, error = verify_checkpoint(
        authority_path,
        checkpoint,
        witness_verifier=planes.witness_verifier,
        countersign_verifier=Ed25519CountersignVerifier(public_key=other_public),
        authority_verifier=planes.authority_verifier,
    )
    assert not ok
    assert error is not None and "countersignature" in error.lower()


def test_wrong_authority_key_fails(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)

    _, other_public = generate_keypair()
    ok, error = verify_checkpoint(
        authority_path,
        checkpoint,
        witness_verifier=planes.witness_verifier,
        countersign_verifier=planes.countersign_verifier,
        authority_verifier=Ed25519HeadVerifier(
            public_key=other_public, trust_root_id="authority-1"
        ),
    )
    assert not ok
    assert error is not None and "attestation" in error.lower()


def test_authority_verifier_is_optional(tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)

    ok, error = verify_checkpoint(
        authority_path,
        checkpoint,
        witness_verifier=planes.witness_verifier,
        countersign_verifier=planes.countersign_verifier,
    )
    assert ok, error


def _freeze_checkpoint_value(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_checkpoint_value(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_checkpoint_value(item) for item in value)
    return value


def test_recursively_immutable_checkpoint_verifies_without_exception(
    tmp_path: Path,
) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)
    witness_record = checkpoint["witness_record"]
    witness_record["metadata"] = [{"retained": True}, ["immutable"]]
    witness_unsigned = {key: value for key, value in witness_record.items() if key != "record_hash"}
    witness_record["record_hash"] = hash_object(witness_unsigned)
    checkpoint["countersignature"] = planes.countersigner.sign_countersignature(
        checkpoint_payload(
            seq=checkpoint["seq"],
            record_hash=checkpoint["record_hash"],
            attestation_hash=hash_object(checkpoint["attestation"]),
            witness_record_hash=witness_record["record_hash"],
        )
    )

    frozen = _freeze_checkpoint_value(checkpoint)

    assert _verify(planes, authority_path, frozen) == (True, None)


@pytest.mark.parametrize("invalid_value", ["unsupported", "cycle", "overdeep"])
def test_non_json_checkpoint_values_fail_closed(invalid_value: str, tmp_path: Path) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)
    if invalid_value == "unsupported":
        value: Any = object()
    elif invalid_value == "cycle":
        value = []
        value.append(value)
    else:
        value = None
        for _ in range(65):
            value = [value]
    checkpoint["witness_record"]["invalid"] = value

    ok, error = _verify(planes, authority_path, checkpoint)

    assert not ok
    assert error is not None and error.startswith("checkpoint is malformed")


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda cp: cp.update(seq=cp["seq"] - 1), id="seq"),
        pytest.param(lambda cp: cp.update(record_hash="f" * 64), id="record_hash"),
        pytest.param(
            lambda cp: cp["attestation"].update(signature="ed25519:AAAA"),
            id="attestation_signature",
        ),
        pytest.param(
            lambda cp: cp["attestation"].update(recorded_at="2026-01-01T00:00:00.000Z"),
            id="attestation_recorded_at",
        ),
        pytest.param(
            lambda cp: cp["attestation"].update(max_seq=cp["attestation"]["max_seq"] + 1),
            id="attestation_max_seq",
        ),
        pytest.param(
            lambda cp: cp["attestation"].update(head_record_hash="f" * 64),
            id="attestation_head_record_hash",
        ),
        pytest.param(
            lambda cp: cp["witness_record"]["attestation"].update(signature="ed25519:AAAA"),
            id="witness_signature",
        ),
        pytest.param(
            lambda cp: cp["witness_record"]["attestation"].update(head_record_hash="f" * 64),
            id="witness_head_record_hash",
        ),
        pytest.param(
            lambda cp: cp["witness_record"].update(witnessed_ledger_id="other"),
            id="witnessed_ledger_id",
        ),
        pytest.param(
            lambda cp: cp["witness_record"].update(record_hash="f" * 64),
            id="witness_record_hash",
        ),
        pytest.param(lambda cp: cp.update(countersignature="ed25519:AAAA"), id="countersignature"),
        pytest.param(lambda cp: cp.update(extra="x"), id="unknown_key"),
        pytest.param(lambda cp: cp.pop("attestation"), id="missing_attestation"),
        pytest.param(lambda cp: cp.pop("witness_record"), id="missing_witness_record"),
        pytest.param(lambda cp: cp.pop("countersignature"), id="missing_countersignature"),
        pytest.param(lambda cp: cp.pop("seq"), id="missing_seq"),
        pytest.param(lambda cp: cp.pop("record_hash"), id="missing_record_hash"),
        pytest.param(lambda cp: cp["attestation"].update(extra="x"), id="attestation_unknown_key"),
    ],
)
def test_every_tampered_field_is_refused(tmp_path: Path, mutate: Any) -> None:
    planes = _Planes()
    authority_path = _authority(tmp_path, 5)
    checkpoint = _checkpoint(planes, tmp_path / "witness.jsonl", authority_path)
    mutate(checkpoint)

    ok, error = _verify(planes, authority_path, checkpoint)
    assert not ok
    assert error is not None
