"""Adversarial verification of signed behavioural statements and retained source history."""

import base64
import copy
import json
from dataclasses import asdict

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ambit_verify.behavioural import (
    MAX_SNAPSHOT_BYTES,
    SCHEMA,
    SIGNING_DOMAIN,
    BehaviouralVerificationError,
    VerifiedBehaviouralSnapshot,
    parse_behavioural_snapshot,
    snapshot_bytes,
    verify_behavioural_snapshot,
)
from ambit_verify.hashing import canonical_json_bytes, hash_object
from ambit_verify.head_attestation import HeadAttestation, attestation_payload

NOW = 1_700_000_000_000
STAMP = "2023-11-14T22:13:20+00:00"


@pytest.fixture
def case():
    observer = Ed25519PrivateKey.generate()
    writer = Ed25519PrivateKey.generate()
    record = {
        "record_type": "decision",
        "seq": 1,
        "prev_hash": "0" * 64,
        "actor_id": "agent",
        "decision": "ALLOW",
        "timestamp_utc": STAMP,
        "action": {"type": "read", "boundary": "tool_execution"},
    }
    record["record_hash"] = hash_object(record)
    head = HeadAttestation(
        1,
        record["record_hash"],
        STAMP,
        "writer",
        "ed25519:"
        + base64.b64encode(
            writer.sign(
                attestation_payload(
                    1,
                    record["record_hash"],
                    STAMP,
                    "writer",
                    "decisions",
                )
            )
        ).decode(),
        "decisions",
    )
    config = {"model_version": "1.0.0"}
    payload = {
        "schema": SCHEMA,
        "issuer": "observer",
        "actor_id": "agent",
        "domain": "organisation",
        "audience": "valve",
        "issued_at_ms": NOW,
        "expires_at_ms": NOW + 60_000,
        "source": {"head": asdict(head)},
        "model_config": config,
        "result": {
            "score": 0.9,
            "score_band": "critical",
            "confidence_band": "low",
            "observation_count": 1,
            "posterior_state": {
                "actor_id": "agent",
                "observation_count": 1,
            },
        },
    }
    trust = {
        "source_records": [record],
        "observer_public_keys": {"observer": observer.public_key().public_bytes_raw().hex()},
        "source_public_keys": {"writer": writer.public_key().public_bytes_raw().hex()},
        "expected_actor": "agent",
        "expected_domain": "organisation",
        "expected_audience": "valve",
        "expected_source_ledger": "decisions",
        "expected_model_config_hash": hash_object(config),
        "evaluation_time_ms": NOW,
        "max_age_ms": 60_000,
    }
    return payload, observer, trust


def signed(payload, key):
    return snapshot_bytes(
        {
            "payload": payload,
            "signature": base64.b64encode(
                key.sign(SIGNING_DOMAIN + canonical_json_bytes(payload))
            ).decode(),
        }
    )


@pytest.mark.parametrize("count", [True, False, 1.0, "1", None, []])
def test_posterior_count_is_a_strict_integer(case, count):
    payload, key, trust = case
    payload["result"]["posterior_state"]["observation_count"] = count
    with pytest.raises(BehaviouralVerificationError, match="posterior identity"):
        verify_behavioural_snapshot(signed(payload, key), **trust)


def test_raw_bytes_cannot_construct_a_verified_snapshot():
    with pytest.raises(TypeError, match="authenticate_behavioural_snapshot"):
        VerifiedBehaviouralSnapshot(b'{"score":0}')


def test_valid_detached_snapshot(case):
    payload, key, trust = case
    verified = verify_behavioural_snapshot(signed(payload, key), **trust)
    changed = verified.payload
    changed["result"]["score_band"] = "normal"
    assert verified.payload["result"]["score_band"] == "critical"
    assert verified.digest == hash_object(verified.snapshot)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "other"),
        ("actor_id", "other"),
        ("domain", "other"),
        ("audience", "other"),
        ("issuer", "other"),
        ("issued_at_ms", NOW + 1),
        ("expires_at_ms", NOW),
        ("expires_at_ms", NOW + 60_001),
        ("issued_at_ms", True),
    ],
)
def test_wrong_binding_or_time_even_when_signed(case, field, value):
    payload, key, trust = case
    payload[field] = value
    with pytest.raises(BehaviouralVerificationError):
        verify_behavioural_snapshot(signed(payload, key), **trust)


@pytest.mark.parametrize("which", ["observer_public_keys", "source_public_keys"])
def test_wrong_trusted_key(case, which):
    payload, key, trust = case
    trust[which] = {
        next(iter(trust[which])): Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    }
    with pytest.raises(BehaviouralVerificationError):
        verify_behavioural_snapshot(signed(payload, key), **trust)


def test_modified_statement_and_wrong_signing_domain(case):
    payload, key, trust = case
    document = parse_behavioural_snapshot(signed(payload, key))
    document["payload"]["result"]["score"] = 0.1
    with pytest.raises(BehaviouralVerificationError):
        verify_behavioural_snapshot(snapshot_bytes(document), **trust)
    document["signature"] = base64.b64encode(key.sign(canonical_json_bytes(payload))).decode()
    with pytest.raises(BehaviouralVerificationError):
        verify_behavioural_snapshot(snapshot_bytes(document), **trust)


@pytest.mark.parametrize(
    "mutation", ["drop", "duplicate", "replace", "wrong_ledger", "bad_head", "config"]
)
def test_source_and_config_substitution(case, mutation):
    payload, key, trust = case
    source = payload["source"]
    if mutation == "drop":
        trust["source_records"] = []
    elif mutation == "duplicate":
        trust["source_records"] *= 2
    elif mutation == "replace":
        record = trust["source_records"][0]
        record["decision"] = "DENY"
        record.pop("record_hash")
        record["record_hash"] = hash_object(record)
    elif mutation == "wrong_ledger":
        source["head"]["ledger_id"] = "other"
    elif mutation == "bad_head":
        source["head"]["max_seq"] = True
    else:
        payload["model_config"]["model_version"] = "other"
    with pytest.raises(BehaviouralVerificationError):
        verify_behavioural_snapshot(signed(payload, key), **trust)


@pytest.mark.parametrize(
    "data",
    [
        b'{"payload":{},"payload":{},"signature":"x"}',
        b'{"payload":NaN,"signature":"x"}',
        b"\xff",
        b"{}",
        b" " * (MAX_SNAPSHOT_BYTES + 1),
        b"[" * 2000 + b"]" * 2000,
    ],
)
def test_hostile_parser(data):
    with pytest.raises(BehaviouralVerificationError):
        parse_behavioural_snapshot(data)


def test_stale_reissued_source(case):
    payload, key, trust = case
    trust["evaluation_time_ms"] = NOW + 70_000
    payload["issued_at_ms"] = NOW + 70_000
    payload["expires_at_ms"] = NOW + 100_000
    with pytest.raises(BehaviouralVerificationError, match="source: stale"):
        verify_behavioural_snapshot(signed(payload, key), **trust)


def test_unknown_fields_and_nonfinite_mapping(case):
    payload, key, trust = case
    payload["extra"] = True
    with pytest.raises(BehaviouralVerificationError):
        verify_behavioural_snapshot(signed(payload, key), **trust)
    document = {"payload": copy.deepcopy(payload), "signature": "x"}
    document["payload"]["result"]["score"] = float("inf")
    with pytest.raises(BehaviouralVerificationError):
        snapshot_bytes(document)
    assert json.dumps({"ok": True})
