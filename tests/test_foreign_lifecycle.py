"""A foreign request may escalate before it acquires consumable authority."""

import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path

import pytest

from ambit_verify.admission import verify_authority_admission, verify_foreign_dispatch


def material():
    data = json.loads(
        (Path(__file__).with_name("fixtures") / "foreign_lifecycle_v1.json").read_text()
    )
    record = data["bundle"]["records"][0]
    block = record["evidence"]["authority_admission"]
    at = datetime.fromisoformat(record["evaluated_at"].replace("Z", "+00:00"))
    result = verify_authority_admission(
        block["artifact"],
        admission_trust_roots=data["context"]["admission_trust_roots_by_adapter"]["http"],
        expected_domain="http",
        expected_ledger_id="slice",
        at=at,
    )
    assert result.valid and result.admission is not None
    return record, result.admission, at


def test_exact_foreign_escalation_authenticates_without_consuming_authority():
    record, admission, at = material()
    assert record["decision"] == "ESCALATE" and "consumption" not in record
    result = verify_foreign_dispatch(record, admission=admission, at=at)
    assert result.valid, result.errors


@pytest.mark.parametrize("fault", ["allow", "malformed", "actor", "payload", "mixed"])
def test_nonconsequential_foreign_identity_does_not_weaken_execution(fault):
    original, admission, at = material()
    record = deepcopy(original)
    if fault == "allow":
        record["decision"] = "ALLOW"
    elif fault == "malformed":
        record["consumption"] = {}
    elif fault == "actor":
        record["actor_id"] = "another-actor"
    elif fault == "payload":
        record["evidence"]["request_envelope"]["call"]["arguments"]["customer_id"] = "changed"
    elif fault == "mixed":
        record["evidence"]["actor_proof"] = {"scheme": "p256"}
    result = verify_foreign_dispatch(record, admission=admission, at=at)
    assert not result.valid
    assert result.errors == (
        "foreign dispatch evidence is not admitted"
        if fault == "mixed"
        else "foreign dispatch does not bind B's canonical request",
    )
