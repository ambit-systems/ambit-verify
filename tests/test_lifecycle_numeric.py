"""Replay held generic capacity from exact calls and independent quantity policy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ambit_verify import replay_execution_prefix, verify_execution_prefix
from ambit_verify.generic_quantities import generic_quantities
from test_lifecycle_prefix import context, rechain

FIXTURES = Path(__file__).with_name("fixtures") / "generic_numeric_v1"


def material(case="case-001"):
    data = json.loads((FIXTURES / f"{case}.json").read_text())
    return data["bundle"], data["context"]


@pytest.mark.parametrize("case", ["case-001", "case-002", "case-003", "case-004"])
def test_live_numeric_prefix_requires_independent_policy(case):
    bundle, trust = material(case)
    result = verify_execution_prefix(bundle, **trust)
    assert result.valid and result.coverage_complete, result.errors
    assert len(result.record_coverage) == len(bundle["records"])
    assert result.accounts
    assert all(account.committed_amount_scaled == "0" for account in result.accounts)
    if case == "case-002":
        assert result.all_operations_terminal
        assert all(account.pending_amount_scaled == "0" for account in result.accounts)
        assert sum(int(a.released_amount_scaled) for a in result.accounts) == 59
    else:
        assert not result.all_operations_terminal
        assert all(op.state == "fenced" for op in result.unresolved_operations)
        assert all(int(account.pending_amount_scaled) > 0 for account in result.accounts)
        if case == "case-003":
            assert sorted(int(a.pending_amount_scaled) for a in result.accounts) == [
                40,
                60,
                100,
                100,
            ]
    trust.pop("generic_quantity_policy")
    refused = verify_execution_prefix(bundle, **trust)
    assert not refused.valid and not refused.coverage_complete
    assert "independent policy" in refused.errors[0]


@pytest.mark.parametrize(
    "field,value",
    [("amount_scaled", "1"), ("scope_id", "forged"), ("window_epoch", "1900-01-01T00:00:00Z")],
)
def test_signed_account_cannot_change_even_with_rehashed_prefix(field, value):
    bundle, trust = material("case-003")
    records = bundle["records"][:1]
    records[0]["consumption"]["accounts"][0][field] = value
    result = replay_execution_prefix(
        rechain(records),
        **context(bundle, trust),
        generic_quantity_policy=trust["generic_quantity_policy"],
    )
    assert not result.valid
    assert any(
        "account" in error or "debit" in error or "bound" in error for error in result.errors
    ), result.errors


def test_changed_record_selector_cannot_replay_an_accepted_debit():
    bundle, trust = material("case-003")
    trust["generic_quantity_policy"]["records_field_by_action"]["send"] = "different_records"
    result = verify_execution_prefix(bundle, **trust)
    assert not result.valid
    assert "no independently derived quantity" in result.errors[0]


@pytest.mark.parametrize("status", ["released", "committed"])
def test_numeric_unknown_cannot_acquire_terminal_state(status):
    bundle, trust = material()
    records = bundle["records"]
    decision = records[0]
    fence = next(r for r in records if r.get("event") == "dispatch_fenced")
    records.append(
        {
            "record_type": "consumption",
            "profile": "canonical-operation/1",
            "event": "settlement",
            "operation": fence["operation"],
            "decision_hash": decision["record_hash"],
            "intent_hash": fence["intent_hash"],
            "status": status,
            "basis": "resource_receipt" if status == "committed" else "durable_no_dispatch",
            "resource_outcome": "forged" if status == "committed" else None,
            "evaluated_at": fence["evaluated_at"],
        }
    )
    result = replay_execution_prefix(
        rechain(records),
        **context(bundle, trust),
        generic_quantity_policy=trust["generic_quantity_policy"],
    )
    assert not result.valid
    assert "unsigned generic fence cannot establish a terminal" in result.errors[0]


def test_numeric_unknown_cannot_acquire_native_start():
    bundle, trust = material()
    records = bundle["records"]
    operation = records[0]["consumption"]["operation"]
    from ambit_verify.native_start import JOIN_FIELDS, digest, message, validate_start_record
    from ambit_verify.resource_protocol import dispatch_message, verify_dispatch
    from test_git_publication_profile import _token
    from test_native_start import _material

    authority, resource, request, _, record = _material()
    dispatch = verify_dispatch(
        record["dispatch_token"], public_key=authority.public_key().public_bytes_raw()
    )
    dispatch.update({name: operation[name] for name in ("domain_id", "operation_id")})
    token = _token(dispatch, dispatch_message(dispatch), authority)
    request["dispatch_token"] = token
    record.update(
        {name: dispatch[name] for name in JOIN_FIELDS},
        dispatch_token=token,
        dispatch_hash=digest(token),
        request_token=_token(request, message(request, grant=False), resource),
    )
    validate_start_record(record)  # The forgery has valid internal signatures and joins.
    records.append(record)
    result = replay_execution_prefix(
        rechain(records),
        **context(bundle, trust),
        generic_quantity_policy=trust["generic_quantity_policy"],
    )
    assert not result.valid
    assert "native_start_history_missing" in result.errors[0]


@pytest.mark.parametrize("amount", [0, 5, 2**64])
def test_custom_quantity_uses_installed_scale_and_exact_non_negative_integer(amount):
    policy = {
        "enabled": True,
        "argument_quantity_by_action": {
            "execute": {
                "argument": "tokens",
                "kind": "token_count",
                "unit": "count:tokens",
                "scale": 2,
            }
        },
    }
    assert generic_quantities(
        policy=policy,
        action_type="execute",
        action_boundary="tool_execution",
        arguments={"tokens": amount},
    ) == {("token_count", "count:tokens"): amount * 100}


@pytest.mark.parametrize("amount", [True, -1, 1.0, "1", None])
def test_custom_quantity_does_not_coerce_malformed_argument(amount):
    policy = {
        "enabled": True,
        "argument_quantity_by_action": {
            "execute": {
                "argument": "tokens",
                "kind": "token_count",
                "unit": "count:tokens",
                "scale": 0,
            }
        },
    }
    with pytest.raises(ValueError, match="non-negative integer"):
        generic_quantities(
            policy=policy,
            action_type="execute",
            action_boundary="tool_execution",
            arguments={"tokens": amount},
        )


@pytest.mark.parametrize(
    "policy",
    [
        None,
        {},
        {"enabled": False},
        {"enabled": 1},
        {"enabled": True, "unexpected": 1},
        {"enabled": True, "records_field_by_action": {"send": 1}},
        {
            "enabled": True,
            "argument_quantity_by_action": {
                "send": {"argument": "n", "kind": "payload_size", "unit": "bytes", "scale": 0}
            },
        },
    ],
)
def test_missing_or_malformed_policy_fails_closed(policy):
    with pytest.raises(ValueError, match="policy"):
        generic_quantities(
            policy=policy, action_type="send", action_boundary="network_egress", arguments={}
        )


def test_custom_quantity_scale_and_argument_are_independent_policy_inputs():
    bundle, trust = material("case-004")
    result = verify_execution_prefix(bundle, **trust)
    assert result.valid and result.coverage_complete, result.errors
    assert [account.pending_amount_scaled for account in result.accounts] == ["2000"]
    policy = trust["generic_quantity_policy"]["argument_quantity_by_action"]["send"]
    policy["scale"] = 0
    refused = verify_execution_prefix(bundle, **trust)
    assert not refused.valid
    assert "debit does not equal" in refused.errors[0]
    policy["scale"] = 2
    policy["argument"] = "other_amount"
    refused = verify_execution_prefix(bundle, **trust)
    assert not refused.valid
    assert "no independently derived quantity" in refused.errors[0]
