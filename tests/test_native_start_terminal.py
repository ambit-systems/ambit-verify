# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

import pytest

from ambit_verify.native_start import validate_terminal_start, validate_terminal_start_record
from ambit_verify.resource_protocol import outcome_message
from test_git_publication_profile import _outcome, _token
from test_native_start import _material


@pytest.mark.parametrize("status", ["committed", "not_executed", "unknown"])
def test_terminal_preserves_native_start_time_or_null_status_semantics(status):
    _authority, resource, _request, _request_token, start = _material()
    outcome = _outcome(status)
    if status == "committed":
        outcome["accepted_at"] = start["accepted_at"]
    validate_terminal_start(outcome, [start])
    validate_terminal_start_record(
        {
            "record_type": "consumption",
            "event": "settlement",
            "operation": {name: start[name] for name in ("domain_id", "operation_id")},
            "resource_outcome": _token(outcome, outcome_message(outcome), resource),
        },
        [start],
    )


def test_changed_acceptance_time_fails_even_inside_dispatch_interval():
    _authority, resource, _request, _request_token, start = _material()
    outcome = _outcome("committed")
    assert outcome["accepted_at"] != start["accepted_at"]
    with pytest.raises(ValueError, match="native_start_terminal_acceptance_mismatch"):
        validate_terminal_start(outcome, [start])
    with pytest.raises(ValueError, match="native_start_terminal_acceptance_mismatch"):
        validate_terminal_start_record(
            {
                "record_type": "consumption",
                "event": "settlement",
                "operation": {name: start[name] for name in ("domain_id", "operation_id")},
                "resource_outcome": _token(outcome, outcome_message(outcome), resource),
            },
            [start],
        )


def test_historical_terminal_without_native_start_keeps_existing_contract():
    *_unused, start = _material()
    outcome = _outcome("committed")
    validate_terminal_start(outcome, [])
    validate_terminal_start(outcome, [{**start, "domain_id": "another-domain"}])


def test_terminal_cannot_substitute_another_action_under_the_started_identity():
    *_unused, start = _material()
    outcome = {
        **_outcome("committed"),
        "accepted_at": start["accepted_at"],
        "payload_hash": "b" * 64,
    }
    with pytest.raises(ValueError, match="native_start_terminal_operation_mismatch"):
        validate_terminal_start(outcome, [start])
