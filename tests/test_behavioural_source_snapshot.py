"""A checked source record must not be replaced before observation attribution."""

import pytest

from ambit_verify import behavioural
from ambit_verify.behavioural import BehaviouralVerificationError
from test_behavioural import signed

pytest_plugins = ["test_behavioural"]


def test_mutation_after_hash_check_cannot_substitute_source_actor(case, monkeypatch):
    payload, key, trust = case
    # The writer signed a source observation for agent, not for replacement.
    # A valid observer signature must not relabel that source observation.
    payload["actor_id"] = "replacement"
    payload["result"]["posterior_state"]["actor_id"] = "replacement"
    trust["expected_actor"] = "replacement"
    original_check = behavioural._check_record

    def check_then_replace(*args, **kwargs):
        checked = original_check(*args, **kwargs)
        assert checked.error is None
        trust["source_records"][0]["actor_id"] = "replacement"
        return checked

    monkeypatch.setattr(behavioural, "_check_record", check_then_replace)
    with pytest.raises(BehaviouralVerificationError, match="source observation count mismatch"):
        behavioural.verify_behavioural_snapshot(signed(payload, key), **trust)
