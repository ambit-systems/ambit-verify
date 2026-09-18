# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""The revocation-window check compares against the retained freshness instant.

The engine seals the decision instant (``at``) before it reads the revocation
store. The store read sets ``checked_at`` and evaluates freshness at the
moment of that read, retained as ``freshness_evaluated_at``. Because the read
happens after the seal, ``checked_at`` can land a few milliseconds after
``at``. The window check must compare against the retained freshness instant,
not the sealed instant, or a genuine receipt fails on millisecond ordering
alone.

These tests load a genuine receipt's signed revocation status (and a genuine
cumulative-status row) from the fixtures and edit only unsigned timestamp
fields in memory: ``checked_at`` is part of the signed attestation payload
and is left untouched; ``at`` is a caller-supplied argument, never signed;
``freshness_evaluated_at`` is carried alongside the signed fields but is not
itself signed.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

from ambit_verify.admission import _moment, _verify_cumulative_rows, _verify_revocation_status

_LIFECYCLE_FIXTURE = Path(__file__).with_name("fixtures") / "controlled_lifecycle_v6"
_CUMULATIVE_FIXTURE = Path(__file__).with_name("fixtures") / "controlled_cumulative_sibling_v6"


def _lifecycle_status() -> tuple[dict[str, Any], str, dict[str, str]]:
    bundle = json.loads((_LIFECYCLE_FIXTURE / "execution-bundle.json").read_text(encoding="utf-8"))
    record = bundle["records"][0]
    status = dict(record["delegation"]["revocation_status"])
    roots = {
        "demo-revocation-root": "5d3deb33c3fbe3f468e4818b6a89673d73de45dd5005132b8de615d4db4d9715"
    }
    return status, str(status["jti"]), roots


def test_genuine_status_passes_when_the_store_read_lands_after_the_sealed_instant() -> None:
    """A store read a millisecond after the seal must not fail a genuine receipt."""
    status, jti, roots = _lifecycle_status()
    checked_at = _moment(status["checked_at"])
    at = checked_at - timedelta(milliseconds=1)
    freshness_evaluated_at = at + timedelta(milliseconds=2)
    status["freshness_evaluated_at"] = freshness_evaluated_at.isoformat().replace("+00:00", "Z")

    result = _verify_revocation_status(
        status,
        jti=jti,
        roots=roots,
        at=at,
        admission_age_limit_ms=60000,
        grant_age_limit_ms=None,
        epoch_floor=0,
    )

    assert result is None


def test_genuine_parent_chain_jitter_before_the_sealed_instant_still_passes() -> None:
    """A parent-chain check read a millisecond before the leaf's seal must not fail either.

    Parent-chain revocation status is checked through the same helper as the leaf
    (``verify_execution_authority`` calls ``_verify_revocation_status`` once per
    parent, with the leaf's ``at``). Genuine bundles show this same read-around-the-
    seal jitter landing on either side of ``at`` for parent entries, by a few
    milliseconds -- see ``controlled_cumulative_sibling_v6``. Only a freshness
    instant older than the bound is a stale or replayed status, not jitter.
    """
    status, jti, roots = _lifecycle_status()
    checked_at = _moment(status["checked_at"])
    at = checked_at + timedelta(milliseconds=3)
    status["freshness_evaluated_at"] = (
        (at - timedelta(milliseconds=3)).isoformat().replace("+00:00", "Z")
    )

    result = _verify_revocation_status(
        status,
        jti=jti,
        roots=roots,
        at=at,
        admission_age_limit_ms=60000,
        grant_age_limit_ms=None,
        epoch_floor=0,
    )

    assert result is None


def test_freshness_evaluated_before_the_sealed_instant_is_refused() -> None:
    """A status evaluated well before the decision instant names the ordering it violates.

    A few milliseconds of read-before-seal jitter is genuine engine behaviour (the
    same jitter the defect report documents for parent-chain checks) and must pass.
    A freshness instant older than the bound itself is not jitter -- it is a stale
    or replayed status, and must be refused.
    """
    status, jti, roots = _lifecycle_status()
    checked_at = _moment(status["checked_at"])
    at = checked_at
    bound_ms = 60000
    status["freshness_evaluated_at"] = (
        (at - timedelta(milliseconds=bound_ms + 1)).isoformat().replace("+00:00", "Z")
    )

    result = _verify_revocation_status(
        status,
        jti=jti,
        roots=roots,
        at=at,
        admission_age_limit_ms=bound_ms,
        grant_age_limit_ms=None,
        epoch_floor=0,
    )

    assert result is not None
    assert "before" in result


def test_freshness_evaluated_beyond_the_bound_cannot_widen_the_window() -> None:
    """A forward-dated freshness instant cannot buy extra time past the bound."""
    status, jti, roots = _lifecycle_status()
    checked_at = _moment(status["checked_at"])
    at = checked_at
    bound_ms = 60000
    status["freshness_evaluated_at"] = (
        (at + timedelta(milliseconds=bound_ms + 1)).isoformat().replace("+00:00", "Z")
    )

    result = _verify_revocation_status(
        status,
        jti=jti,
        roots=roots,
        at=at,
        admission_age_limit_ms=bound_ms,
        grant_age_limit_ms=None,
        epoch_floor=0,
    )

    assert result is not None
    assert "does not cover" in result


def test_status_without_freshness_evaluated_at_still_uses_the_sealed_instant() -> None:
    """Absent the retained freshness instant, the check falls back to ``at`` unchanged."""
    status, jti, roots = _lifecycle_status()
    assert "freshness_evaluated_at" not in status
    checked_at = _moment(status["checked_at"])
    at = checked_at

    result = _verify_revocation_status(
        status,
        jti=jti,
        roots=roots,
        at=at,
        admission_age_limit_ms=60000,
        grant_age_limit_ms=None,
        epoch_floor=0,
    )

    assert result is None


def _cumulative_row() -> tuple[dict[str, Any], dict[str, str], list[dict[str, Any]]]:
    bundle = json.loads((_CUMULATIVE_FIXTURE / "execution-bundle.json").read_text(encoding="utf-8"))
    row = None
    for record in bundle["records"]:
        evidence = record.get("evidence") if isinstance(record, dict) else None
        if isinstance(evidence, dict) and evidence.get("cumulative_status"):
            row = dict(evidence["cumulative_status"][0])
            break
    assert row is not None
    roots = {"slice-cumulative": "4050b655617ba5386cb4c5a0d36dac3dca210b178043865785f84179e794449d"}
    bounds = [
        {
            "kind": row["kind"],
            "unit": row["unit"],
            "window_duration_ms": row["window_duration_ms"],
            "aggregation": None,
        }
    ]
    return row, roots, bounds


def test_cumulative_row_passes_when_the_store_read_lands_after_the_sealed_instant() -> None:
    """The sibling cumulative-status check applies the same retained-instant rule."""
    row, roots, bounds = _cumulative_row()
    checked_at = _moment(row["signed_payload"]["checked_at"])
    at = checked_at - timedelta(milliseconds=1)
    assert _moment(row["freshness_evaluated_at"]) >= at

    result = _verify_cumulative_rows(
        [row],
        jti=str(row["jti"]),
        roots=roots,
        at=at,
        age_limit_ms=30000,
        expected_bounds=bounds,
        authority_entry_hash=None,
    )

    assert result is None
