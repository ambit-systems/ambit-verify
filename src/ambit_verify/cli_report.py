# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Per-claim report for the ``ambit-verify`` command (``--report json``)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NamedTuple

CLAIMS = ("record_hashes", "chain", "head_attestation", "witness", "checkpoint")

PASS = "pass"
FAIL = "fail"
NOT_CHECKED = "not_checked"


class ClaimOutcome(NamedTuple):
    """The outcome of one claim.

    Attributes:
        result: ``"pass"``, ``"fail"`` or ``"not_checked"``.
        detail: The failure reason, or the reason the claim did not run. None otherwise.
    """

    result: str
    detail: str | None = None


def build_report(ledger: str, outcomes: Mapping[str, ClaimOutcome]) -> dict[str, Any]:
    """Build the JSON report object from the outcome of each claim.

    Args:
        ledger: The ledger path as given on the command line.
        outcomes: Outcome per claim name. A claim missing from the mapping is
            reported as ``not_checked`` with no detail.

    Returns:
        A dict with ``ledger``, ``result`` and ``claims``. ``result`` is ``"pass"``
        when no claim failed. ``claims`` follows the order of ``CLAIMS``.
    """
    claims = []
    for name in CLAIMS:
        outcome = outcomes.get(name, ClaimOutcome(NOT_CHECKED))
        claims.append({"claim": name, "result": outcome.result, "detail": outcome.detail})
    failed = any(claim["result"] == FAIL for claim in claims)
    return {"ledger": ledger, "result": FAIL if failed else PASS, "claims": claims}
