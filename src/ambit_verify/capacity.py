# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Recompute cumulative capacity per window from the records of one ledger.

The recomputation reads only the ledger. The ceiling and the amount of each
account row are as the ledger states them. They are not checked against
signed credentials. A settlement settles all reservations of its operation in
full. The ledger carries no partial settlement.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

PASS = "pass"
FAIL = "fail"
NOT_CHECKED = "not_checked"

NO_ACCOUNTS_DETAIL = "ledger carries no cumulative account records"

_AUTHORIZED = "authorized"
_COMMITTED = "committed"
_RELEASED = "released"

WindowKey = tuple[str, str | None, str, str, str, int]


@dataclass(frozen=True, slots=True)
class CapacityAccount:
    """Recomputed totals of one window. Amounts are integer strings (``amount_scaled``)."""

    scope_id: str
    scope: str | None
    kind: str
    unit: str
    window_epoch: str
    window_duration_ms: int
    ceiling_amount_scaled: str
    committed_amount_scaled: str
    held_amount_scaled: str
    released_amount_scaled: str

    @property
    def key(self) -> WindowKey:
        """Return the window key."""
        return (
            self.scope_id,
            self.scope,
            self.kind,
            self.unit,
            self.window_epoch,
            self.window_duration_ms,
        )

    def as_dict(self) -> dict[str, Any]:
        """Return the account as a JSON-ready mapping."""
        return {
            "scope_id": self.scope_id,
            "scope": self.scope,
            "kind": self.kind,
            "unit": self.unit,
            "window_epoch": self.window_epoch,
            "window_duration_ms": self.window_duration_ms,
            "ceiling_amount_scaled": self.ceiling_amount_scaled,
            "committed_amount_scaled": self.committed_amount_scaled,
            "held_amount_scaled": self.held_amount_scaled,
            "released_amount_scaled": self.released_amount_scaled,
        }


@dataclass(frozen=True, slots=True)
class CapacityResult:
    """Outcome of ``recompute_capacity``.

    Attributes:
        result: ``"pass"``, ``"fail"`` or ``"not_checked"``.
        accounts: Totals per window, in order of first charge. Empty unless the
            result is ``"pass"``.
        detail: The failure reason or the reason nothing was checked. None on a pass.
        window: The window key of the first offending record, when one applies.
        seq: The ``seq`` of the first offending record, when one applies.
    """

    result: str
    accounts: tuple[CapacityAccount, ...] = ()
    detail: str | None = None
    window: WindowKey | None = None
    seq: int | None = None


class _CapacityError(Exception):
    def __init__(self, reason: str, *, seq: object, window: WindowKey | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.seq = seq if type(seq) is int else None
        self.window = window


@dataclass(slots=True)
class _Window:
    ceiling: int
    committed: int = 0
    held: int = 0
    released: int = 0


@dataclass(slots=True)
class _Reservation:
    key: WindowKey
    amount: int
    state: str


def _window_key(row: Mapping[str, Any], seq: object) -> WindowKey:
    scope = row.get("scope")
    scope_id = row.get("jti") if scope is None else row.get("scope_id")
    duration = row.get("window_duration_ms")
    texts = (scope_id, row.get("kind"), row.get("unit"), row.get("window_epoch"))
    if (
        not all(isinstance(text, str) and text for text in texts)
        or not (scope is None or isinstance(scope, str))
        or type(duration) is not int
    ):
        raise _CapacityError("account row has a malformed window key", seq=seq)
    return (
        str(scope_id),
        scope,
        str(row["kind"]),
        str(row["unit"]),
        str(row["window_epoch"]),
        duration,
    )


def _integer(value: object, *, what: str, seq: object, window: WindowKey | None) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise _CapacityError(f"account row {what} is not an integer string", seq=seq, window=window)
    return int(value)


def _operation_key(operation: object, seq: object) -> tuple[str, str]:
    if isinstance(operation, Mapping):
        domain, operation_id = operation.get("domain_id"), operation.get("operation_id")
        if isinstance(domain, str) and isinstance(operation_id, str) and operation_id:
            return domain, operation_id
    raise _CapacityError("record carries no operation identity", seq=seq)


def _describe(key: WindowKey) -> str:
    scope_id, scope, kind, unit, epoch, duration = key
    return f"window {scope_id!r} (scope {scope!r}, {kind}, {unit}, epoch {epoch}, {duration} ms)"


def _charge(
    row: Mapping[str, Any],
    seq: object,
    windows: dict[WindowKey, _Window],
    reservations: dict[str, _Reservation],
) -> str:
    key = _window_key(row, seq)
    ceiling = _integer(row.get("ceiling_amount_scaled"), what="ceiling", seq=seq, window=key)
    amount = _integer(row.get("amount_scaled"), what="amount", seq=seq, window=key)
    reservation_id = row.get("reservation_id")
    if not isinstance(reservation_id, str) or not reservation_id:
        raise _CapacityError(f"{_describe(key)}: reservation_id is missing", seq=seq, window=key)
    if reservation_id in reservations:
        raise _CapacityError(
            f"{_describe(key)}: reservation_id {reservation_id} is repeated", seq=seq, window=key
        )
    window = windows.get(key)
    if window is None:
        window = windows[key] = _Window(ceiling)
    elif window.ceiling != ceiling:
        raise _CapacityError(
            f"{_describe(key)}: the ceiling changes inside the window", seq=seq, window=key
        )
    if window.committed + window.held + amount > window.ceiling:
        raise _CapacityError(
            f"{_describe(key)}: committed and held amounts exceed the ceiling", seq=seq, window=key
        )
    window.held += amount
    reservations[reservation_id] = _Reservation(key, amount, _AUTHORIZED)
    return reservation_id


def _settle(
    record: Mapping[str, Any],
    operations: dict[tuple[str, str], list[str]],
    settled: set[tuple[str, str]],
    reservations: dict[str, _Reservation],
    windows: dict[WindowKey, _Window],
) -> None:
    seq = record.get("seq")
    operation = _operation_key(record.get("operation"), seq)
    if operation not in operations:
        raise _CapacityError(
            f"settlement for operation {operation[1]!r} has no authorized decision", seq=seq
        )
    if operation in settled:
        raise _CapacityError(f"operation {operation[1]!r} has a second settlement", seq=seq)
    status = record.get("status")
    if status not in (_COMMITTED, _RELEASED):
        raise _CapacityError(
            f"settlement of operation {operation[1]!r} has an unknown status", seq=seq
        )
    settled.add(operation)
    for reservation_id in operations[operation]:
        reservation = reservations[reservation_id]
        window = windows[reservation.key]
        window.held -= reservation.amount
        if status == _COMMITTED:
            window.committed += reservation.amount
        else:
            window.released += reservation.amount
        reservation.state = status


def recompute_capacity(records: Sequence[Mapping[str, Any]]) -> CapacityResult:
    """Recompute committed, held and released capacity per window from ledger records.

    An authorized ``decision`` record charges each row of ``consumption.accounts``
    to its window. A ``consumption`` record with event ``settlement`` commits or
    releases every reservation of its operation in full. The function does not
    read credentials and does not convert amounts. It treats the ceiling and
    amount of each row as the ledger states them.

    Args:
        records: Ledger records in order. The caller must have verified the hash chain.

    Returns:
        ``not_checked`` when no authorized decision carries account rows. ``fail``
        with the window key and ``seq`` of the first offending record when a
        reservation id repeats, a ceiling changes inside a window, committed plus
        held exceeds the ceiling, an operation settles twice, or a settlement has
        no authorized decision. ``pass`` with totals per window otherwise.
    """
    if not any(_carries_accounts(record) for record in records):
        return CapacityResult(NOT_CHECKED, detail=NO_ACCOUNTS_DETAIL)
    windows: dict[WindowKey, _Window] = {}
    reservations: dict[str, _Reservation] = {}
    operations: dict[tuple[str, str], list[str]] = {}
    settled: set[tuple[str, str]] = set()
    try:
        for record in records:
            if not isinstance(record, Mapping):
                continue
            consumption = record.get("consumption")
            if record.get("record_type") == "decision" and isinstance(consumption, Mapping):
                if consumption.get("state") != _AUTHORIZED:
                    continue
                seq = record.get("seq")
                operation = _operation_key(consumption.get("operation"), seq)
                held = operations.setdefault(operation, [])
                rows = consumption.get("accounts")
                for row in rows if isinstance(rows, list) else []:
                    if not isinstance(row, Mapping):
                        raise _CapacityError("account row is not an object", seq=seq)
                    held.append(_charge(row, seq, windows, reservations))
            elif record.get("record_type") == "consumption" and record.get("event") == "settlement":
                _settle(record, operations, settled, reservations, windows)
    except _CapacityError as failure:
        where = f" at seq {failure.seq}" if failure.seq is not None else ""
        return CapacityResult(
            FAIL, detail=f"{failure.reason}{where}", window=failure.window, seq=failure.seq
        )
    accounts = tuple(
        CapacityAccount(
            *key,
            str(window.ceiling),
            str(window.committed),
            str(window.held),
            str(window.released),
        )
        for key, window in windows.items()
    )
    return CapacityResult(PASS, accounts=accounts)


def cross_check_with_replay(
    records: Sequence[Mapping[str, Any]],
    accounts: Sequence[CapacityAccount],
    *,
    admission_trust_roots_by_adapter: Mapping[str, Mapping[str, Any]],
    generic_quantity_policy: Mapping[str, Any],
    enforcement_point_public_key: str,
) -> str | None:
    """Compare the totals with a lifecycle replay that checks bounds and quantities.

    The replay takes the domain, the ledger id and the enforcement point id from
    the operation descriptor of the first authorized decision.

    Returns:
        None when the replay is valid and its account totals equal ``accounts``.
        Otherwise the reason they differ or the reason the replay failed.
    """
    from .lifecycle import replay_execution_prefix

    descriptor = next(
        (record["consumption"]["operation"] for record in records if _carries_accounts(record)),
        None,
    )
    names = ("domain_id", "ledger_id", "enforcement_point_id")
    if not isinstance(descriptor, Mapping) or not all(
        isinstance(descriptor.get(name), str) for name in names
    ):
        return "the operation descriptor lacks domain, ledger or enforcement point id"
    replay = replay_execution_prefix(
        list(records),
        admission_trust_roots_by_adapter=admission_trust_roots_by_adapter,
        expected_domain=descriptor["domain_id"],
        expected_ledger_id=descriptor["ledger_id"],
        enforcement_point_id=descriptor["enforcement_point_id"],
        enforcement_point_public_key=enforcement_point_public_key,
        generic_quantity_policy=generic_quantity_policy,
    )
    if not replay.valid:
        return f"lifecycle replay failed: {replay.errors[0] if replay.errors else 'invalid'}"
    replayed = {
        (a.scope_id, a.scope, a.kind, a.unit, a.window_epoch, a.window_duration_ms): (
            a.ceiling_amount_scaled,
            a.committed_amount_scaled,
            a.pending_amount_scaled,
            a.released_amount_scaled,
        )
        for a in replay.accounts
    }
    recomputed = {
        account.key: (
            account.ceiling_amount_scaled,
            account.committed_amount_scaled,
            account.held_amount_scaled,
            account.released_amount_scaled,
        )
        for account in accounts
    }
    if replayed != recomputed:
        return "lifecycle replay totals differ from the recomputed totals"
    return None


def _carries_accounts(record: object) -> bool:
    if not isinstance(record, Mapping) or record.get("record_type") != "decision":
        return False
    consumption = record.get("consumption")
    return (
        isinstance(consumption, Mapping)
        and consumption.get("state") == _AUTHORIZED
        and bool(consumption.get("accounts"))
    )
