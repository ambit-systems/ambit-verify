# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Immutable results for an independently checked canonical lifecycle prefix."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .issuance_replay import IssuanceReplayState

LIFECYCLE_PROFILE = "canonical-lifecycle/1"


@dataclass(frozen=True, slots=True)
class RecordCoverage:
    """State which semantics were checked for one retained record."""

    seq: int
    record_type: str
    event: str | None
    status: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class OperationReplayState:
    """Exact identity, evidence links, and state of one operation."""

    domain_id: str
    operation_id: str
    descriptor: Mapping[str, str]
    actor_id: str
    state: str
    decision_hash: str
    intent_hash: str | None
    dispatch_record_hash: str | None
    dispatch_token_hash: str | None
    start_hash: str | None
    transport_hashes: tuple[str, ...]
    settlement_hash: str | None
    reservation_ids: tuple[str, ...]

    @property
    def terminal(self) -> bool:
        """Whether the retained operation has a permitted terminal state."""
        return self.state in {"refused", "released", "committed"}


@dataclass(frozen=True, slots=True)
class AccountReplayState:
    """Capacity charged by pending and committed reservations in one period."""

    scope_id: str
    scope: str | None
    kind: str
    unit: str
    window_epoch: str
    window_duration_ms: int
    ceiling_amount_scaled: str
    pending_amount_scaled: str
    committed_amount_scaled: str
    released_amount_scaled: str

    @property
    def charged_amount_scaled(self) -> str:
        """Return pending plus committed capacity; release never counts as spending."""
        return str(int(self.pending_amount_scaled) + int(self.committed_amount_scaled))


@dataclass(frozen=True, slots=True)
class ConsumedIdentifierState:
    """The last retained consumption of an identifier and its expiry."""

    namespace: str
    identifier: str
    expires_at: str


@dataclass(frozen=True, slots=True)
class ExecutionPrefixVerification:
    """Separate valid prefix semantics, record coverage, and terminal progress."""

    valid: bool
    coverage_complete: bool
    record_coverage: tuple[RecordCoverage, ...] = ()
    operations: tuple[OperationReplayState, ...] = ()
    accounts: tuple[AccountReplayState, ...] = ()
    consumed_identifiers: tuple[ConsumedIdentifierState, ...] = ()
    issuances: tuple[IssuanceReplayState, ...] = ()
    errors: tuple[str, ...] = ()
    profile: str = LIFECYCLE_PROFILE
    external_history_completeness: str = "not_established"

    @property
    def all_operations_terminal(self) -> bool:
        """Report progress separately from the validity of an unresolved prefix."""
        return self.valid and self.coverage_complete and all(op.terminal for op in self.operations)

    @property
    def unresolved_operations(self) -> tuple[OperationReplayState, ...]:
        """Return charged or pre-dispatch operations without a terminal result."""
        return tuple(op for op in self.operations if not op.terminal)
