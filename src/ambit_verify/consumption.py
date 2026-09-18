# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Pure grammar and accounting-bound checks for canonical consumption evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from .hashing import canonical_json_bytes, parse_nonnegative_amount_scaled
from .models import DelegationClaims

CONSUMPTION_PROFILE = "canonical-operation/1"
_OPERATION_FIELDS = frozenset(
    {
        "operation_id",
        "domain_id",
        "ledger_id",
        "enforcement_point_id",
        "actor_key_fingerprint",
        "request_hash",
        "payload_hash",
        "resource_binding_hash",
    }
)
_ACCOUNT_FIELDS = frozenset(
    {
        "jti",
        "scope",
        "scope_id",
        "kind",
        "unit",
        "ceiling_amount_scaled",
        "window_epoch",
        "window_duration_ms",
        "amount_scaled",
        "reservation_id",
    }
)
_CONSUMED_IDENTIFIER_FIELDS = frozenset({"namespace", "identifier", "expires_at"})
_HEX = frozenset("0123456789abcdef")
_OPERATION_ID_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
)


def _nonempty_text(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be nonempty canonical text")
    return value


def _digest(value: object, *, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or set(value) - _HEX:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _moment(value: object, *, name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} requires an explicit timezone")
    return parsed.astimezone(UTC)


def _amount(value: object, *, name: str) -> str:
    if parse_nonnegative_amount_scaled(value) is None:
        raise ValueError(f"{name} must be a canonical non-negative integer")
    return str(value)


def validate_operation_descriptor(value: object) -> dict[str, Any]:
    """Return a copied, strict canonical operation descriptor or raise ``ValueError``."""
    if not isinstance(value, Mapping) or set(value) != _OPERATION_FIELDS:
        raise ValueError("operation descriptor fields are invalid")
    operation_id = value.get("operation_id")
    if (
        not isinstance(operation_id, str)
        or not 1 <= len(operation_id) <= 128
        or any(character not in _OPERATION_ID_CHARS for character in operation_id)
    ):
        raise ValueError("operation descriptor operation_id is invalid")
    result = {"operation_id": operation_id}
    for name in ("domain_id", "ledger_id", "enforcement_point_id", "actor_key_fingerprint"):
        result[name] = _nonempty_text(value.get(name), name=f"operation descriptor {name}")
    for name in ("request_hash", "payload_hash", "resource_binding_hash"):
        result[name] = _digest(value.get(name), name=f"operation descriptor {name}")
    try:
        canonical_json_bytes(result)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("operation descriptor is outside canonical JSON") from error
    return result


def bound_applies(bound: Mapping[str, Any], *, action_type: str, action_boundary: str) -> bool:
    """Return whether a signed bound applies to an action/boundary pair.

    This is the deterministic public extraction of Core's former
    ``rules_magnitude._bound_applies`` rule. Claim-shape validation establishes
    the mapping's grammar before callers reach this function.
    """
    applies_to = bound.get("applies_to")
    if not applies_to:
        return True
    if not isinstance(applies_to, Mapping):
        return False
    actions = applies_to.get("actions")
    if actions is not None and action_type not in set(actions):
        return False
    boundaries = applies_to.get("boundaries")
    return boundaries is None or action_boundary in set(boundaries)


def _account_description(
    claim: DelegationClaims, bound: Mapping[str, Any], *, scope: str | None, scope_id: str | None
) -> dict[str, Any]:
    epoch = bound.get("window_epoch")
    duration = bound.get("window_duration_ms")
    if (
        not isinstance(epoch, str)
        or not epoch
        or not isinstance(duration, int)
        or isinstance(duration, bool)
        or duration <= 0
    ):
        raise ValueError("required account bound is not windowed")
    return {
        "jti": claim.jti,
        "scope": scope,
        "scope_id": scope_id,
        "kind": bound["kind"],
        "unit": bound["unit"],
        "ceiling_amount_scaled": bound["amount_scaled"],
        "window_epoch": epoch,
        "window_duration_ms": duration,
        "window_kind": bound.get("window_kind"),
    }


def required_account_bounds(
    chain: Sequence[DelegationClaims], *, action_type: str, action_boundary: str
) -> tuple[dict[str, Any], ...]:
    """Return every applicable windowed grant/entry account for a verified chain.

    The result reads only signed claims. It never looks at a current store or
    derives a current period: Core remains the sole period-start derivation.
    """
    if (
        not isinstance(action_type, str)
        or not action_type
        or not isinstance(action_boundary, str)
        or not action_boundary
    ):
        raise ValueError("action type and boundary must be nonempty")
    if (
        not isinstance(chain, Sequence)
        or not chain
        or any(not isinstance(item, DelegationClaims) for item in chain)
    ):
        raise ValueError("chain must be a nonempty verified delegation-claims sequence")
    rows: list[dict[str, Any]] = []
    aggregate_by_identity: dict[tuple[object, ...], dict[str, Any]] = {}
    for claim in chain:
        for bound in claim.bounds:
            if not bound_applies(bound, action_type=action_type, action_boundary=action_boundary):
                continue
            if bound.get("window_epoch") is None or bound.get("window_duration_ms") is None:
                continue
            aggregation = bound.get("aggregation")
            if aggregation is None:
                rows.append(_account_description(claim, bound, scope=None, scope_id=None))
                continue
            if aggregation != "entry" or not isinstance(claim.authority_entry_hash, str):
                raise ValueError("entry aggregate account lacks an authority entry hash")
            row = _account_description(
                claim, bound, scope="entry", scope_id=claim.authority_entry_hash
            )
            identity = (
                row["scope"],
                row["scope_id"],
                row["kind"],
                row["unit"],
                row["window_epoch"],
                row["window_duration_ms"],
                row["window_kind"],
            )
            previous = aggregate_by_identity.get(identity)
            if previous is None:
                aggregate_by_identity[identity] = row
            elif previous["ceiling_amount_scaled"] != row["ceiling_amount_scaled"]:
                raise ValueError("contradictory duplicate entry aggregate account descriptions")
    rows.extend(aggregate_by_identity.values())
    return tuple(rows)


def _validate_identifier(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _CONSUMED_IDENTIFIER_FIELDS:
        raise ValueError("consumed identifier fields are invalid")
    return {
        name: _nonempty_text(value.get(name), name=f"consumed identifier {name}")
        for name in ("namespace", "identifier", "expires_at")
    }


def _validate_account(value: object, *, authorized_at: datetime) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _ACCOUNT_FIELDS:
        raise ValueError("consumption account fields are invalid")
    jti = _nonempty_text(value.get("jti"), name="consumption account jti")
    scope = value.get("scope")
    scope_id = value.get("scope_id")
    if scope is None:
        if scope_id is not None:
            raise ValueError("grant account must not name scope_id")
    elif scope == "entry":
        scope_id = _digest(scope_id, name="entry account scope_id")
    else:
        raise ValueError("consumption account scope is invalid")
    kind = _nonempty_text(value.get("kind"), name="consumption account kind")
    unit = _nonempty_text(value.get("unit"), name="consumption account unit")
    ceiling = _amount(value.get("ceiling_amount_scaled"), name="consumption account ceiling")
    amount = _amount(value.get("amount_scaled"), name="consumption account amount")
    reservation_id = _nonempty_text(
        value.get("reservation_id"), name="consumption account reservation_id"
    )
    epoch = _moment(value.get("window_epoch"), name="consumption account window_epoch")
    duration = value.get("window_duration_ms")
    if not isinstance(duration, int) or isinstance(duration, bool) or duration <= 0:
        raise ValueError("consumption account window_duration_ms is invalid")
    if not epoch <= authorized_at < epoch + timedelta(milliseconds=duration):
        raise ValueError("authorized_at is outside the supplied half-open account period")
    return {
        "jti": jti,
        "scope": scope,
        "scope_id": scope_id,
        "kind": kind,
        "unit": unit,
        "ceiling_amount_scaled": ceiling,
        "window_epoch": value["window_epoch"],
        "window_duration_ms": duration,
        "amount_scaled": amount,
        "reservation_id": reservation_id,
    }


def _validate_consumption_block(value: object, *, authorized_at: datetime) -> None:
    fields = {"profile", "operation", "state", "consumed_identifiers", "accounts"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("decision consumption fields are invalid")
    if value.get("profile") != CONSUMPTION_PROFILE:
        raise ValueError("decision consumption profile is invalid")
    validate_operation_descriptor(value.get("operation"))
    state = value.get("state")
    if state not in {"authorized", "refused"}:
        raise ValueError("decision consumption state is invalid")
    identifiers = value.get("consumed_identifiers")
    accounts = value.get("accounts")
    if not isinstance(identifiers, list) or not isinstance(accounts, list):
        raise ValueError("decision consumption identifiers or accounts are invalid")
    parsed_identifiers = [_validate_identifier(item) for item in identifiers]
    if len({(item["namespace"], item["identifier"]) for item in parsed_identifiers}) != len(
        parsed_identifiers
    ):
        raise ValueError("decision consumption repeats an identifier")
    parsed_accounts = [_validate_account(item, authorized_at=authorized_at) for item in accounts]
    if len({item["reservation_id"] for item in parsed_accounts}) != len(parsed_accounts):
        raise ValueError("decision consumption repeats a reservation")
    if state == "refused" and (identifiers or accounts):
        raise ValueError("refused decision consumption must be uncharged")


def _validate_consumption_event(record: Mapping[str, Any], *, evaluated_at: datetime) -> None:
    base = {"record_type", "profile", "event", "operation", "evaluated_at"}
    if record.get("record_type") != "consumption" or record.get("profile") != CONSUMPTION_PROFILE:
        raise ValueError("consumption record identity is invalid")
    event = record.get("event")
    if event not in {"dispatch_fenced", "settlement", "authentication"}:
        raise ValueError("consumption event is invalid")
    if event != "authentication":
        validate_operation_descriptor(record.get("operation"))
    if event == "dispatch_fenced":
        fields = base | {"decision_hash", "intent_hash", "dispatch_token", "dispatch_claims"}
        if set(record) - {"seq", "prev_hash", "record_hash", "timestamp_utc"} != fields:
            raise ValueError("dispatch_fenced record fields are invalid")
        _digest(record.get("decision_hash"), name="dispatch decision_hash")
        _digest(record.get("intent_hash"), name="dispatch intent_hash")
        token = record.get("dispatch_token")
        claims = record.get("dispatch_claims")
        if token is not None and not isinstance(token, str):
            raise ValueError("dispatch token is invalid")
        if not isinstance(claims, Mapping):
            raise ValueError("dispatch claims are invalid")
        if claims.get("payload_hash") != record["operation"].get("payload_hash"):
            raise ValueError("dispatch claims payload hash differs from operation")
    elif event == "settlement":
        fields = base | {"decision_hash", "intent_hash", "status", "basis", "resource_outcome"}
        if set(record) - {"seq", "prev_hash", "record_hash", "timestamp_utc"} != fields:
            raise ValueError("settlement record fields are invalid")
        _digest(record.get("decision_hash"), name="settlement decision_hash")
        intent_hash = record.get("intent_hash")
        if intent_hash is not None:
            _digest(intent_hash, name="settlement intent_hash")
        if record.get("status") not in {"committed", "released"}:
            raise ValueError("settlement status is invalid")
        basis = record.get("basis")
        outcome = record.get("resource_outcome")
        if basis == "resource_receipt" and isinstance(outcome, str) and outcome:
            return
        if (
            basis == "durable_no_dispatch"
            and outcome is None
            and record.get("status") == "released"
        ):
            return
        raise ValueError("settlement basis and terminal outcome are inconsistent")
    else:
        fields = base | {
            "authentication_kind",
            "request",
            "proof",
            "consumed_identifiers",
            "authentication_context",
        }
        if set(record) - {"seq", "prev_hash", "record_hash", "timestamp_utc"} != fields:
            raise ValueError("authentication record fields are invalid")
        kind = record.get("authentication_kind")
        if kind not in {"retry", "reconciliation", "delegation_issuance"}:
            raise ValueError("authentication kind is invalid")
        operation = record.get("operation")
        if kind == "delegation_issuance":
            if operation is not None:
                raise ValueError("delegation issuance authentication must not name an operation")
        else:
            validate_operation_descriptor(operation)
        request = record.get("request")
        proof = record.get("proof")
        if not isinstance(request, Mapping) or not isinstance(proof, Mapping):
            raise ValueError("authentication request or proof is invalid")
        actor = request.get("actor")
        if isinstance(actor, Mapping) and "proof" in actor:
            raise ValueError("authentication request must omit actor.proof")
        context = record.get("authentication_context")
        context_fields = {
            "domain_id",
            "ledger_id",
            "enforcement_point_id",
            "actor_key_fingerprint",
            "request_hash",
            "admission_token",
        }
        if not isinstance(context, Mapping) or set(context) != context_fields:
            raise ValueError("authentication context fields are invalid")
        for name in (
            "domain_id",
            "ledger_id",
            "enforcement_point_id",
            "actor_key_fingerprint",
            "admission_token",
        ):
            _nonempty_text(context.get(name), name=f"authentication context {name}")
        _digest(context.get("request_hash"), name="authentication context request_hash")
        if operation is not None:
            if (
                context["domain_id"] != operation["domain_id"]
                or context["ledger_id"] != operation["ledger_id"]
            ):
                raise ValueError("authentication context does not join the original operation")
            if context["enforcement_point_id"] != operation["enforcement_point_id"]:
                raise ValueError(
                    "authentication context point does not join the original operation"
                )
            if context["actor_key_fingerprint"] != operation["actor_key_fingerprint"]:
                raise ValueError(
                    "authentication context actor does not join the original operation"
                )
        identifiers = record.get("consumed_identifiers")
        if not isinstance(identifiers, list):
            raise ValueError("authentication consumed identifiers are invalid")
        parsed_identifiers = [_validate_identifier(item) for item in identifiers]
        if len({(item["namespace"], item["identifier"]) for item in parsed_identifiers}) != len(
            parsed_identifiers
        ):
            raise ValueError("authentication record repeats an identifier")


def validate_consumption_record(record: Mapping[str, Any]) -> None:
    """Validate a decision consumption block or one canonical consumption event.

    It checks wire grammar and local period containment only. Ledger hashing,
    signed status verification, policy evaluation, and store-derived period
    selection deliberately remain outside this public verifier.
    """
    if not isinstance(record, Mapping):
        raise ValueError("consumption record is not an object")
    record_type = record.get("record_type")
    if record_type == "decision":
        decision = record.get("decision")
        source = decision if isinstance(decision, Mapping) else record
        authorized_at = _moment(source.get("evaluated_at"), name="decision evaluated_at")
        _validate_consumption_block(record.get("consumption"), authorized_at=authorized_at)
        return
    if record_type == "consumption":
        evaluated_at = _moment(record.get("evaluated_at"), name="consumption evaluated_at")
        _validate_consumption_event(record, evaluated_at=evaluated_at)
        return
    raise ValueError("record does not carry Phase4 consumption evidence")


__all__ = [
    "CONSUMPTION_PROFILE",
    "bound_applies",
    "required_account_bounds",
    "validate_consumption_record",
    "validate_operation_descriptor",
]
