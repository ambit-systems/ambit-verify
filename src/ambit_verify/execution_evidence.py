# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Standalone verification of one retained Phase-4 canonical operation."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .actor_proof import actor_proof_request_hash, verify_actor_proof
from .admission import verify_authority_admission, verify_execution_authority
from .consumption import required_account_bounds, validate_consumption_record
from .credential_registration import verify_enforcement_point_registration
from .hashing import canonical_json_bytes, hash_object
from .head_attestation import ATTESTATION_BLOCK_KEYS, HeadAttestation
from .head_attestation_ed25519 import Ed25519HeadVerifier
from .resource_protocol import (
    git_publication_plan_hash,
    git_ref_is_covered,
    payload_bytes,
    resource_binding_hash,
    verify_dispatch,
    verify_resource_outcome,
)
from .tokens_slips import parse_approval, parse_delegation
from .verify import GENESIS_HASH

_HEX = frozenset("0123456789abcdef")


def _resource_join_fields(profile: object) -> tuple[str, ...]:
    common = (
        "version",
        "profile",
        "domain_id",
        "ledger_id",
        "enforcement_point_id",
        "resource_id",
        "resource_binding_hash",
        "operation_id",
        "request_hash",
        "payload_hash",
        "decision_hash",
        "intent_hash",
    )
    if profile == "git-publication/1":
        return (
            *common,
            "actor_id",
            "plan_hash",
            "remote",
            "ref",
            "expected_old_oid",
            "new_oid",
            "range",
            "force",
        )
    return common


@dataclass(frozen=True, slots=True)
class ExecutionBundleVerification:
    """Per-claim result for a retained, caller-pinned execution bundle."""

    valid: bool
    checks: Mapping[str, str]
    errors: tuple[str, ...] = ()


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and not (set(value) - _HEX)


def _moment(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp is not text")
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("timestamp has no timezone")
    return moment.astimezone(UTC)


def _records(value: object, *, expected_head: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    if (
        not isinstance(expected_head, Mapping)
        or set(expected_head) != {"seq", "record_hash"}
        or not isinstance(expected_head.get("seq"), int)
        or isinstance(expected_head.get("seq"), bool)
        or expected_head["seq"] <= 0
        or not _digest(expected_head.get("record_hash"))
    ):
        raise ValueError("caller-pinned expected head is invalid")
    if not isinstance(value, list) or not value:
        raise ValueError("bundle records are missing")
    previous = GENESIS_HASH
    result: list[Mapping[str, Any]] = []
    for index, record in enumerate(value, start=1):
        if not isinstance(record, Mapping):
            raise ValueError(f"bundle record {index} is not an object")
        sequence = record.get("seq")
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence <= 0
            or sequence != index
            or record.get("prev_hash") != previous
        ):
            raise ValueError(f"bundle record {index} does not continue the canonical prefix")
        record_hash = record.get("record_hash")
        if not _digest(record_hash):
            raise ValueError(f"bundle record {index} has an invalid hash")
        unsigned = {name: item for name, item in record.items() if name != "record_hash"}
        if hash_object(unsigned) != record_hash:
            raise ValueError(f"bundle record {index} hash does not verify")
        previous = record_hash
        if record.get("record_type") == "consumption" or record.get("consumption") is not None:
            validate_consumption_record(record)
        result.append(record)
    if len(result) != expected_head["seq"] or previous != expected_head["record_hash"]:
        raise ValueError("bundle prefix does not end at the caller-pinned head")
    return tuple(result)


def _decision_for_operation(
    records: Sequence[Mapping[str, Any]], operation_id: str
) -> Mapping[str, Any]:
    candidates = [
        record
        for record in records
        if record.get("record_type") == "decision"
        and isinstance(record.get("consumption"), Mapping)
        and isinstance(record["consumption"].get("operation"), Mapping)
        and record["consumption"]["operation"].get("operation_id") == operation_id
    ]
    if len(candidates) != 1:
        raise ValueError("canonical prefix does not contain exactly one operation decision")
    return candidates[0]


def _event_for_operation(
    records: Sequence[Mapping[str, Any]], operation_id: str, event: str
) -> Mapping[str, Any] | None:
    candidates = [
        record
        for record in records
        if record.get("record_type") == "consumption"
        and record.get("event") == event
        and isinstance(record.get("operation"), Mapping)
        and record["operation"].get("operation_id") == operation_id
    ]
    if len(candidates) > 1:
        raise ValueError(f"canonical prefix has duplicate {event} events")
    return candidates[0] if candidates else None


def _period_start_is_authorized(
    supplied: str, expected: Mapping[str, Any], *, authorized_at: datetime
) -> bool:
    try:
        start = _moment(supplied)
        base = _moment(expected["window_epoch"])
        duration = expected["window_duration_ms"]
        if not isinstance(duration, int) or isinstance(duration, bool) or duration <= 0:
            return False
        if expected.get("window_kind") is None:
            correct_start = start == base
        elif expected.get("window_kind") == "repeating":
            delta = start - base
            period = timedelta(milliseconds=duration)
            correct_start = delta >= timedelta(0) and delta % period == timedelta(0)
        else:
            return False
        return correct_start and start <= authorized_at < start + timedelta(milliseconds=duration)
    except KeyError, TypeError, ValueError, OverflowError:
        return False


def _accounting(decision: Mapping[str, Any]) -> None:
    validate_consumption_record(decision)
    consumption = decision["consumption"]
    if consumption.get("state") != "authorized":
        raise ValueError("operation decision is not an authorization")
    source = decision.get("decision")
    if not isinstance(source, Mapping):
        source = decision
    authorized_at = _moment(source.get("evaluated_at"))
    delegation = decision.get("delegation")
    if not isinstance(delegation, Mapping):
        raise ValueError("operation delegation evidence is missing")
    leaf_evidence = delegation.get("credential_evidence")
    leaf_token = leaf_evidence.get("artifact") if isinstance(leaf_evidence, Mapping) else None
    parents = delegation.get("credential_chain")
    evidence = decision.get("evidence")
    admission_evidence = (
        evidence.get("authority_admission") if isinstance(evidence, Mapping) else None
    )
    configuration = (
        admission_evidence.get("verification_configuration")
        if isinstance(admission_evidence, Mapping)
        else None
    )
    roots = (
        configuration.get("credential_trust_roots") if isinstance(configuration, Mapping) else None
    )
    if (
        not isinstance(leaf_token, str)
        or not isinstance(parents, list)
        or not isinstance(roots, Mapping)
    ):
        raise ValueError(
            "operation delegation chain or retained credential trust roots are missing"
        )
    leaf_ok, leaf = parse_delegation(leaf_token, trust_roots=roots)
    if not leaf_ok or leaf is None:
        raise ValueError("operation leaf claims cannot be parsed")
    claims = [leaf]
    for parent in parents:
        token = parent.get("artifact") if isinstance(parent, Mapping) else None
        if not isinstance(token, str):
            raise ValueError("operation ancestor claims are missing")
        parent_ok, parsed = parse_delegation(token, trust_roots=roots)
        if not parent_ok or parsed is None:
            raise ValueError("operation ancestor claims cannot be parsed")
        claims.append(parsed)
    action = decision.get("action")
    evidence = decision.get("evidence")
    request = evidence.get("request_envelope") if isinstance(evidence, Mapping) else None
    call = request.get("call") if isinstance(request, Mapping) else None
    action_type = action.get("type") if isinstance(action, Mapping) else None
    action_boundary = action.get("boundary") if isinstance(action, Mapping) else None
    binding = (
        admission_evidence.get("resource_binding")
        if isinstance(admission_evidence, Mapping)
        else None
    )
    if not isinstance(binding, Mapping):
        raise ValueError("operation lacks its retained resource binding")
    profile = binding.get("outcome_profile")
    if (
        not isinstance(action, Mapping)
        or not isinstance(action_type, str)
        or not isinstance(action_boundary, str)
        or not isinstance(call, Mapping)
        or set(call) != {"name", "arguments"}
        or not isinstance(call.get("name"), str)
        or not isinstance(call.get("arguments"), Mapping)
    ):
        raise ValueError("decision lacks the exact retained resource call")
    tool_name = call["name"]
    arguments = call["arguments"]
    target = decision.get("object")
    if profile == "record-egress/1":
        if not isinstance(arguments.get("records"), list) or not arguments["records"]:
            raise ValueError("record-egress decision lacks exact records")
        quantities = {
            ("record_count", "count:records"): len(arguments["records"]),
            ("payload_size", "bytes"): len(
                payload_bytes({"name": tool_name, "arguments": arguments})
            ),
        }
        domain = target.get("domain") if isinstance(target, Mapping) else None
        _signed_record_egress_scope(
            claims, action=action, domain=domain, authorized_at=authorized_at
        )
    elif profile == "git-publication/1":
        _git_publication_call(
            call=call,
            target=target,
            binding=binding,
        )
        quantities = {("git_push", "count:push"): 1}
        _signed_git_publication_scope(
            claims,
            action=action,
            target=target,
            ref=arguments["ref"],
            authorized_at=authorized_at,
        )
    else:
        raise ValueError("operation has no supported signed resource profile")
    expected = required_account_bounds(
        claims,
        action_type=action_type,
        action_boundary=action_boundary,
    )
    accounts = consumption.get("accounts")
    if not isinstance(accounts, list) or len(accounts) != len(expected):
        raise ValueError("operation accounting is incomplete")
    unmatched = list(expected)
    for account in accounts:
        if not isinstance(account, Mapping):
            raise ValueError("operation account is malformed")
        window_epoch = account.get("window_epoch")
        if not isinstance(window_epoch, str):
            raise ValueError("operation account window epoch is malformed")
        match = next(
            (
                bound
                for bound in unmatched
                if all(
                    account.get(name) == bound.get(name)
                    for name in (
                        "jti",
                        "scope",
                        "scope_id",
                        "kind",
                        "unit",
                        "ceiling_amount_scaled",
                        "window_duration_ms",
                    )
                )
                and _period_start_is_authorized(window_epoch, bound, authorized_at=authorized_at)
            ),
            None,
        )
        if match is None:
            raise ValueError("operation account does not match a required signed bound")
        if int(account["amount_scaled"]) != quantities[(match["kind"], match["unit"])]:
            raise ValueError("cumulative debit does not equal the exact resource quantity")
        unmatched.remove(match)
    if unmatched:
        raise ValueError("operation accounting omits a required signed bound")


def _signed_record_egress_scope(
    claims: Sequence[Any], *, action: Mapping[str, Any], domain: object, authorized_at: datetime
) -> None:
    if (
        action.get("type") != "send"
        or action.get("boundary") != "network_egress"
        or not isinstance(domain, str)
        or not domain.strip()
    ):
        raise ValueError("operation is not the fixed record-egress action")
    domain = domain.strip().lower()
    for claim in claims:
        if "send" not in claim.scope_actions:
            raise ValueError("signed delegation does not cover record-egress send")
        if domain not in {item.strip().lower() for item in claim.scope_domains if item.strip()}:
            raise ValueError("signed delegation does not cover the record-egress domain")
        if "." not in set(claim.scope_paths):
            raise ValueError("signed delegation does not cover the record-egress path")
        if claim.capabilities and not any(
            "send" in capability.actions and capability.nbf <= authorized_at <= capability.exp
            for capability in claim.capabilities
        ):
            raise ValueError("signed delegation capability does not cover record-egress send")


def _git_publication_call(
    *,
    call: Mapping[str, Any],
    target: object,
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    arguments = call.get("arguments")
    required = {
        "actor_id",
        "code_id",
        "remote",
        "ref",
        "expected_old_oid",
        "new_oid",
        "range",
        "force",
        "plan_hash",
    }
    if (
        call.get("name") != "git.publish"
        or not isinstance(arguments, Mapping)
        or set(arguments) != required
        or not isinstance(target, Mapping)
        or target.get("id") != arguments.get("ref")
        or arguments.get("code_id") != arguments.get("ref")
        or arguments.get("remote") != binding.get("git_remote")
        or arguments.get("ref") != binding.get("git_ref")
        or not isinstance(arguments.get("actor_id"), str)
        or not arguments["actor_id"]
        or not _digest(arguments.get("plan_hash"))
        or arguments.get("force") is not False
    ):
        raise ValueError("Git publication call does not match its admitted resource")
    expected_plan = git_publication_plan_hash(
        remote_url=arguments["remote"],
        ref=arguments["ref"],
        expected_old_oid=arguments["expected_old_oid"],
        new_oid=arguments["new_oid"],
        commit_range=arguments["range"],
        force=arguments["force"],
    )
    if arguments["plan_hash"] != expected_plan:
        raise ValueError("Git publication plan hash is invalid")
    return dict(arguments)


def _signed_git_publication_scope(
    claims: Sequence[Any],
    *,
    action: Mapping[str, Any],
    target: object,
    ref: str,
    authorized_at: datetime,
) -> None:
    domain = target.get("domain") if isinstance(target, Mapping) else None
    if (
        not isinstance(domain, str)
        or not domain
        or not isinstance(action.get("type"), str)
        or not isinstance(action.get("boundary"), str)
    ):
        raise ValueError("operation lacks a canonical Git action target")
    for claim in claims:
        if action["type"] not in claim.scope_actions:
            raise ValueError("signed delegation does not cover the Git action")
        if domain not in {item.strip().lower() for item in claim.scope_domains if item.strip()}:
            raise ValueError("signed delegation does not cover the Git target domain")
        if not git_ref_is_covered(ref, claim.scope_paths):
            raise ValueError("signed delegation does not cover the Git ref")
        if claim.capabilities and not any(
            action["type"] in capability.actions
            and capability.nbf <= authorized_at <= capability.exp
            for capability in claim.capabilities
        ):
            raise ValueError("signed delegation capability does not cover the Git action")


def _action_and_payload(
    decision: Mapping[str, Any], dispatch: Mapping[str, Any]
) -> tuple[dict[str, Any], list[Any] | None]:
    claims = dispatch.get("dispatch_claims")
    if not isinstance(claims, Mapping):
        raise ValueError("dispatch claims are absent")
    action = decision.get("action")
    target = decision.get("object")
    evidence = decision.get("evidence")
    request = evidence.get("request_envelope") if isinstance(evidence, Mapping) else None
    call = request.get("call") if isinstance(request, Mapping) else None
    if (
        not isinstance(action, Mapping)
        or action.get("type") != claims.get("action_type")
        or action.get("boundary") != claims.get("action_boundary")
        or not isinstance(target, Mapping)
        or target.get("domain") != claims.get("action_domain")
        or not isinstance(call, Mapping)
        or set(call) != {"name", "arguments"}
        or not isinstance(call.get("name"), str)
        or not isinstance(call.get("arguments"), Mapping)
    ):
        raise ValueError("dispatch action or retained resource call differs from authorization")
    tool_name = call["name"]
    arguments = call["arguments"]
    payload = payload_bytes({"name": tool_name, "arguments": arguments})
    if hashlib.sha256(payload).hexdigest() != claims.get("payload_hash"):
        raise ValueError("dispatch payload hash differs from exact resource call")
    if claims.get("profile") == "record-egress/1":
        if (
            claims.get("action_type") != "send"
            or claims.get("action_boundary") != "network_egress"
            or claims.get("action_path") != "."
        ):
            raise ValueError("dispatch does not state the fixed record-egress action")
        records = arguments.get("records")
        if not isinstance(records, list) or not records:
            raise ValueError("record-egress call has no records")
        if "url" in arguments:
            raise ValueError("record-egress call must not carry an arbitrary URL")
        return dict(claims), records
    if claims.get("profile") != "git-publication/1":
        raise ValueError("dispatch profile is unsupported")
    admission_evidence = (
        evidence.get("authority_admission") if isinstance(evidence, Mapping) else None
    )
    binding = (
        admission_evidence.get("resource_binding")
        if isinstance(admission_evidence, Mapping)
        else None
    )
    if not isinstance(binding, Mapping):
        raise ValueError("Git dispatch lacks its admitted resource binding")
    git = _git_publication_call(call=call, target=target, binding=binding)
    request_actor = request.get("actor") if isinstance(request, Mapping) else None
    if (
        claims.get("actor_id") != git["actor_id"]
        or not isinstance(request_actor, Mapping)
        or claims["actor_id"] != request_actor.get("id")
        or any(
            claims.get(name) != git[name]
            for name in (
                "plan_hash",
                "remote",
                "ref",
                "expected_old_oid",
                "new_oid",
                "range",
                "force",
            )
        )
        or claims.get("action_path") != git["ref"]
    ):
        raise ValueError("Git dispatch differs from its canonical request target")
    return dict(claims), None


def _expected_consumed_facts(
    decision: Mapping[str, Any], admission: Any
) -> set[tuple[str, str, datetime]]:
    evidence = decision.get("evidence")
    source = decision.get("decision")
    if not isinstance(source, Mapping):
        source = decision
    if not isinstance(evidence, Mapping):
        raise ValueError("authorized decision lacks retained evidence")
    proof = evidence.get("actor_proof")
    request = evidence.get("request_envelope")
    actor_id = source.get("actor_id")
    if (
        not isinstance(proof, Mapping)
        or not isinstance(request, Mapping)
        or not isinstance(actor_id, str)
    ):
        raise ValueError("authorized decision lacks retained holder proof/preimage")
    authorized_at = _moment(source.get("evaluated_at"))
    request_hash = actor_proof_request_hash(request)
    holder = verify_actor_proof(
        {"actor_id": actor_id, "actor_proof": proof},
        admission.claims["credential_trust_roots"],
        request_hash=request_hash,
        audience=str(admission.claims["ledger_id"]),
        now=authorized_at,
        freshness_seconds=int(admission.claims["max_actor_proof_age_seconds"]),
        registration_public_keys=admission.claims["credential_registration_public_keys"],
    )
    if not holder.valid or holder.key_fingerprint is None or holder.nonce is None:
        raise ValueError("authorized decision holder proof is invalid")
    issued = _moment(proof.get("issued_at"))
    facts = {
        (
            "actor_nonce",
            canonical_json_bytes(
                {
                    "ledger_id": admission.claims["ledger_id"],
                    "key_fingerprint": holder.key_fingerprint,
                    "nonce": holder.nonce,
                }
            ).decode("utf-8"),
            issued + timedelta(seconds=int(admission.claims["max_actor_proof_age_seconds"])),
        )
    }
    approval = decision.get("approval")
    approval_evidence = (
        approval.get("credential_evidence") if isinstance(approval, Mapping) else None
    )
    approval_token = (
        approval_evidence.get("artifact") if isinstance(approval_evidence, Mapping) else None
    )
    raw_quorum = evidence.get("quorum_approval_tokens")
    tokens = ([approval_token] if isinstance(approval_token, str) else []) + (
        raw_quorum
        if isinstance(raw_quorum, list) and all(isinstance(token, str) for token in raw_quorum)
        else []
    )
    if raw_quorum is None or not isinstance(raw_quorum, list):
        raise ValueError("schema-v6 decision lacks retained quorum approval token list")
    for token in tokens:
        ok, claims = parse_approval(token, trust_roots=admission.claims["credential_trust_roots"])
        # Approval precedes its inclusion in the holder-signed envelope. It binds
        # the canonical action fingerprint, not the envelope hash containing itself.
        if (
            not ok
            or claims is None
            or claims.request_fingerprint != source.get("request_fingerprint")
        ):
            raise ValueError("retained approval does not verify or bind the canonical request")
        facts.add(("approval", claims.jti, claims.exp.astimezone(UTC)))
    return facts


def _adapter_roots(
    record: Mapping[str, Any],
    admission_trust_roots_by_adapter: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    adapter_id = record.get("adapter_id")
    roots = (
        admission_trust_roots_by_adapter.get(adapter_id) if isinstance(adapter_id, str) else None
    )
    if not isinstance(roots, Mapping):
        raise ValueError("canonical record adapter has no configured admission roots")
    return roots


def _require_admission_adapter(admission: Any, adapter_id: str) -> None:
    claims = getattr(admission, "claims", None)
    binding = claims.get("resource_binding") if isinstance(claims, Mapping) else None
    if not isinstance(binding, Mapping) or binding.get("adapter_id") != adapter_id:
        raise ValueError("signed admission resource binding does not match canonical adapter")


def _admission_token_adapter(token: object) -> str:
    if not isinstance(token, str) or token.count(".") != 1:
        raise ValueError("authentication admission token is malformed")
    try:
        encoded = token.split(".", 1)[0]
        payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        claims = json.loads(payload)
        binding = claims.get("resource_binding") if isinstance(claims, Mapping) else None
        adapter_id = binding.get("adapter_id") if isinstance(binding, Mapping) else None
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("authentication admission token cannot select configured roots") from exc
    if not isinstance(adapter_id, str) or not adapter_id:
        raise ValueError("authentication admission omits its resource adapter")
    return adapter_id


def _retained_escalation(
    decision: Mapping[str, Any],
    retained_decisions: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    approval = decision.get("approval")
    digest = approval.get("escalation_record_hash") if isinstance(approval, Mapping) else None
    escalation = retained_decisions.get(digest) if isinstance(digest, str) else None
    if escalation is not None and escalation["seq"] < decision["seq"]:
        return escalation
    return None


def _replay_prefix(
    records: Sequence[Mapping[str, Any]],
    *,
    retained_decisions: Mapping[str, Mapping[str, Any]],
    admission_trust_roots_by_adapter: Mapping[str, Mapping[str, Any]],
    expected_domain: str,
    expected_ledger_id: str,
) -> None:
    """Replay every current operation's retained accounting/transition evidence."""
    decisions: dict[str, Mapping[str, Any]] = {}
    operation_states: dict[str, str] = {}
    reservations: dict[str, tuple[tuple[Any, ...], int, str, str]] = {}
    fences: dict[str, Mapping[str, Any]] = {}
    operation_reservations: dict[str, list[str]] = {}
    charged: dict[tuple[Any, ...], tuple[int, int]] = {}
    consumed: dict[tuple[str, str], datetime] = {}
    intents = {
        record.get("record_hash"): record
        for record in records
        if record.get("record_type") == "consequence_intent" and _digest(record.get("record_hash"))
    }
    for legacy in records:
        if legacy.get("record_type") != "decision" or legacy.get("consumption") is not None:
            continue
        verdict = legacy.get("decision")
        allowed = verdict == "ALLOW" or (
            isinstance(verdict, Mapping) and verdict.get("outcome") == "ALLOW"
        )
        linked_intent = any(
            intent.get("decision_seq") == legacy.get("seq") for intent in intents.values()
        )
        if (allowed or linked_intent) and legacy.get("dry_run") is not True:
            raise ValueError("unsupported legacy consequential decision in canonical prefix")
    for record in records:
        if record.get("record_type") == "decision":
            roots = _adapter_roots(record, admission_trust_roots_by_adapter)
            consumption = record.get("consumption")
            if consumption is None:
                if record.get("decision") == "ALLOW" or any(
                    intent.get("decision_seq") == record.get("seq") for intent in intents.values()
                ):
                    raise ValueError(
                        "unsupported legacy consequential decision in canonical prefix"
                    )
                continue
            validate_consumption_record(record)
            operation = consumption["operation"]
            operation_id = operation["operation_id"]
            if operation_id in decisions:
                raise ValueError("canonical prefix repeats an operation id")
            if consumption["state"] == "authorized":
                authority = verify_execution_authority(
                    record,
                    admission_trust_roots=roots,
                    expected_domain=expected_domain,
                    expected_ledger_id=expected_ledger_id,
                    escalation_record=_retained_escalation(record, retained_decisions),
                )
                if not authority.valid:
                    raise ValueError(
                        "; ".join(authority.errors) or "operation authority is invalid"
                    )
                evidence = record.get("evidence")
                admission_evidence = (
                    evidence.get("authority_admission") if isinstance(evidence, Mapping) else None
                )
                admission_token = (
                    admission_evidence.get("artifact")
                    if isinstance(admission_evidence, Mapping)
                    else None
                )
                authorized_source: Mapping[str, Any] = record
                retained_authorized_decision = record.get("decision")
                if isinstance(retained_authorized_decision, Mapping):
                    authorized_source = retained_authorized_decision
                if not isinstance(admission_token, str):
                    raise ValueError("authorized decision admission token is missing")
                admission = verify_authority_admission(
                    admission_token,
                    admission_trust_roots=roots,
                    expected_domain=expected_domain,
                    expected_ledger_id=expected_ledger_id,
                    at=_moment(authorized_source.get("evaluated_at")),
                ).admission
                if admission is None:
                    raise ValueError("authorized decision admission cannot be re-verified")
                _require_admission_adapter(admission, str(record["adapter_id"]))
                declared = {
                    (item["namespace"], item["identifier"], _moment(item["expires_at"]))
                    for item in consumption["consumed_identifiers"]
                }
                if declared != _expected_consumed_facts(record, admission):
                    raise ValueError(
                        "authorized decision consumed identifiers differ from verified facts"
                    )
                _accounting(record)
            operation_states[operation_id] = consumption["state"]
            decisions[operation_id] = record
            identifiers = consumption["consumed_identifiers"]
            decision_source: Mapping[str, Any] = record
            retained_decision = record.get("decision")
            if isinstance(retained_decision, Mapping):
                decision_source = retained_decision
            decision_time = _moment(decision_source.get("evaluated_at"))
            for item in identifiers:
                consumed_key = (item["namespace"], item["identifier"])
                expiry = _moment(item["expires_at"])
                if consumed_key in consumed and decision_time <= consumed[consumed_key]:
                    raise ValueError(
                        "canonical prefix reuses an unexpired consumed identifier in record order"
                    )
                consumed[consumed_key] = expiry
            if consumption["state"] == "authorized":
                for account in consumption["accounts"]:
                    reservation = account["reservation_id"]
                    if reservation in reservations:
                        raise ValueError("canonical prefix repeats a reservation")
                    key = (
                        account["jti"] if account["scope"] is None else account["scope_id"],
                        account["scope"],
                        account["kind"],
                        account["unit"],
                        account["window_epoch"],
                        account["window_duration_ms"],
                    )
                    amount = int(account["amount_scaled"])
                    ceiling = int(account["ceiling_amount_scaled"])
                    used, existing_ceiling = charged.get(key, (0, ceiling))
                    if existing_ceiling != ceiling:
                        raise ValueError("canonical prefix changes an admitted account ceiling")
                    if amount > ceiling - used:
                        raise ValueError(
                            "canonical prefix exceeds an admitted account ceiling in record order"
                        )
                    charged[key] = (used + amount, ceiling)
                    reservations[reservation] = (key, amount, operation_id, "authorized")
                    operation_reservations.setdefault(operation_id, []).append(reservation)
            continue
        if record.get("record_type") != "consumption":
            continue
        validate_consumption_record(record)
        event = record["event"]
        operation = record["operation"]
        if event == "authentication":
            auth_time = _moment(record["evaluated_at"])
            for item in record["consumed_identifiers"]:
                authentication_key = (item["namespace"], item["identifier"])
                expiry = _moment(item["expires_at"])
                if authentication_key in consumed and auth_time <= consumed[authentication_key]:
                    raise ValueError(
                        "canonical prefix reuses an unexpired consumed identifier in record order"
                    )
                consumed[authentication_key] = expiry
            context = record["authentication_context"]
            admission_token = context.get("admission_token")
            if not isinstance(admission_token, str):
                raise ValueError("authentication admission token is missing")
            if operation is None:
                admission_at = auth_time
                adapter_id = _admission_token_adapter(admission_token)
                admission_record: Mapping[str, Any] = {"adapter_id": adapter_id}
            else:
                original = decisions.get(operation["operation_id"])
                if original is None:
                    raise ValueError("authentication names an unknown original operation")
                if original.get("seq", 0) >= record.get("seq", 0):
                    raise ValueError("authentication precedes its canonical original operation")
                original_consumption = original.get("consumption")
                if not isinstance(
                    original_consumption, Mapping
                ) or operation != original_consumption.get("operation"):
                    raise ValueError(
                        "retrieval authentication does not retain the complete original operation"
                    )
                original_evidence = original.get("evidence")
                original_admission = (
                    original_evidence.get("authority_admission")
                    if isinstance(original_evidence, Mapping)
                    else None
                )
                if not isinstance(
                    original_admission, Mapping
                ) or admission_token != original_admission.get("artifact"):
                    raise ValueError(
                        "retrieval authentication does not retain the original admission"
                    )
                original_source: Mapping[str, Any] = original
                retained_original_decision = original.get("decision")
                if isinstance(retained_original_decision, Mapping):
                    original_source = retained_original_decision
                admission_at = _moment(original_source.get("evaluated_at"))
                adapter_value = original.get("adapter_id")
                if not isinstance(adapter_value, str) or not adapter_value:
                    raise ValueError("original operation lacks a canonical adapter")
                adapter_id = adapter_value
                admission_record = original
            roots = _adapter_roots(
                admission_record,
                admission_trust_roots_by_adapter,
            )
            admission_result = verify_authority_admission(
                admission_token,
                admission_trust_roots=roots,
                expected_domain=expected_domain,
                expected_ledger_id=expected_ledger_id,
                at=admission_at,
            )
            admission = admission_result.admission
            if not admission_result.valid or admission is None:
                raise ValueError(
                    "authentication admission is invalid at its required comparison time"
                )
            _require_admission_adapter(admission, adapter_id)
            request = record["request"]
            actor = request.get("actor") if isinstance(request, Mapping) else None
            actor_id = actor.get("id") if isinstance(actor, Mapping) else None
            if (
                not isinstance(actor_id, str)
                or actor_proof_request_hash(request) != context["request_hash"]
            ):
                raise ValueError("authentication request preimage does not bind its context")
            proof = record["proof"]
            holder = verify_actor_proof(
                {"actor_id": actor_id, "actor_proof": proof},
                admission.claims["credential_trust_roots"],
                request_hash=context["request_hash"],
                audience=expected_ledger_id,
                now=auth_time,
                freshness_seconds=int(admission.claims["max_actor_proof_age_seconds"]),
                registration_public_keys=admission.claims["credential_registration_public_keys"],
            )
            if not holder.valid or holder.key_fingerprint != context["actor_key_fingerprint"]:
                raise ValueError("authentication holder proof does not verify at the event time")
            proof_issued = _moment(proof["issued_at"])
            expected_auth_fact = {
                (
                    "actor_nonce",
                    canonical_json_bytes(
                        {
                            "ledger_id": admission.claims["ledger_id"],
                            "key_fingerprint": holder.key_fingerprint,
                            "nonce": holder.nonce,
                        }
                    ).decode("utf-8"),
                    proof_issued
                    + timedelta(seconds=int(admission.claims["max_actor_proof_age_seconds"])),
                )
            }
            declared_auth_facts = {
                (item["namespace"], item["identifier"], _moment(item["expires_at"]))
                for item in record["consumed_identifiers"]
            }
            if declared_auth_facts != expected_auth_fact:
                raise ValueError("authentication consumed identifiers differ from its holder proof")
            continue
        operation_id = operation["operation_id"]
        decision = decisions.get(operation_id)
        if decision is None:
            raise ValueError("lifecycle event precedes its canonical decision")
        if decision.get("seq", 0) >= record.get("seq", 0):
            raise ValueError("lifecycle event precedes its canonical decision")
        original_consumption = decision.get("consumption")
        if not isinstance(original_consumption, Mapping) or operation != original_consumption.get(
            "operation"
        ):
            raise ValueError("lifecycle event does not retain the complete authorized operation")
        if record["decision_hash"] != decision.get("record_hash"):
            raise ValueError("lifecycle event does not join its canonical decision")
        if event == "dispatch_fenced":
            intent = intents.get(record["intent_hash"])
            if intent is None or intent.get("seq", 0) >= record.get("seq", 0):
                raise ValueError("dispatch fence lacks an earlier canonical intent")
            if (
                intent.get("decision_seq") != decision.get("seq")
                or intent.get("operation") != operation
            ):
                raise ValueError(
                    "dispatch fence intent does not join its canonical decision and operation"
                )
            claims = record.get("dispatch_claims")
            token = record.get("dispatch_token")
            if token is not None:
                if (
                    not isinstance(token, str)
                    or not isinstance(claims, Mapping)
                    or any(
                        claims.get(name) != operation.get(name)
                        for name in (
                            "domain_id",
                            "ledger_id",
                            "enforcement_point_id",
                            "operation_id",
                            "request_hash",
                            "payload_hash",
                            "resource_binding_hash",
                        )
                    )
                    or not isinstance(claims.get("authorized_at"), str)
                    or not isinstance(claims.get("not_after"), str)
                ):
                    raise ValueError("signed dispatch fence does not join its exact operation")
                _action_and_payload(decision, record)
            if operation_states.get(operation_id) != "authorized":
                raise ValueError("dispatch fence is not the first authorized lifecycle transition")
            operation_states[operation_id] = "fenced"
            for reservation in operation_reservations.get(operation_id, []):
                key, amount, owner, state = reservations[reservation]
                if owner != operation_id or state != "authorized":
                    raise ValueError("dispatch fence repeats a reservation transition")
                reservations[reservation] = (key, amount, owner, "fenced")
            fences[operation_id] = record
            continue
        if event == "settlement":
            status = record["status"]
            fence = fences.get(operation_id)
            pre_fence_release = (
                operation_states.get(operation_id) == "authorized"
                and status == "released"
                and record.get("basis") == "durable_no_dispatch"
            )
            if pre_fence_release:
                intent_hash = record.get("intent_hash")
                if intent_hash is not None:
                    intent = intents.get(intent_hash)
                    if (
                        intent is None
                        or intent.get("seq", 0) >= record.get("seq", 0)
                        or intent.get("decision_seq") != decision.get("seq")
                        or intent.get("operation") != operation
                    ):
                        raise ValueError("pre-fence settlement does not retain its earlier intent")
            else:
                if operation_states.get(operation_id) != "fenced" or fence is None:
                    raise ValueError(
                        "settlement is not the unique terminal transition after its fence"
                    )
                if record.get("intent_hash") != fence.get("intent_hash"):
                    raise ValueError("settlement does not retain the fenced dispatch intent")
            roots = _adapter_roots(decision, admission_trust_roots_by_adapter)
            if record.get("basis") == "resource_receipt":
                if fence is None:
                    raise ValueError("terminal receipt lacks its dispatch fence")
                evidence = decision.get("evidence")
                admission_evidence = (
                    evidence.get("authority_admission") if isinstance(evidence, Mapping) else None
                )
                token = (
                    admission_evidence.get("artifact")
                    if isinstance(admission_evidence, Mapping)
                    else None
                )
                settlement_source: Mapping[str, Any] = decision
                retained_settlement_decision = decision.get("decision")
                if isinstance(retained_settlement_decision, Mapping):
                    settlement_source = retained_settlement_decision
                if not isinstance(token, str):
                    raise ValueError("terminal admission token is missing")
                admission = verify_authority_admission(
                    token,
                    admission_trust_roots=roots,
                    expected_domain=expected_domain,
                    expected_ledger_id=expected_ledger_id,
                    at=_moment(settlement_source.get("evaluated_at")),
                ).admission
                if admission is None:
                    raise ValueError("terminal admission cannot be re-verified")
                _require_admission_adapter(admission, str(decision["adapter_id"]))
                binding = admission.claims.get("resource_binding")
                outcome_key = (
                    binding.get("outcome_public_key") if isinstance(binding, Mapping) else None
                )
                if (
                    not isinstance(binding, Mapping)
                    or not isinstance(record.get("resource_outcome"), str)
                    or not isinstance(outcome_key, (bytes, str))
                ):
                    raise ValueError("terminal receipt lacks its admitted independent resource key")
                outcome = verify_resource_outcome(
                    record["resource_outcome"], public_key=outcome_key
                )
                dispatch_claims = fence.get("dispatch_claims")
                if not isinstance(dispatch_claims, Mapping) or any(
                    outcome.get(name) != dispatch_claims.get(name)
                    for name in _resource_join_fields(dispatch_claims.get("profile"))
                ):
                    raise ValueError("terminal receipt does not join its fenced dispatch")
                claims, egress_records = _action_and_payload(decision, fence)
                accepted_at = outcome.get("accepted_at")
                if accepted_at is not None and not (
                    _moment(claims["authorized_at"])
                    <= _moment(accepted_at)
                    < _moment(claims["not_after"])
                ):
                    raise ValueError("resource accepted_at is outside the signed dispatch interval")
                if status == "committed":
                    if outcome.get("status") != "committed":
                        raise ValueError(
                            "settlement state differs from its signed terminal outcome"
                        )
                    if claims.get("profile") == "record-egress/1" and (
                        egress_records is None
                        or outcome.get("record_count") != len(egress_records)
                        or outcome.get("records_hash") != hash_object(egress_records)
                    ):
                        raise ValueError("record-egress outcome does not bind exact records")
                elif status == "released" and outcome.get("status") != "not_executed":
                    raise ValueError("settlement state differs from its signed terminal outcome")
            relevant = [
                reservation
                for reservation in operation_reservations.get(operation_id, [])
                if reservations[reservation][3] in {"authorized", "fenced"}
            ]
            if status == "released":
                if any(reservations[key][3] == "fenced" for key in relevant) and (
                    record.get("basis") != "resource_receipt"
                    or not isinstance(record.get("resource_outcome"), str)
                ):
                    raise ValueError(
                        "fenced capacity may release only on a retained not-executed receipt"
                    )
                for reservation in relevant:
                    key, amount, owner, _ = reservations[reservation]
                    used, ceiling = charged[key]
                    charged[key] = (used - amount, ceiling)
                    reservations[reservation] = (key, amount, owner, "released")
                operation_states[operation_id] = "released"
            else:
                fence = fences.get(operation_id)
                if (
                    fence is None
                    or not isinstance(fence.get("dispatch_token"), str)
                    or not isinstance(record.get("resource_outcome"), str)
                    or record.get("basis") != "resource_receipt"
                ):
                    raise ValueError(
                        "committed settlement lacks retained signed dispatch/outcome evidence"
                    )
                if any(reservations[key][3] != "fenced" for key in relevant):
                    raise ValueError("committed settlement does not follow a dispatch fence")
                for reservation in relevant:
                    key, amount, owner, _ = reservations[reservation]
                    reservations[reservation] = (key, amount, owner, "committed")
                operation_states[operation_id] = "committed"


def verify_execution_bundle(
    bundle: Mapping[str, Any],
    *,
    admission_trust_roots_by_adapter: Mapping[str, Mapping[str, Any]],
    enforcement_point_registration_public_keys: Mapping[str, str],
    expected_domain: str,
    expected_ledger_id: str,
    expected_head: Mapping[str, Any],
    operation_id: str,
) -> ExecutionBundleVerification:
    """Verify one complete Phase-4 execution claim against caller-pinned trust/head.

    The bundle has the frozen schema-1 canonical-operation container. Its
    records are a complete prefix; the head and registration inside the bundle
    are candidates that must agree with independently supplied roots/head.
    """
    check_names = (
        "canonical_prefix",
        "prefix_accounting",
        "enforcement_point_registration",
        "head_attestation",
        "authority",
        "accounting",
        "dispatch",
        "resource_outcome",
        "record_effect",
    )
    checks: dict[str, str] = dict.fromkeys(check_names, "not_established")
    effect_check = "record_effect"

    def failed(name: str, error: Exception | str) -> ExecutionBundleVerification:
        checks[name] = "failed"
        return ExecutionBundleVerification(False, checks, (str(error),))

    def not_established(error: Exception | str) -> ExecutionBundleVerification:
        return ExecutionBundleVerification(False, checks, (str(error),))

    if not isinstance(operation_id, str) or not operation_id:
        return failed("canonical_prefix", "operation id is invalid")
    if (
        not isinstance(bundle, Mapping)
        or set(bundle)
        != {
            "schema_version",
            "profile",
            "records",
            "head_attestation",
            "enforcement_point_registration",
        }
        or bundle.get("schema_version") != 1
        or bundle.get("profile") != "canonical-operation/1"
        or not isinstance(admission_trust_roots_by_adapter, Mapping)
        or not isinstance(enforcement_point_registration_public_keys, Mapping)
    ):
        return failed("canonical_prefix", "verification bundle or caller roots are invalid")
    try:
        records = _records(bundle["records"], expected_head=expected_head)
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return failed("canonical_prefix", error)
    checks["canonical_prefix"] = "valid"

    try:
        retained_decisions = {
            record["record_hash"]: record
            for record in records
            if record.get("record_type") == "decision"
        }
        _replay_prefix(
            records,
            retained_decisions=retained_decisions,
            admission_trust_roots_by_adapter=admission_trust_roots_by_adapter,
            expected_domain=expected_domain,
            expected_ledger_id=expected_ledger_id,
        )
        decision = _decision_for_operation(records, operation_id)
        descriptor = decision["consumption"]["operation"]
        if not isinstance(descriptor, Mapping):
            raise ValueError("operation descriptor is not an object")
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return failed("prefix_accounting", error)
    checks["prefix_accounting"] = "valid"

    try:
        registration_raw = bundle["enforcement_point_registration"]
        if not isinstance(registration_raw, Mapping):
            raise ValueError("enforcement-point registration is missing")
        registration = verify_enforcement_point_registration(
            registration_raw,
            registration_public_keys=enforcement_point_registration_public_keys,
        )
        if (
            registration.enforcement_point_id != descriptor["enforcement_point_id"]
            or registration.ledger_id != expected_ledger_id
        ):
            raise ValueError("enforcement-point registration does not bind the operation")
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return failed("enforcement_point_registration", error)
    checks["enforcement_point_registration"] = "valid"

    try:
        attestation_raw = bundle["head_attestation"]
        if (
            not isinstance(attestation_raw, Mapping)
            or set(attestation_raw) != ATTESTATION_BLOCK_KEYS
        ):
            raise ValueError("head attestation fields are invalid")
        attestation = HeadAttestation(**dict(attestation_raw))
        if (
            attestation.max_seq != expected_head["seq"]
            or attestation.head_record_hash != expected_head["record_hash"]
            or attestation.ledger_id != expected_ledger_id
            or not Ed25519HeadVerifier(
                public_key=bytes.fromhex(registration.public_key),
                trust_root_id=registration.trust_root_id,
            ).verify_head(attestation)
        ):
            raise ValueError("head attestation does not verify the caller-pinned head")
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return failed("head_attestation", error)
    checks["head_attestation"] = "valid"

    try:
        roots = _adapter_roots(decision, admission_trust_roots_by_adapter)
        authority = verify_execution_authority(
            decision,
            admission_trust_roots=roots,
            expected_domain=expected_domain,
            expected_ledger_id=expected_ledger_id,
            escalation_record=_retained_escalation(decision, retained_decisions),
        )
        if not authority.valid:
            raise ValueError(
                "; ".join(authority.errors) or "retained authority verification failed"
            )
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return failed("authority", error)
    checks["authority"] = "valid"
    admission_evidence = decision["evidence"]["authority_admission"]
    if admission_evidence["resource_binding"].get("outcome_profile") == "git-publication/1":
        effect_check = "git_publication_effect"
        checks[effect_check] = checks.pop("record_effect")

    try:
        _accounting(decision)
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return failed("accounting", error)
    checks["accounting"] = "valid"

    try:
        dispatch = _event_for_operation(records, operation_id, "dispatch_fenced")
        if dispatch is None:
            return not_established("operation has no dispatch fence")
        validate_consumption_record(dispatch)
        if not isinstance(dispatch.get("dispatch_token"), str):
            raise ValueError("operation has no attesting dispatch token")
        dispatch_claims = verify_dispatch(
            dispatch["dispatch_token"], public_key=registration.public_key
        )
        if dispatch_claims != dict(dispatch["dispatch_claims"]):
            raise ValueError("signed dispatch claims differ from the canonical fence")
        if any(
            dispatch_claims.get(name) != descriptor.get(name)
            for name in (
                "domain_id",
                "ledger_id",
                "enforcement_point_id",
                "operation_id",
                "request_hash",
                "payload_hash",
                "resource_binding_hash",
            )
        ):
            raise ValueError("dispatch does not join the authorized operation")
        if dispatch.get("decision_hash") != decision.get("record_hash"):
            raise ValueError("dispatch does not name the operation decision")
        claims, egress_records = _action_and_payload(decision, dispatch)
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return failed("dispatch", error)
    checks["dispatch"] = "valid"

    try:
        evidence = decision.get("evidence")
        admission_evidence = (
            evidence.get("authority_admission") if isinstance(evidence, Mapping) else None
        )
        token = (
            admission_evidence.get("artifact") if isinstance(admission_evidence, Mapping) else None
        )
        admission_source: Mapping[str, Any] = decision
        retained_admission_decision = decision.get("decision")
        if isinstance(retained_admission_decision, Mapping):
            admission_source = retained_admission_decision
        if not isinstance(token, str):
            raise ValueError("retained admission token is missing")
        admission = verify_authority_admission(
            token,
            admission_trust_roots=roots,
            expected_domain=expected_domain,
            expected_ledger_id=expected_ledger_id,
            at=_moment(admission_source.get("evaluated_at")),
        ).admission
        if admission is None:
            raise ValueError("retained admission cannot be re-verified")
        _require_admission_adapter(admission, str(decision["adapter_id"]))
        binding = admission.claims.get("resource_binding")
        resource_key = binding.get("outcome_public_key") if isinstance(binding, Mapping) else None
        if (
            not isinstance(binding, Mapping)
            or resource_binding_hash(binding) != descriptor["resource_binding_hash"]
            or claims.get("resource_id") != admission.claims.get("resource_id")
            or not isinstance(resource_key, (bytes, str))
        ):
            raise ValueError("operation resource binding or resource id is not admitted")
        settlement = _event_for_operation(records, operation_id, "settlement")
        if settlement is None:
            return not_established("operation has no terminal settlement")
        validate_consumption_record(settlement)
        if not (
            settlement.get("basis") == "resource_receipt"
            and isinstance(settlement.get("resource_outcome"), str)
        ):
            raise ValueError("terminal settlement lacks a signed resource outcome")
        outcome = verify_resource_outcome(settlement["resource_outcome"], public_key=resource_key)
        accepted_at = outcome.get("accepted_at")
        if accepted_at is not None:
            accepted = _moment(accepted_at)
            if not _moment(claims["authorized_at"]) <= accepted < _moment(claims["not_after"]):
                raise ValueError("resource accepted_at is outside the signed dispatch interval")
        if any(
            outcome.get(name) != claims.get(name)
            for name in _resource_join_fields(claims.get("profile"))
        ):
            raise ValueError("resource outcome does not join the signed dispatch")
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return failed("resource_outcome", error)
    checks["resource_outcome"] = "valid"

    if settlement.get("status") == "committed":
        try:
            if outcome.get("status") != "committed":
                raise ValueError("committed settlement lacks a committed resource outcome")
            if claims.get("profile") == "record-egress/1" and (
                egress_records is None
                or outcome.get("record_count") != len(egress_records)
                or outcome.get("records_hash") != hash_object(egress_records)
            ):
                raise ValueError("record-egress outcome does not bind exact records")
        except (KeyError, TypeError, ValueError, OverflowError) as error:
            return failed(effect_check, error)
        checks[effect_check] = "valid"
    elif outcome.get("status") != "not_executed":
        return failed(effect_check, "released resource receipt is not a not-executed tombstone")

    return ExecutionBundleVerification(all(state == "valid" for state in checks.values()), checks)


__all__ = ["ExecutionBundleVerification", "verify_execution_bundle"]
