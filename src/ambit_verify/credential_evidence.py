# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Independent verification of credential artefacts retained in receipt schema v3 and v4.

Schema v3 retains the delegation and approval artefacts. Schema v4 adds the
actor's own identity proof, so a stranger holding the receipt, the trust roots,
and the organisational enrolment roots can check who acted as well as what was
authorised. Every input is retained evidence or configuration: no clock is
read, and no live state is consulted.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .actor_proof import verify_actor_proof
from .credential_registration import verify_credential_registration
from .evidence_schema import SUPPORTED_EVIDENCE_SCHEMA_VERSIONS
from .models import ApprovalClaims, DelegationClaims
from .tokens import MAX_VERIFICATION_CHAIN_DEPTH, replay_delegation_chain
from .tokens_slips import (
    SLIP_CONTEXT_APPROVAL,
    SLIP_CONTEXT_DELEGATION,
    parse_approval,
    parse_delegation,
    verified_slip_scheme,
    verified_slip_trust_root_id,
)


@dataclass(frozen=True)
class ReceiptCredentialVerification:
    """Result of verifying retained delegation, approval, and actor artefacts.

    ``actor_proof_valid`` is ``True`` when the receipt carried no actor proof:
    a v3 receipt, or a decision made outside constitutional mode, states no
    identity claim to check.
    """

    valid: bool
    delegation_valid: bool
    approval_valid: bool
    escalation_link_valid: bool
    errors: list[str] = field(default_factory=list)
    actor_proof_valid: bool = True
    origin_admission: str = "not_established"


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _decision(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    nested = _mapping(receipt.get("decision"))
    return nested if nested else receipt


def _evaluation_time(receipt: Mapping[str, Any]) -> datetime:
    decision = _decision(receipt)
    value = decision.get("evaluated_at")
    if not isinstance(value, str):
        raise ValueError("receipt is missing decision.evaluated_at")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _check_registration(
    signed_root: Any,
    *,
    label: str,
    trust_roots: Mapping[str, Any],
    registration_public_keys: Mapping[str, str] | None,
    evaluation_time: datetime,
    errors: list[str],
) -> None:
    """Append each registration failure of the P-256 root *signed_root* to *errors*."""
    root = trust_roots.get(signed_root)
    registration = root.get("registration") if isinstance(root, Mapping) else None
    public_key = root.get("public_key") if isinstance(root, Mapping) else None
    if not isinstance(registration, Mapping) or not isinstance(public_key, str):
        errors.append(f"{label}.credential registration missing")
    elif registration_public_keys is None:
        errors.append(f"{label}.credential registration roots missing")
    else:
        verification = verify_credential_registration(
            registration,
            registration_public_keys=registration_public_keys,
            expected_trust_root_id=signed_root,
            expected_public_key=public_key,
        )
        if not verification.valid:
            errors.append(
                f"{label}.credential registration invalid: " + "; ".join(verification.errors)
            )
        else:
            registered_at = registration.get("registered_at")
            try:
                parsed_registered_at = (
                    datetime.fromisoformat(str(registered_at).replace("Z", "+00:00"))
                    if isinstance(registered_at, str)
                    else None
                )
            except ValueError:
                parsed_registered_at = None
            if parsed_registered_at is None or parsed_registered_at.tzinfo is None:
                errors.append(f"{label}.credential registration timestamp invalid")
            elif parsed_registered_at.astimezone(UTC) > evaluation_time:
                errors.append(f"{label}.credential registration postdates decision")


def _artifact(
    block: Mapping[str, Any],
    *,
    expected_context: str,
    evaluation_time: datetime,
    trust_roots: Mapping[str, Any],
    registration_public_keys: Mapping[str, str] | None,
    errors: list[str],
    label: str,
) -> str | None:
    evidence = block if "artifact" in block else _mapping(block.get("credential_evidence"))
    artifact = evidence.get("artifact")
    if not isinstance(artifact, str) or not artifact:
        errors.append(f"{label}.credential_evidence.artifact missing")
        return None
    try:
        signed_scheme = verified_slip_scheme(artifact)
        signed_root = verified_slip_trust_root_id(artifact)
    except TypeError, ValueError, UnicodeError:
        signed_scheme, signed_root = None, None
        errors.append(f"{label}.credential_evidence.artifact is malformed")
    if evidence.get("scheme") != signed_scheme or signed_scheme not in {"ed25519", "p256"}:
        errors.append(f"{label}.credential_evidence.scheme mismatch")
    if evidence.get("proof_class") != "public_key_verifiable":
        errors.append(f"{label}.credential_evidence.proof_class is not public_key_verifiable")
    if evidence.get("verification_context") != expected_context:
        errors.append(f"{label}.credential_evidence.verification_context mismatch")
    block_root = block.get("trust_root_id")
    if evidence.get("trust_root_id") != signed_root or block_root != signed_root:
        errors.append(f"{label}.credential_evidence.trust_root_id mismatch")
    if signed_scheme == "p256" and signed_root is not None:
        _check_registration(
            signed_root,
            label=label,
            trust_roots=trust_roots,
            registration_public_keys=registration_public_keys,
            evaluation_time=evaluation_time,
            errors=errors,
        )
    return artifact


def _verify_retained_actor_proof(
    receipt: Mapping[str, Any],
    trust_roots: Mapping[str, Any],
    *,
    registration_public_keys: Mapping[str, str] | None,
    audience: str | None,
    evaluated_at: datetime,
    errors: list[str],
) -> bool:
    """Re-verify actor identity and its duplicated decision summaries."""
    evidence = _mapping(receipt.get("evidence"))
    carried = evidence.get("actor_proof")
    decision = _decision(receipt)
    summary_fingerprint = decision.get("actor_key_fingerprint")
    summary_nonce = decision.get("actor_proof_nonce")
    if carried is None:
        if summary_fingerprint is not None or summary_nonce is not None:
            errors.append("actor proof summaries are present without retained proof")
            return False
        return True
    if not isinstance(carried, Mapping):
        errors.append("retained actor proof is not an object")
        return False
    proof = carried
    carried_audience = proof.get("audience")
    expected_audience = audience if audience is not None else str(carried_audience or "")
    verification = verify_actor_proof(
        {"actor_id": decision.get("actor_id"), "actor_proof": dict(proof)},
        trust_roots,
        request_hash=str(proof.get("request_hash") or ""),
        audience=expected_audience,
        now=evaluated_at,
        registration_public_keys=registration_public_keys,
    )
    if not verification.valid:
        errors.append(f"actor proof did not verify: {verification.refusal}")
        return False
    if summary_fingerprint != verification.key_fingerprint or summary_nonce != verification.nonce:
        errors.append("actor proof summaries do not match the verified proof")
        return False
    return True


def _unverified(error: Any) -> ReceiptCredentialVerification:
    """Return the result for a receipt that cannot be checked at all, with its one error."""
    return ReceiptCredentialVerification(
        valid=False,
        delegation_valid=False,
        approval_valid=False,
        escalation_link_valid=False,
        errors=[error],
        actor_proof_valid=False,
    )


def _delegation_chain_valid(
    delegation: Mapping[str, Any],
    delegation_claims: DelegationClaims,
    trust_roots: Mapping[str, Any],
    *,
    registration_public_keys: Mapping[str, str] | None,
    evaluated_at: datetime,
    errors: list[str],
) -> bool:
    """Verify each retained parent grant and replay the chain under its recorded rule version.

    Parent evidence is bounded by the verifier resource profile before any
    retained parent artefact is acquired or signature is checked.
    """
    chain_entries = delegation.get("credential_chain")
    if not isinstance(chain_entries, list):
        errors.append("delegation.credential_chain must be a list")
        delegation_valid = False
    elif (
        delegation_claims.chain_depth > MAX_VERIFICATION_CHAIN_DEPTH
        or len(chain_entries) > MAX_VERIFICATION_CHAIN_DEPTH
    ):
        errors.append(
            f"delegation chain exceeds verifier resource limit {MAX_VERIFICATION_CHAIN_DEPTH}"
        )
        delegation_valid = False
    else:
        parent_artifacts: list[str] = []
        for index, entry in enumerate(chain_entries):
            artifact = _artifact(
                _mapping(entry),
                expected_context=SLIP_CONTEXT_DELEGATION,
                evaluation_time=evaluated_at,
                trust_roots=trust_roots,
                registration_public_keys=registration_public_keys,
                errors=errors,
                label=f"delegation.credential_chain[{index}]",
            )
            if artifact is not None:
                parent_artifacts.append(artifact)
        recorded_rule_version = recorded_chain_rule_version(delegation)
        chain = replay_delegation_chain(
            delegation_claims,
            parent_artifacts,
            recorded_rule_version=recorded_rule_version,
            evaluation_time=evaluated_at,
            trust_roots=trust_roots,
        )
        if not chain.supported:
            errors.append(
                f"delegation chain rule version is not supported: {recorded_rule_version!r}"
            )
        delegation_valid = (
            chain.supported and chain.valid and len(parent_artifacts) == len(chain_entries)
        )
    return delegation_valid


def _verify_delegation(
    receipt: Mapping[str, Any],
    trust_roots: Mapping[str, Any],
    *,
    registration_public_keys: Mapping[str, str] | None,
    evaluated_at: datetime,
    errors: list[str],
) -> bool:
    """Verify the retained delegation artefact and its chain; append each failure to *errors*."""
    raw_delegation = receipt.get("delegation")
    if raw_delegation is None:
        delegation: Mapping[str, Any] = {}
    elif isinstance(raw_delegation, Mapping):
        delegation = raw_delegation
    else:
        errors.append("delegation evidence is not an object")
        return False
    delegation_present = "artifact" in delegation or "credential_evidence" in delegation
    delegation_valid = not delegation_present
    delegation_artifact = None
    if delegation_present:
        delegation_artifact = _artifact(
            delegation,
            expected_context=SLIP_CONTEXT_DELEGATION,
            evaluation_time=evaluated_at,
            trust_roots=trust_roots,
            registration_public_keys=registration_public_keys,
            errors=errors,
            label="delegation",
        )
    if delegation_artifact is not None:
        delegation_valid, delegation_claims = parse_delegation(
            delegation_artifact, trust_roots=trust_roots
        )
        if delegation_valid and delegation_claims is not None:
            delegation_valid = _delegation_chain_valid(
                delegation,
                delegation_claims,
                trust_roots,
                registration_public_keys=registration_public_keys,
                evaluated_at=evaluated_at,
                errors=errors,
            )
        if not delegation_valid:
            errors.append("delegation artefact or chain did not verify")
    return delegation_valid


def _escalation_link_valid(
    escalation_record: Mapping[str, Any], approval_claims: ApprovalClaims, request_fingerprint: Any
) -> bool:
    """Return whether *escalation_record* is the ESCALATE record the approval names."""
    raw_escalation_decision = escalation_record.get("decision")
    escalation_outcome = (
        raw_escalation_decision.get("outcome")
        if isinstance(raw_escalation_decision, Mapping)
        else raw_escalation_decision
    )
    escalation_link_valid = (
        escalation_record.get("record_hash") == approval_claims.escalation_record_hash
        and str(escalation_outcome or "").lower() == "escalate"
        and escalation_record.get("request_fingerprint") == request_fingerprint
    )
    return escalation_link_valid


def _verify_approval(
    receipt: Mapping[str, Any],
    trust_roots: Mapping[str, Any],
    escalation_record: Mapping[str, Any] | None,
    *,
    registration_public_keys: Mapping[str, str] | None,
    evaluated_at: datetime,
    errors: list[str],
) -> tuple[bool, bool]:
    """Verify the approval artefact and its escalation link; append each failure to *errors*.

    Returns whether the approval binds the decision and whether the escalation record verifies.
    """
    raw_approval = receipt.get("approval")
    if raw_approval is None:
        approval: Mapping[str, Any] = {}
    elif isinstance(raw_approval, Mapping):
        approval = raw_approval
    else:
        errors.append("approval evidence is not an object")
        return False, False
    approval_present = "artifact" in approval or "credential_evidence" in approval
    approval_valid = not approval_present
    escalation_link_valid = not approval_present
    if approval_present:
        approval_artifact = _artifact(
            approval,
            expected_context=SLIP_CONTEXT_APPROVAL,
            evaluation_time=evaluated_at,
            trust_roots=trust_roots,
            registration_public_keys=registration_public_keys,
            errors=errors,
            label="approval",
        )
        if approval_artifact is not None:
            approval_valid, approval_claims = parse_approval(
                approval_artifact, trust_roots=trust_roots
            )
            if approval_valid and approval_claims is not None:
                decision = _decision(receipt)
                request_fingerprint = decision.get("request_fingerprint")
                approval_valid = (
                    approval_claims.request_fingerprint == request_fingerprint
                    and approval_claims.escalation_record_hash
                    == approval.get("escalation_record_hash")
                    and approval_claims.nbf <= evaluated_at <= approval_claims.exp
                )
                if escalation_record is not None:
                    escalation_link_valid = _escalation_link_valid(
                        escalation_record, approval_claims, request_fingerprint
                    )
            if not approval_valid:
                errors.append("approval artefact did not verify or bind to the decision")
        if not escalation_link_valid:
            errors.append("approval escalation record did not verify")
    return approval_valid, escalation_link_valid


def _origin_admission(
    evidence: Mapping[str, Any],
    schema_version: Any,
    *,
    admission_trust_roots: Mapping[str, Any] | None,
    evaluated_at: datetime,
    errors: list[str],
) -> str:
    """Verify the retained authority admission block for a schema-5/6 receipt."""
    if schema_version not in {"5", "6"} or admission_trust_roots is None:
        return "not_established"
    from .admission import verify_authority_admission

    admission_evidence = _mapping(evidence.get("authority_admission"))
    result = verify_authority_admission(
        admission_evidence.get("artifact"),
        admission_trust_roots=admission_trust_roots,
        expected_domain=admission_evidence.get("domain_id"),
        expected_ledger_id=admission_evidence.get("ledger_id"),
        at=evaluated_at,
        minimum_version=admission_evidence.get("minimum_version"),
        expected_previous_hash=admission_evidence.get("expected_previous_hash"),
    )
    if not result.valid or result.admission is None:
        errors.append("origin admission did not verify: " + "; ".join(result.errors))
        return "failed"
    if admission_evidence.get("origin_grant_hash") not in result.admission.claims.get(
        "origin_grant_hashes", ()
    ):
        errors.append("retained origin grant hash is not covered by the verified admission")
        return "failed"
    return "valid"


def verify_receipt_credentials(
    receipt: Mapping[str, Any],
    trust_roots: Mapping[str, Any],
    *,
    registration_public_keys: Mapping[str, str] | None,
    escalation_record: Mapping[str, Any] | None,
    audience: str | None = None,
    admission_trust_roots: Mapping[str, Any] | None = None,
) -> ReceiptCredentialVerification:
    """Verify retained credentials without trusting recorded validity flags.

    v3/v4 preserve their historical optional-absence meaning when they carry
    no execution profile. A profile explicitly marked ``simulation`` or
    ``nonconsequential`` remains a non-live record; a profile marked ``live``
    and every v5/v6 receipt must retain a holder proof. This prevents a live
    producer from silently downgrading a missing proof into a historical
    contract.

    Pass the referenced record for an approval-bearing receipt. Pass ``None``
    explicitly only when the receipt carries no approval credential. P-256
    evidence additionally requires the organisational registration roots.

    *audience* is the evidence ledger identifier the receipt was written to.
    When given, a retained actor proof must name it. When ``None``, the proof's
    own audience is accepted, and the signature still covers it -- so the check
    proves the proof was made for some ledger, not for this one. Pass the
    ledger id whenever the caller knows it.

    A ``valid`` result does not establish origin. Check ``origin_admission == "valid"`` for that.
    """
    if not isinstance(receipt, Mapping):
        return _unverified("receipt is not an object")
    if not isinstance(trust_roots, Mapping):
        return _unverified("credential trust roots are not an object")
    if registration_public_keys is not None and not isinstance(registration_public_keys, Mapping):
        return _unverified("credential registration roots are not an object")
    errors: list[str] = []
    evidence = _mapping(receipt.get("evidence"))
    schema_version = evidence.get("schema_version")
    if schema_version not in SUPPORTED_EVIDENCE_SCHEMA_VERSIONS:
        return _unverified("unsupported evidence schema version")
    execution_profile = evidence.get("execution_profile")
    proof_required = schema_version in {"5", "6"} or execution_profile == "live"
    if proof_required and not isinstance(evidence.get("actor_proof"), Mapping):
        return _unverified(
            f"schema-v{schema_version} live evidence requires a retained actor proof"
        )
    if execution_profile is not None and execution_profile not in {
        "live",
        "simulation",
        "nonconsequential",
    }:
        return _unverified("evidence execution profile is unsupported")

    try:
        evaluated_at = _evaluation_time(receipt)
    except (TypeError, ValueError) as exc:
        return _unverified(str(exc))

    actor_proof_valid = _verify_retained_actor_proof(
        receipt,
        trust_roots,
        registration_public_keys=registration_public_keys,
        audience=audience,
        evaluated_at=evaluated_at,
        errors=errors,
    )

    delegation_valid = _verify_delegation(
        receipt,
        trust_roots,
        registration_public_keys=registration_public_keys,
        evaluated_at=evaluated_at,
        errors=errors,
    )

    approval_valid, escalation_link_valid = _verify_approval(
        receipt,
        trust_roots,
        escalation_record,
        registration_public_keys=registration_public_keys,
        evaluated_at=evaluated_at,
        errors=errors,
    )

    origin_admission = _origin_admission(
        evidence,
        schema_version,
        admission_trust_roots=admission_trust_roots,
        evaluated_at=evaluated_at,
        errors=errors,
    )

    valid = (
        delegation_valid
        and approval_valid
        and escalation_link_valid
        and actor_proof_valid
        and not errors
    )
    return ReceiptCredentialVerification(
        valid=valid,
        delegation_valid=delegation_valid,
        approval_valid=approval_valid,
        escalation_link_valid=escalation_link_valid,
        errors=errors,
        actor_proof_valid=actor_proof_valid,
        origin_admission=origin_admission,
    )


def recorded_chain_rule_version(delegation: Mapping[str, Any]) -> str | None:
    """Return the chain rule version that a receipt's delegation block recorded.

    An absent ``chain_rule_version`` key marks a receipt from before the key
    existed, so the result is ``None`` and replay applies the legacy rule. A
    present value that is not a string names no rule. The result is then a
    label that no build supports, so replay refuses the chain and does not
    apply the legacy rule.

    Args:
        delegation: The receipt's ``delegation`` block.

    Returns:
        The recorded version string, ``None`` for an absent key, or an
        unsupported label for a value that is not a string.
    """
    if "chain_rule_version" not in delegation:
        return None
    value = delegation["chain_rule_version"]
    if isinstance(value, str):
        return value
    return f"non-string {type(value).__name__}"


__all__ = [
    "ReceiptCredentialVerification",
    "recorded_chain_rule_version",
    "verify_receipt_credentials",
]
