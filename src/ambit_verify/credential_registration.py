# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Verification of countersigned registration records for approval credentials.

The PIV credential does not authenticate its own enrolment ceremony.  A
separate organisational Ed25519 enrolment root signs the record, turning the
exported evidence into a chain rather than a self-signed bag of assertions.
The organisational signature attests that the ceremony validated the retained
manufacturer evidence.

``credential_kind`` selects the ceremony to check.  The kind ``piv`` carries
manufacturer attestation for a YubiKey PIV slot; ``secure_enclave`` carries an
Apple Secure Enclave P-256 key behind biometry; ``enforcement_point`` binds one
valve deployment's evidence ledger to the Ed25519 key that signs its head;
``workload`` carries a software P-256 key a running workload holds. Every kind
rests on the registrar's countersignature for its device claims.

Signing, key generation, and enrolment production stay private; this module
only verifies a supplied record against configured enrolment roots.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .hashing import canonical_json_bytes, sha256_hex
from .tokens_slips import ENFORCEMENT_POINT_REGISTRATION_CONTEXT

REGISTRATION_CONTEXT = "ambit.credential.registration.v1"
REGISTRATION_SIGNATURE_PREFIX = "ed25519:"
POSSESSION_CONTEXT = "ambit.credential.possession.v1"
CREDENTIAL_KIND_PIV = "piv"
CREDENTIAL_KIND_SECURE_ENCLAVE = "secure_enclave"
CREDENTIAL_KIND_WORKLOAD = "workload"

#: The registration kind that binds one enforcement point's identity.
ENFORCEMENT_POINT_KIND = "enforcement_point"
#: Characters in a derived enforcement-point id. The audience claim
#: (claim_shapes._validate_audience) refuses any other length.
ENFORCEMENT_POINT_ID_LENGTH = 16

_HEX_DIGITS = frozenset("0123456789abcdef")
_REQUIRED_ACCESS_CONTROL = frozenset({"private_key_usage", "biometry_current_set"})


@dataclass(frozen=True)
class CredentialRegistrationVerification:
    """Result of independently checking a countersigned registration record."""

    valid: bool
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EnforcementPointIdentity:
    """The identity one verified enforcement-point registration binds.

    ``enforcement_point_id`` is derived from the other three fields, never
    chosen, so two points cannot share an id and a point that changes its head
    key becomes a different point.
    """

    enforcement_point_id: str
    ledger_id: str
    trust_root_id: str
    public_key: str


def derive_enforcement_point_id(*, ledger_id: str, trust_root_id: str, public_key_hex: str) -> str:
    """Return the enforcement-point id these three bound facts derive.

    The id is the first sixteen characters of the SHA-256 over the canonical
    JSON of the evidence ledger id, the trust root id, and the hexadecimal
    public key that signs the ledger head. An operator cannot name two points
    the same, and the id moves when the key moves: the identity that signs the
    evidence is the identity a grant is addressed to.

    Raises:
        ValueError: When any of the three facts is empty.
    """
    if not ledger_id or not trust_root_id or not public_key_hex:
        raise ValueError("ledger_id, trust_root_id and public_key_hex must be non-empty")
    return sha256_hex(
        canonical_json_bytes(
            {
                "ledger_id": ledger_id,
                "trust_root_id": trust_root_id,
                "public_key": public_key_hex,
            }
        )
    )[:ENFORCEMENT_POINT_ID_LENGTH]


def _unsigned_record(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "registration_signature"}


def _signed_bytes(record: Mapping[str, Any]) -> bytes:
    payload = base64.urlsafe_b64encode(canonical_json_bytes(_unsigned_record(record))).rstrip(b"=")
    return REGISTRATION_CONTEXT.encode("ascii") + b"." + payload


def possession_message(record: Mapping[str, Any]) -> bytes:
    """Return the bytes the registered key signs to prove it holds the private half.

    The message covers the record without its two signature fields. A
    registrar builds the same bytes at enrolment and a verifier rebuilds them
    from the retained record.
    """
    unsigned = {
        key: value
        for key, value in record.items()
        if key not in {"registration_signature", "proof_of_possession"}
    }
    payload = base64.urlsafe_b64encode(canonical_json_bytes(unsigned)).rstrip(b"=")
    return POSSESSION_CONTEXT.encode("ascii") + b"." + payload


def enforcement_point_possession_message(record: Mapping[str, Any]) -> bytes:
    """Return the bytes an enforcement point signs to prove it holds its head key.

    The message covers the record without its two signature fields, under the
    enforcement-point registration context. The context is part of what is
    signed, so a signature minted for any other purpose never validates here.
    """
    unsigned = {
        key: value
        for key, value in record.items()
        if key not in {"registration_signature", "proof_of_possession"}
    }
    payload = base64.urlsafe_b64encode(canonical_json_bytes(unsigned)).rstrip(b"=")
    return ENFORCEMENT_POINT_REGISTRATION_CONTEXT.encode("ascii") + b"." + payload


def credential_key_fingerprint(public_key: str) -> str:
    """Return the 64-hex fingerprint of a P-256 public point.

    The fingerprint is ``SHA-256`` over the raw uncompressed point bytes, so
    two parties that hold the same public key always name it identically. An
    actor proof carries this value; a verifier recomputes it from the
    registration's own ``public_key`` and never trusts the carried one.

    Raises:
        ValueError: *public_key* is not hexadecimal.
    """
    return sha256_hex(bytes.fromhex(public_key))


def _firmware_tuple(value: object) -> tuple[int, int, int] | None:
    if not isinstance(value, str):
        return None
    try:
        parts = tuple(int(part) for part in value.split("."))
    except ValueError:
        return None
    if len(parts) != 3 or any(part < 0 for part in parts):
        return None
    return parts


def _non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _is_sha256_hex(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value.lower()) <= _HEX_DIGITS


def _check_credential_binding(
    registration: Mapping[str, Any],
    expected_trust_root_id: str,
    expected_public_key: str,
    errors: list[str],
    *,
    credential_kind: str,
) -> None:
    """Check the four facts every registration binds, whatever its kind.

    Only the scheme depends on the kind: a hardware credential is a P-256 key,
    and an enforcement point is the Ed25519 key that signs its ledger head.
    Neither scheme is accepted for the other kind.
    """
    if registration.get("schema_version") != "1":
        errors.append("unsupported registration schema version")
    if registration.get("trust_root_id") != expected_trust_root_id:
        errors.append("credential trust root mismatch")
    expected_scheme = "ed25519" if credential_kind == ENFORCEMENT_POINT_KIND else "p256"
    if registration.get("scheme") != expected_scheme:
        errors.append(f"credential scheme must be {expected_scheme}")
    if registration.get("public_key") != expected_public_key:
        errors.append("credential public key mismatch")


def _check_piv_ceremony(registration: Mapping[str, Any], errors: list[str]) -> None:
    if registration.get("piv_slot") != "9c":
        errors.append("PIV slot must be 9c")
    if registration.get("key_origin") != "on_device_generated":
        errors.append("key origin must be on_device_generated")
    if registration.get("pin_policy") != "always":
        errors.append("PIN policy must be always")
    if registration.get("touch_policy") != "always":
        errors.append("touch policy must be always")
    firmware = _firmware_tuple(registration.get("firmware_version"))
    if firmware is None or firmware < (5, 3, 0):
        errors.append("firmware must be at least 5.3 for policy evidence")
    if not _non_empty_string(registration.get("attestation_certificate")):
        errors.append("attestation certificate missing")
    chain = registration.get("attestation_chain")
    if not isinstance(chain, list) or not chain or not all(isinstance(item, str) for item in chain):
        errors.append("attestation chain missing")


def _possession_proof_holds(registration: Mapping[str, Any]) -> bool:
    proof = registration.get("proof_of_possession")
    public_key_hex = registration.get("public_key")
    if not isinstance(proof, str) or not isinstance(public_key_hex, str):
        return False
    try:
        signature = base64.b64decode(proof, validate=True)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(public_key_hex)
        )
        public_key.verify(signature, possession_message(registration), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature, ValueError:
        return False
    return True


def _check_secure_enclave_ceremony(registration: Mapping[str, Any], errors: list[str]) -> None:
    if registration.get("key_origin") != "secure_enclave_generated":
        errors.append("key origin must be secure_enclave_generated")
    access_control = registration.get("access_control")
    if (
        not isinstance(access_control, list)
        or not all(isinstance(item, str) for item in access_control)
        or not _REQUIRED_ACCESS_CONTROL.issubset(access_control)
    ):
        errors.append("access control lacks biometry")
    if registration.get("biometry_type") != "touch_id":
        errors.append("biometry type must be touch_id")
    if not _non_empty_string(registration.get("device_hardware_uuid")):
        errors.append("device hardware uuid missing")
    if not _non_empty_string(registration.get("device_model")):
        errors.append("device model missing")
    if not _non_empty_string(registration.get("os_version")):
        errors.append("os version missing")
    if not _is_sha256_hex(registration.get("helper_sha256")):
        errors.append("helper digest missing")
    if not _possession_proof_holds(registration):
        errors.append("possession proof invalid")


def _ed25519_possession_proof_holds(registration: Mapping[str, Any]) -> bool:
    proof = registration.get("proof_of_possession")
    public_key_hex = registration.get("public_key")
    if not isinstance(proof, str) or not isinstance(public_key_hex, str):
        return False
    try:
        signature = base64.b64decode(proof, validate=True)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            signature, enforcement_point_possession_message(registration)
        )
    except InvalidSignature, ValueError:
        return False
    return True


def _check_enforcement_point_ceremony(registration: Mapping[str, Any], errors: list[str]) -> None:
    """Check the ledger binding, the derived id, and the proof of possession.

    There is no manufacturer to attest a valve deployment. What the record can
    prove is that the key it names holds its private half, and that the id it
    states is the one the three bound facts derive.
    """
    ledger_id = registration.get("ledger_id")
    trust_root_id = registration.get("trust_root_id")
    public_key = registration.get("public_key")
    if not _non_empty_string(ledger_id):
        errors.append("ledger id missing")
    if not _non_empty_string(public_key):
        errors.append("enforcement point public key missing")
    if not (
        _non_empty_string(ledger_id)
        and _non_empty_string(trust_root_id)
        and _non_empty_string(public_key)
    ):
        return
    expected_id = derive_enforcement_point_id(
        ledger_id=str(ledger_id),
        trust_root_id=str(trust_root_id),
        public_key_hex=str(public_key),
    )
    if registration.get("enforcement_point_id") != expected_id:
        errors.append("enforcement point id does not match the derived value")
    if not _ed25519_possession_proof_holds(registration):
        errors.append("possession proof invalid")


def _check_workload_ceremony(registration: Mapping[str, Any], errors: list[str]) -> None:
    """Check the claims a workload enrolment makes about a software P-256 key.

    No biometry and no access control are required: a workload has no person at
    the keyboard, and demanding a human ceremony of it would make the record a
    fiction. The record must instead name the actor the key acts as, the
    composition it was issued to, the entity that owns it, and the provisioning
    act that placed it, and it must prove possession of the private key.
    """
    if not _non_empty_string(registration.get("subject")):
        errors.append("workload subject missing")
    public_key = registration.get("public_key")
    if not isinstance(public_key, str) or registration.get("key_fingerprint") != (
        _key_fingerprint_or_none(public_key)
    ):
        errors.append("key fingerprint does not match the public key")
    if not _is_sha256_hex(registration.get("composition_hash")):
        errors.append("composition hash missing")
    if not _non_empty_string(registration.get("owner_of_record")):
        errors.append("owner of record missing")
    if not _non_empty_string(registration.get("provisioning_ref")):
        errors.append("provisioning reference missing")
    if not _possession_proof_holds(registration):
        errors.append("possession proof invalid")


def _key_fingerprint_or_none(public_key: object) -> str | None:
    """Return the fingerprint of *public_key*, or ``None`` when it is not a point."""
    if not isinstance(public_key, str):
        return None
    try:
        return credential_key_fingerprint(public_key)
    except ValueError:
        return None


def _check_registered_at(registration: Mapping[str, Any], errors: list[str]) -> None:
    registered_at = registration.get("registered_at")
    if not _non_empty_string(registered_at):
        errors.append("registration timestamp missing")
        return
    try:
        parsed_registered_at = datetime.fromisoformat(str(registered_at).replace("Z", "+00:00"))
    except ValueError:
        errors.append("registration timestamp invalid")
        return
    if parsed_registered_at.tzinfo is None:
        errors.append("registration timestamp must be timezone-aware")


def _check_ceremony(
    registration: Mapping[str, Any], credential_kind: str, errors: list[str]
) -> None:
    """Run the ceremony checks that *credential_kind* selects."""
    if credential_kind == CREDENTIAL_KIND_PIV:
        _check_piv_ceremony(registration, errors)
    elif credential_kind == CREDENTIAL_KIND_SECURE_ENCLAVE:
        _check_secure_enclave_ceremony(registration, errors)
    elif credential_kind == ENFORCEMENT_POINT_KIND:
        _check_enforcement_point_ceremony(registration, errors)
    elif credential_kind == CREDENTIAL_KIND_WORKLOAD:
        _check_workload_ceremony(registration, errors)
    else:
        errors.append("credential kind unsupported")


def _check_registration_signature(
    registration: Mapping[str, Any], registration_public_keys: Mapping[str, str], errors: list[str]
) -> None:
    """Check the organisational countersignature under a configured enrolment root."""
    registration_root_id = registration.get("registration_root_id")
    public_key_hex = (
        registration_public_keys.get(registration_root_id)
        if isinstance(registration_root_id, str)
        else None
    )
    if not isinstance(public_key_hex, str) or not public_key_hex:
        errors.append("registration root is not configured")
        return
    signature = registration.get("registration_signature")
    if not isinstance(signature, str) or not signature.startswith(REGISTRATION_SIGNATURE_PREFIX):
        errors.append("registration signature missing")
        return
    try:
        signature_bytes = base64.b64decode(
            signature[len(REGISTRATION_SIGNATURE_PREFIX) :], validate=True
        )
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            signature_bytes, _signed_bytes(registration)
        )
    except InvalidSignature, ValueError:
        errors.append("registration signature invalid")


def verify_credential_registration(
    registration: Mapping[str, Any],
    *,
    registration_public_keys: Mapping[str, str],
    expected_trust_root_id: str,
    expected_public_key: str,
) -> CredentialRegistrationVerification:
    """Verify registration binding, ceremony claims, and organisational signature.

    ``credential_kind`` selects the ceremony and the scheme. An absent kind
    reads as ``piv``. Use :func:`verify_enforcement_point_registration` for the
    ``enforcement_point`` kind: it reads the bound facts out of the record
    itself and returns the identity they carry.
    """
    if not isinstance(registration, Mapping):
        return CredentialRegistrationVerification(
            valid=False, errors=["credential registration is not an object"]
        )
    if not isinstance(registration_public_keys, Mapping):
        return CredentialRegistrationVerification(
            valid=False, errors=["credential registration roots are not an object"]
        )
    errors: list[str] = []
    raw_kind = registration.get("credential_kind", CREDENTIAL_KIND_PIV)
    credential_kind = raw_kind if isinstance(raw_kind, str) else ""
    _check_credential_binding(
        registration,
        expected_trust_root_id,
        expected_public_key,
        errors,
        credential_kind=credential_kind,
    )
    _check_ceremony(registration, credential_kind, errors)
    _check_registered_at(registration, errors)
    _check_registration_signature(registration, registration_public_keys, errors)
    return CredentialRegistrationVerification(valid=not errors, errors=errors)


def verify_enforcement_point_registration(
    record: Mapping[str, Any],
    *,
    registration_public_keys: Mapping[str, str],
) -> EnforcementPointIdentity:
    """Verify an enforcement-point registration and return the identity it binds.

    The record states its own ledger id, trust root and public key, so this
    function reads them from the record and then checks that they hold
    together: the derived id must match, the point's proof of possession must
    verify under the stated key, and the registrar's countersignature must
    verify under a configured enrolment root.

    Raises:
        ValueError: With every reason the record is refused.
    """
    if not isinstance(record, Mapping):
        raise ValueError("enforcement point registration refused: record is not an object")
    if not isinstance(registration_public_keys, Mapping):
        raise ValueError(
            "enforcement point registration refused: registration roots are not an object"
        )
    if record.get("credential_kind") != ENFORCEMENT_POINT_KIND:
        raise ValueError("enforcement point registration refused: credential kind unsupported")
    ledger_id = record.get("ledger_id")
    trust_root_id = record.get("trust_root_id")
    public_key = record.get("public_key")
    if not (
        _non_empty_string(ledger_id)
        and _non_empty_string(trust_root_id)
        and _non_empty_string(public_key)
    ):
        raise ValueError(
            "enforcement point registration refused: ledger_id, trust_root_id and "
            "public_key must be non-empty strings"
        )
    verification = verify_credential_registration(
        record,
        registration_public_keys=registration_public_keys,
        expected_trust_root_id=str(trust_root_id),
        expected_public_key=str(public_key),
    )
    if not verification.valid:
        raise ValueError(
            "enforcement point registration refused: " + "; ".join(verification.errors)
        )
    return EnforcementPointIdentity(
        enforcement_point_id=str(record["enforcement_point_id"]),
        ledger_id=str(ledger_id),
        trust_root_id=str(trust_root_id),
        public_key=str(public_key),
    )


def _registered_after(registration: Mapping[str, Any], moment: datetime) -> bool:
    """Return whether the record's ``registered_at`` is later than *moment*."""
    registered_at = datetime.fromisoformat(
        str(registration["registered_at"]).replace("Z", "+00:00")
    )
    return registered_at.astimezone(UTC) > moment.astimezone(UTC)


def credential_registration_error(
    trust_roots: Mapping[str, Any],
    trust_root_id: str,
    *,
    registration_public_keys: Mapping[str, str] | None,
    evaluation_time: datetime | None = None,
) -> str | None:
    """Return why *trust_root_id* is not a registered credential, or ``None``.

    A P-256 trust root is a hardware credential, and its enrolment ceremony is
    what a signature alone cannot prove. Every path that accepts such a
    signature as authority calls this first.

    The check does not apply to a root whose scheme is not ``p256``, nor to a
    root the caller did not supply: neither one verified a P-256 signature, so
    both return ``None``. A registration is missing, not accepted, when the
    root states no registration or no enrolment roots are configured.

    *evaluation_time*, when given, is the moment the credential acted. A record
    enrolled after that moment did not exist when the credential was used.
    """
    if not isinstance(trust_roots, Mapping):
        return "credential trust roots invalid"
    root = trust_roots.get(trust_root_id)
    if not isinstance(root, Mapping) or root.get("scheme") != "p256":
        return None
    registration = root.get("registration")
    public_key = root.get("public_key")
    if not isinstance(registration, Mapping) or not isinstance(public_key, str):
        return "credential registration missing"
    if not registration_public_keys:
        return "credential registration roots missing"
    verification = verify_credential_registration(
        registration,
        registration_public_keys=registration_public_keys,
        expected_trust_root_id=trust_root_id,
        expected_public_key=public_key,
    )
    if not verification.valid:
        return "credential registration invalid: " + "; ".join(verification.errors)
    if evaluation_time is not None and _registered_after(registration, evaluation_time):
        return "credential registration postdates use"
    return None


def require_registered_credential(
    trust_roots: Mapping[str, Any],
    trust_root_id: str,
    *,
    registration_public_keys: Mapping[str, str] | None,
    evaluation_time: datetime | None = None,
) -> None:
    """Raise unless *trust_root_id* is a registered credential, or needs no registration.

    The raising form of :func:`credential_registration_error`, for the paths
    that refuse rather than report. Each caller adds its own refusal prefix.

    Raises:
        ValueError: With the reason the credential is not registered.
    """
    error = credential_registration_error(
        trust_roots,
        trust_root_id,
        registration_public_keys=registration_public_keys,
        evaluation_time=evaluation_time,
    )
    if error is not None:
        raise ValueError(error)


__all__ = [
    "CREDENTIAL_KIND_PIV",
    "CREDENTIAL_KIND_SECURE_ENCLAVE",
    "CREDENTIAL_KIND_WORKLOAD",
    "ENFORCEMENT_POINT_ID_LENGTH",
    "ENFORCEMENT_POINT_KIND",
    "POSSESSION_CONTEXT",
    "REGISTRATION_CONTEXT",
    "CredentialRegistrationVerification",
    "EnforcementPointIdentity",
    "credential_key_fingerprint",
    "credential_registration_error",
    "derive_enforcement_point_id",
    "enforcement_point_possession_message",
    "possession_message",
    "require_registered_credential",
    "verify_credential_registration",
    "verify_enforcement_point_registration",
]
