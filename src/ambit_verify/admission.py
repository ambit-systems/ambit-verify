# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Explicit original-authority admission, anchored outside retained evidence.

Admission recognizes exact originating grants for a principal/resource domain.
It is not a claim that a key label proves organizational authority. The caller
must obtain admission roots, expected domain and accepted version floor through
its own trusted channel. Historical acceptance is not current revocation truth.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

from .actor_proof import actor_proof_request_hash, verify_actor_proof
from .consumption import required_account_bounds
from .credential_evidence import verify_receipt_credentials
from .hashing import canonical_json_bytes, hash_object, sha256_hex
from .models import DelegationClaims
from .ratification_bundle import GRANT_FILE, verify_ratification_bundle
from .resource_protocol import (
    CUSTOMER_DELETE_PROFILE,
    git_ref_is_covered,
    resource_binding_hash,
)
from .revocation_types import verify_revocation_attestation
from .status_evidence import (
    _status_from_evidence,
    _status_public_key,
    epoch_regression,
    verify_cumulative_status_payload,
)
from .tokens import validate_delegation_chain
from .tokens_slips import _verified_slip_signer_id, _verify_slip, parse_delegation

ADMISSION_CONTEXT = "ambit:authority-admission:v1"
ADMISSION_SCHEMA_VERSION = 3
SUPPORTED_ADMISSION_SCHEMA_VERSIONS = frozenset({1, 2, ADMISSION_SCHEMA_VERSION})
_HEX = frozenset("0123456789abcdef")
_FIELDS = frozenset(
    {
        "schema_version",
        "domain_id",
        "principal_id",
        "resource_id",
        "ledger_id",
        "enforcement_point_id",
        "version",
        "previous_admission_hash",
        "nbf",
        "exp",
        "credential_trust_roots",
        "credential_registration_public_keys",
        "revocation_attestation_public_keys",
        "cumulative_attestation_public_keys",
        "origin_grant_hashes",
        "resource_binding",
        "max_revocation_age_ms",
        "max_cumulative_age_ms",
        "max_actor_proof_age_seconds",
        "trust_root_id",
    }
)
_ROOT_FIELDS = (
    "credential_trust_roots",
    "credential_registration_public_keys",
    "revocation_attestation_public_keys",
    "cumulative_attestation_public_keys",
)


@dataclass(frozen=True, slots=True)
class AuthorityAdmission:
    """A verified signed admission; callers must not replace its trusted inputs."""

    claims: Mapping[str, Any]
    admission_hash: str
    trust_configuration_hash: str
    nbf: datetime
    exp: datetime

    @property
    def version(self) -> int:
        """Return the signed admission schema version."""
        return int(self.claims["version"])

    @property
    def domain_id(self) -> str:
        """Return the signed admission domain identifier."""
        return str(self.claims["domain_id"])


@dataclass(frozen=True, slots=True)
class AdmissionVerification:
    """Outcome of validating a signed authority admission."""

    valid: bool
    admission: AuthorityAdmission | None
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class OriginVerification:
    """Outcome of validating the origin portion of an admitted path."""

    valid: bool
    origin_grant_hash: str | None
    errors: tuple[str, ...] = ()


def _digest(value: Any, *, size: int = 64) -> bool:
    return isinstance(value, str) and len(value) == size and set(value) <= _HEX


def _positive_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _moment(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("admission timestamps must be strings")
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("admission timestamps require an explicit timezone")
    return moment.astimezone(UTC)


def _shape_errors(claims: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    version = claims.get("schema_version")
    valid_schema_version = (
        isinstance(version, int)
        and not isinstance(version, bool)
        and version in SUPPORTED_ADMISSION_SCHEMA_VERSIONS
    )
    if not valid_schema_version:
        errors.append("unsupported admission schema version")
    if set(claims) != _FIELDS:
        errors.append(f"admission fields do not match schema version {version!r}")
    for name in ("domain_id", "principal_id", "resource_id", "ledger_id", "trust_root_id"):
        value = claims.get(name)
        if not isinstance(value, str) or not value or value != value.strip():
            errors.append(f"admission {name} must be nonempty canonical text")
    if not _digest(claims.get("enforcement_point_id"), size=16):
        errors.append("admission enforcement_point_id is invalid")
    for name in (
        "version",
        "max_revocation_age_ms",
        "max_cumulative_age_ms",
        "max_actor_proof_age_seconds",
    ):
        if not _positive_integer(claims.get(name)):
            errors.append(f"admission {name} must be a positive integer")
    previous = claims.get("previous_admission_hash")
    if claims.get("version") == 1:
        if previous is not None:
            errors.append("first admission must not name a predecessor")
    elif not _digest(previous):
        errors.append("subsequent admission must name its predecessor hash")
    origins = claims.get("origin_grant_hashes")
    if not isinstance(origins, list) or not origins or any(not _digest(value) for value in origins):
        errors.append("admission must bind exact originating grant hashes")
    elif len(set(origins)) != len(origins):
        errors.append("admission contains duplicate originating grant hashes")
    for name in _ROOT_FIELDS:
        roots = claims.get(name)
        if not isinstance(roots, Mapping) or not roots:
            errors.append(f"admission {name} must contain explicit public roots")
            continue
        for root_id, root in roots.items():
            if not isinstance(root_id, str) or not root_id:
                errors.append(f"admission {name} contains an invalid root identifier")
            if name == "credential_trust_roots":
                if not isinstance(root, Mapping) or root.get("scheme") not in ("ed25519", "p256"):
                    errors.append(f"admission {name} contains an invalid credential root")
                elif not isinstance(root.get("public_key"), str):
                    errors.append(f"admission {name} lacks a public key")
                elif set(root) - {"scheme", "public_key", "registration"}:
                    errors.append(f"admission {name} contains unsupported credential fields")
            elif not _digest(root):
                errors.append(f"admission {name} requires Ed25519 public keys")
    binding = claims.get("resource_binding")
    binding_fields = {"adapter_id", "downstream_url", "downstream_path", "receipt_public_key"}
    if valid_schema_version and version in {2, ADMISSION_SCHEMA_VERSION}:
        binding_fields |= {"outcome_profile", "outcome_public_key"}
    if (
        version == ADMISSION_SCHEMA_VERSION
        and isinstance(binding, Mapping)
        and binding.get("outcome_profile") == "git-publication/1"
    ):
        binding_fields |= {"git_remote", "git_ref"}
    if not isinstance(binding, Mapping) or set(binding) != binding_fields:
        errors.append("admission resource binding fields are invalid")
    else:
        for name in ("adapter_id", "downstream_url", "downstream_path"):
            if not isinstance(binding[name], str) or not binding[name]:
                errors.append(f"admission resource binding {name} is invalid")
        if not _digest(binding["receipt_public_key"]):
            errors.append("admission resource receipt public key is invalid")
        if valid_schema_version and version in {2, ADMISSION_SCHEMA_VERSION}:
            outcome_profile = binding["outcome_profile"]
            outcome_public_key = binding["outcome_public_key"]
            if not (
                (outcome_profile is None and outcome_public_key is None)
                or (
                    outcome_profile
                    in {"record-egress/1", "git-publication/1", CUSTOMER_DELETE_PROFILE}
                    and _digest(outcome_public_key)
                    and outcome_public_key != binding["receipt_public_key"]
                )
            ):
                errors.append("admission resource outcome attestation pair is invalid")
            try:
                if valid_schema_version and version in {2, ADMISSION_SCHEMA_VERSION}:
                    resource_binding_hash(binding)
            except TypeError, ValueError:
                errors.append("admission resource binding is invalid")
            if outcome_profile == "git-publication/1" and version != ADMISSION_SCHEMA_VERSION:
                errors.append("admission Git resource binding is invalid")
            elif version == ADMISSION_SCHEMA_VERSION and outcome_profile != "git-publication/1":
                errors.append("admission schema3 requires the Git publication profile")
    return errors


def validate_authority_admission_claims(
    claims: Mapping[str, Any],
) -> tuple[datetime, datetime]:
    """Validate signature-independent admission claims and return their UTC interval."""
    errors = _shape_errors(claims)
    if errors:
        raise ValueError("; ".join(errors))
    nbf, exp = _moment(claims["nbf"]), _moment(claims["exp"])
    if nbf > exp:
        raise ValueError("admission validity interval is inverted")
    return nbf, exp


def verify_authority_admission(
    token: str,
    *,
    admission_trust_roots: Mapping[str, Any],
    expected_domain: str,
    expected_ledger_id: str,
    at: datetime,
    minimum_version: int = 1,
    expected_previous_hash: str | None = None,
) -> AdmissionVerification:
    """Verify admitted scope at a caller-selected historical or current moment.

    Roots and rollback floor are never read from the token. When admitting a
    successor into an existing history, supply the accepted predecessor hash;
    a caller checking a previously anchored historical admission may omit it.
    """
    if not isinstance(token, str) or not token:
        return AdmissionVerification(False, None, ("authority admission token is missing",))
    if not isinstance(admission_trust_roots, Mapping) or not admission_trust_roots:
        return AdmissionVerification(
            False, None, ("independently accepted admission roots are missing",)
        )
    if (
        not isinstance(expected_domain, str)
        or not expected_domain
        or expected_domain != expected_domain.strip()
        or not isinstance(expected_ledger_id, str)
        or not expected_ledger_id
        or expected_ledger_id != expected_ledger_id.strip()
    ):
        return AdmissionVerification(
            False, None, ("expected admission domain or ledger is invalid",)
        )
    if not _positive_integer(minimum_version):
        return AdmissionVerification(False, None, ("invalid independently accepted version floor",))
    if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() is None:
        return AdmissionVerification(
            False, None, ("admission comparison time requires a timezone",)
        )
    ok, claims = _verify_slip(
        token,
        admission_trust_roots,
        context=ADMISSION_CONTEXT,
        allowed_schemes=frozenset({"ed25519"}),
    )
    if not ok or not isinstance(claims, Mapping):
        return AdmissionVerification(
            False, None, ("admission signature does not verify under caller trust",)
        )
    errors: list[str] = []
    try:
        nbf, exp = validate_authority_admission_claims(claims)
        if not nbf <= at <= exp:
            errors.append("admission does not cover the comparison time")
        if claims["domain_id"] != expected_domain or claims["ledger_id"] != expected_ledger_id:
            errors.append("admission domain or ledger differs from caller expectation")
        if claims["version"] < minimum_version:
            errors.append("admission is below the independently accepted version floor")
        if (
            expected_previous_hash is not None
            and claims["previous_admission_hash"] != expected_previous_hash
        ):
            errors.append("admission does not continue the accepted predecessor")
        trust_hash = hash_object({name: claims[name] for name in _ROOT_FIELDS})
        admission_hash = sha256_hex(token.encode("utf-8"))
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return AdmissionVerification(False, None, (f"malformed authority admission: {error}",))
    if errors:
        return AdmissionVerification(False, None, tuple(errors))
    return AdmissionVerification(
        True, AuthorityAdmission(dict(claims), admission_hash, trust_hash, nbf, exp)
    )


class _HashableAdmission:
    """Wraps an admission so an lru_cache key can hash it by admission_hash alone.

    ``AuthorityAdmission.claims`` is a plain mapping and is not itself hashable.
    """

    __slots__ = ("admission",)

    def __init__(self, admission: AuthorityAdmission) -> None:
        self.admission = admission

    def __hash__(self) -> int:
        return hash(self.admission.admission_hash)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, _HashableAdmission)
            and other.admission.admission_hash == self.admission.admission_hash
        )


@lru_cache(maxsize=128)
def _cached_verify_admitted_origin(
    origin_token: str,
    admission_key: _HashableAdmission,
    artifacts_key: frozenset[tuple[str, bytes]],
) -> OriginVerification:
    return _verify_admitted_origin_uncached(
        origin_token, dict(artifacts_key), admission=admission_key.admission
    )


def verify_admitted_origin(
    origin_token: str,
    artifacts: Mapping[str, bytes],
    *,
    admission: AuthorityAdmission,
) -> OriginVerification:
    """Join an exact admitted originating grant to its completed ratification.

    Lineage-shaped hash fields alone are insufficient. A ratification-only
    bundle is insufficient. The exact issued grant must be admitted and must
    be the candidate actually approved by the retained ratifier path. Its
    audience is also bound to the one enforcement point admitted by the
    caller.

    Repeated calls for the same origin token, admission, and artifact bytes
    reuse the cached result instead of re-verifying the ratification bundle.
    """
    try:
        artifacts_key = frozenset(artifacts.items())
    except TypeError:
        return _verify_admitted_origin_uncached(origin_token, artifacts, admission=admission)
    if not isinstance(origin_token, str) or not isinstance(admission, AuthorityAdmission):
        return _verify_admitted_origin_uncached(origin_token, artifacts, admission=admission)
    return _cached_verify_admitted_origin(
        origin_token, _HashableAdmission(admission), artifacts_key
    )


def _verify_admitted_origin_uncached(
    origin_token: str,
    artifacts: Mapping[str, bytes],
    *,
    admission: AuthorityAdmission,
) -> OriginVerification:
    if not isinstance(origin_token, str) or not origin_token:
        return OriginVerification(False, None, ("originating grant is missing",))
    origin_hash = sha256_hex(origin_token.encode("utf-8"))
    if origin_hash not in admission.claims.get("origin_grant_hashes", ()):
        return OriginVerification(
            False, origin_hash, ("originating grant was not independently admitted",)
        )
    try:
        grant_ok, grant = parse_delegation(
            origin_token, trust_roots=admission.claims["credential_trust_roots"]
        )
    except KeyError, TypeError, ValueError, UnicodeError:
        grant_ok, grant = False, None
    if not grant_ok or grant is None:
        return OriginVerification(
            False,
            origin_hash,
            ("originating grant does not verify under admitted credential roots",),
        )
    expected_audience = [admission.claims.get("enforcement_point_id")]
    if grant.aud != expected_audience:
        return OriginVerification(
            False,
            origin_hash,
            ("originating grant audience must equal exactly the admitted enforcement point",),
        )
    if artifacts.get(GRANT_FILE) != origin_token.encode("utf-8"):
        return OriginVerification(
            False, origin_hash, ("completed bundle does not carry the exact originating grant",)
        )
    result = verify_ratification_bundle(
        artifacts,
        trust_roots=admission.claims["credential_trust_roots"],
        revocation_trust_roots=admission.claims["revocation_attestation_public_keys"],
        registration_public_keys=admission.claims["credential_registration_public_keys"],
    )
    return OriginVerification(result.ok, origin_hash, tuple(result.failures))


def admission_configuration_matches(
    admission: AuthorityAdmission,
    configuration: Mapping[str, Any],
) -> bool:
    """Compare complete public verification preimages, not mutable root aliases."""
    try:
        return all(
            canonical_json_bytes(admission.claims[name])
            == canonical_json_bytes(configuration.get(name))
            for name in _ROOT_FIELDS
        )
    except TypeError, ValueError, OverflowError:
        return False


@dataclass(frozen=True, slots=True)
class ExecutionAuthorityVerification:
    """Independent checks for a retained schema-v5 live authority receipt."""

    valid: bool
    checks: Mapping[str, bool]
    errors: tuple[str, ...] = ()
    limits: tuple[str, ...] = (
        "does not execute or re-evaluate policy",
        "does not prove an enforcement-point identifier matched the actual runtime signer",
        (
            "does not establish nonce-history completeness, ledger anchoring, or "
            "hidden-history absence"
        ),
        "does not prove a resource effect or independent operation",
    )


def verify_admitted_path(
    delegation_token: str,
    parent_tokens: Sequence[str],
    origin_artifacts: Mapping[str, bytes],
    *,
    admission: AuthorityAdmission,
    at: datetime,
) -> OriginVerification:
    """Verify the stronger admitted path without changing historical chain rules.

    The shared current chain walk supplies attenuation and time semantics.  This
    admitted profile adds an external origin join, a canonical signing-key
    constraint for every child, and resource-native Git ref scope when applicable.
    Historical replay hashes and rule versions remain untouched.
    """
    if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() is None:
        return OriginVerification(
            False, None, ("admitted path comparison time requires a timezone",)
        )
    if not isinstance(delegation_token, str) or not delegation_token:
        return OriginVerification(False, None, ("delegation token is missing",))
    if not isinstance(parent_tokens, Sequence) or isinstance(parent_tokens, (str, bytes)):
        return OriginVerification(False, None, ("delegation ancestry must be a token sequence",))
    parents = list(parent_tokens)
    if any(not isinstance(token, str) or not token for token in parents):
        return OriginVerification(False, None, ("delegation ancestry contains an invalid token",))
    roots = admission.claims.get("credential_trust_roots")
    if not isinstance(roots, Mapping):
        return OriginVerification(False, None, ("admission carries no credential trust roots",))
    leaf_ok, leaf = parse_delegation(delegation_token, trust_roots=roots)
    if not leaf_ok or leaf is None:
        return OriginVerification(
            False, None, ("delegation token does not verify under admitted roots",)
        )
    if not leaf.nbf <= at <= leaf.exp:
        return OriginVerification(
            False, None, ("delegation token does not cover the comparison time",)
        )
    chain = validate_delegation_chain(leaf, parents, trust_roots=roots, evaluation_time=at)
    if not chain.valid or chain.depth_exceeded:
        reason = chain.reason or "delegation chain exceeds its declared maximum depth"
        return OriginVerification(False, None, (f"admitted delegation path is invalid: {reason}",))
    origin_token = parents[-1] if parents else delegation_token
    origin = verify_admitted_origin(origin_token, origin_artifacts, admission=admission)
    if not origin.valid:
        return origin
    binding = admission.claims.get("resource_binding")
    git_ref = (
        binding.get("git_ref")
        if isinstance(binding, Mapping) and binding.get("outcome_profile") == "git-publication/1"
        else None
    )
    origin_signer = _verified_slip_signer_id(origin_token, roots)
    if origin_signer is None or not origin_signer.startswith("ed25519:"):
        return OriginVerification(
            False,
            origin.origin_grant_hash,
            ("admitted originating grant has no canonical Ed25519 signer",),
        )
    for index, token in enumerate((delegation_token, *parents)):
        if _verified_slip_signer_id(token, roots) != origin_signer:
            return OriginVerification(
                False,
                origin.origin_grant_hash,
                (
                    f"delegation signer at path position {index} differs from "
                    f"admitted origin issuer",
                ),
            )
        if isinstance(git_ref, str):
            path_claim = leaf if index == 0 else parse_delegation(token, trust_roots=roots)[1]
            if path_claim is None or not git_ref_is_covered(git_ref, path_claim.scope_paths):
                return OriginVerification(
                    False,
                    origin.origin_grant_hash,
                    ("signed delegation does not cover the admitted Git ref",),
                )
    return origin


def _receipt_decision(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    decision = receipt.get("decision")
    return decision if isinstance(decision, Mapping) else receipt


def _receipt_moment(receipt: Mapping[str, Any]) -> datetime | None:
    try:
        return _moment(_receipt_decision(receipt).get("evaluated_at"))
    except TypeError, ValueError:
        return None


def _evidence_artifact(block: Mapping[str, Any]) -> str | None:
    evidence = block.get("credential_evidence")
    candidate = evidence if isinstance(evidence, Mapping) else block
    artifact = candidate.get("artifact")
    return artifact if isinstance(artifact, str) and artifact else None


def _artifact_bytes(artifacts: Any) -> dict[str, bytes] | None:
    if not isinstance(artifacts, Mapping) or not artifacts:
        return None
    resolved: dict[str, bytes] = {}
    for name, value in artifacts.items():
        if not isinstance(name, str) or not name:
            return None
        if isinstance(value, str):
            resolved[name] = value.encode("utf-8")
        elif isinstance(value, bytes):
            resolved[name] = value
        else:
            return None
    return resolved


def _same_json(left: Any, right: Any) -> bool:
    try:
        return canonical_json_bytes(left) == canonical_json_bytes(right)
    except TypeError, ValueError, OverflowError:
        return False


def _native_ingress_text(value: Any) -> str | None:
    """Return the HTTP/MCP boundary's required trimmed string value."""
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized if normalized else None


def _native_holder(
    request_envelope: Mapping[str, Any],
) -> tuple[Any, Mapping[str, Any] | None, bool]:
    """Read holder identity/proof from an exact AuthorityEnvelope or ingress preimage."""
    if "actor_id" in request_envelope or "actor_proof" in request_envelope:
        proof = request_envelope.get("actor_proof")
        return (
            request_envelope.get("actor_id"),
            proof if isinstance(proof, Mapping) else None,
            "actor_proof" in request_envelope,
        )
    actor = request_envelope.get("actor")
    if not isinstance(actor, Mapping):
        return None, None, False
    proof = actor.get("proof")
    return (
        _native_ingress_text(actor.get("id")),
        proof if isinstance(proof, Mapping) else None,
        "proof" in actor,
    )


def _native_request_links(
    request_envelope: Mapping[str, Any],
) -> tuple[str | None, list[str], str | None, str | None, Mapping[str, Any]] | None:
    """Read exact credential and call fields without projecting a new envelope."""
    if "authority_envelope_version" in request_envelope:
        delegation = request_envelope.get("delegation")
        approval = request_envelope.get("approval")
        arguments = request_envelope.get("arguments")
        if (
            not isinstance(delegation, Mapping)
            or not isinstance(approval, Mapping)
            or not isinstance(arguments, Mapping)
        ):
            return None
        leaf = delegation.get("raw_token")
        parents = delegation.get("parent_tokens")
        approval_token = approval.get("raw_token")
        tool_name = request_envelope.get("tool_name")
    else:
        leaf = request_envelope.get("delegation_token")
        parents = request_envelope.get("parent_delegation_tokens", [])
        approval_token = request_envelope.get("approval_token")
        call = request_envelope.get("call")
        if not isinstance(call, Mapping):
            return None
        tool_name = _native_ingress_text(call.get("name"))
        if tool_name is None:
            return None
        raw_arguments = call.get("arguments")
        arguments = {} if raw_arguments is None else raw_arguments
    if (
        (leaf is not None and not isinstance(leaf, str))
        or not isinstance(parents, list)
        or any(not isinstance(token, str) for token in parents)
        or (approval_token is not None and not isinstance(approval_token, str))
        or (tool_name is not None and not isinstance(tool_name, str))
        or not isinstance(arguments, Mapping)
    ):
        return None
    return leaf, list(parents), approval_token, tool_name, arguments


def request_binding_matches(
    envelope: Mapping[str, Any],
    *,
    actor_id: str,
    delegation_token: str | None,
    parent_tokens: Sequence[str],
    approval_token: str | None,
    tool_name: str | None,
    arguments: Mapping[str, Any] | None,
    actor_proof: Mapping[str, Any] | None,
) -> bool:
    """Compare an exact native preimage to its retained execution inputs.

    This performs no projection or policy evaluation. It only accepts one of
    the documented AuthorityEnvelope or native HTTP/MCP shapes and compares
    JSON canonically, preserving distinctions such as ``true`` versus ``1``.
    """
    if (
        not isinstance(envelope, Mapping)
        or not isinstance(actor_id, str)
        or not isinstance(parent_tokens, Sequence)
        or isinstance(parent_tokens, (str, bytes))
        or any(not isinstance(token, str) for token in parent_tokens)
        or (delegation_token is not None and not isinstance(delegation_token, str))
        or (approval_token is not None and not isinstance(approval_token, str))
        or (tool_name is not None and not isinstance(tool_name, str))
        or (arguments is not None and not isinstance(arguments, Mapping))
    ):
        return False
    native_actor_id, native_proof, native_carries_proof = _native_holder(envelope)
    links = _native_request_links(envelope)
    if links is None or native_actor_id != actor_id:
        return False
    if native_carries_proof:
        if not isinstance(native_proof, Mapping) or not isinstance(actor_proof, Mapping):
            return False
        retained_proof = {
            name: value for name, value in actor_proof.items() if name != "request_hash"
        }
        if not _same_json(native_proof, retained_proof):
            return False
    leaf, parents, approval, native_tool_name, native_arguments = links
    return (
        leaf == delegation_token
        and parents == list(parent_tokens)
        and approval == approval_token
        and native_tool_name == tool_name
        and _same_json(native_arguments, arguments or {})
    )


def _verify_revocation_status(
    raw: Any,
    *,
    jti: str,
    roots: Mapping[str, Any],
    at: datetime,
    admission_age_limit_ms: int,
    grant_age_limit_ms: int | None,
    epoch_floor: int,
) -> str | None:
    if not isinstance(raw, Mapping):
        return f"required revocation status for {jti} is missing"
    freshness_evaluated_at_raw = raw.get("freshness_evaluated_at")
    status_evidence = {
        name: value for name, value in raw.items() if name != "freshness_evaluated_at"
    }
    try:
        status = _status_from_evidence(status_evidence)
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return f"revocation status for {jti} is malformed: {error}"
    if status_evidence.get("jti") != jti:
        return f"revocation status belongs to {status_evidence.get('jti')!r}, not {jti!r}"
    if status.is_revoked:
        return f"revocation status for {jti} states revoked"
    if status.source.endswith("_unavailable"):
        return f"revocation status for {jti} reports an unavailable source"
    public_key = _status_public_key(roots, status.trust_root_id)
    if public_key is None or not verify_revocation_attestation(status, jti, public_key):
        return f"revocation status attestation for {jti} does not verify"
    if status.freshness_bound_ms is None:
        return f"revocation status for {jti} has no freshness bound"
    bound = min(
        status.freshness_bound_ms,
        admission_age_limit_ms,
        grant_age_limit_ms if grant_age_limit_ms is not None else admission_age_limit_ms,
    )
    bound_delta = timedelta(milliseconds=bound)
    if freshness_evaluated_at_raw is None:
        comparison_time = at
    else:
        try:
            comparison_time = _moment(freshness_evaluated_at_raw)
        except TypeError, ValueError:
            return f"revocation status freshness_evaluated_at for {jti} is invalid"
    if comparison_time < at - bound_delta:
        return f"revocation status for {jti} was evaluated before the sealed decision instant"
    if comparison_time > at + bound_delta:
        return f"revocation status for {jti} does not cover the retained comparison time"
    if not status.checked_at <= comparison_time <= status.checked_at + bound_delta:
        return f"revocation status for {jti} does not cover the retained comparison time"
    if status.revocation_epoch is None or status.revocation_epoch < epoch_floor:
        return f"revocation status for {jti} is below the required epoch floor"
    return None


def _verify_cumulative_rows(
    rows: Any,
    *,
    jti: str,
    roots: Mapping[str, Any],
    at: datetime,
    age_limit_ms: int,
    expected_bounds: Sequence[Mapping[str, Any]],
    authority_entry_hash: str | None,
) -> str | None:
    if not isinstance(rows, list) or len(rows) != len(expected_bounds):
        return "required cumulative status evidence is missing or incomplete"
    unmatched_bounds = list(expected_bounds)
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            return f"cumulative status row {index} is not an object"
        payload = row.get("signed_payload")
        attestation = row.get("attestation")
        if not isinstance(payload, Mapping) or not isinstance(attestation, str):
            return f"cumulative status row {index} lacks its signed payload or attestation"
        signed_jti = payload.get("jti")
        if signed_jti != jti:
            return f"cumulative status row {index} is bound to the wrong delegation"
        matching_bound = next(
            (
                bound
                for bound in unmatched_bounds
                if payload.get("kind") == bound.get("kind")
                and payload.get("unit") == bound.get("unit")
                and payload.get("window_duration_ms") == bound.get("window_duration_ms")
                and (
                    (
                        bound.get("aggregation") is None
                        and "scope" not in payload
                        and "scope_id" not in payload
                    )
                    or (
                        bound.get("aggregation") is not None
                        and payload.get("scope") == bound.get("aggregation")
                        and payload.get("scope_id") == authority_entry_hash
                    )
                )
            ),
            None,
        )
        if matching_bound is None:
            return f"cumulative status row {index} does not link to an admitted bound account"
        unmatched_bounds.remove(matching_bound)
        if any(row.get(name) != value for name, value in payload.items() if name != "jti"):
            return f"cumulative status row {index} differs from its signed payload"
        root_id = payload.get("trust_root_id")
        public_key = _status_public_key(roots, root_id if isinstance(root_id, str) else None)
        if public_key is None or not verify_cumulative_status_payload(
            payload, attestation, public_key=public_key
        ):
            return f"cumulative status row {index} attestation does not verify"
        if payload.get("admissible") is not True:
            return f"cumulative status row {index} is not admissible"
        try:
            checked_at = _moment(payload.get("checked_at"))
            freshness = payload.get("freshness_bound_ms")
        except TypeError, ValueError:
            return f"cumulative status row {index} has an invalid checked_at"
        if not isinstance(freshness, int) or isinstance(freshness, bool) or freshness < 0:
            return f"cumulative status row {index} has no usable freshness bound"
        bound = min(freshness, age_limit_ms)
        bound_delta = timedelta(milliseconds=bound)
        freshness_evaluated_at_raw = row.get("freshness_evaluated_at")
        if freshness_evaluated_at_raw is None:
            comparison_time = at
        else:
            try:
                comparison_time = _moment(freshness_evaluated_at_raw)
            except TypeError, ValueError:
                return f"cumulative status row {index} has an invalid freshness_evaluated_at"
        if comparison_time < at - bound_delta:
            return f"cumulative status row {index} was evaluated before the sealed decision instant"
        if comparison_time > at + bound_delta:
            return f"cumulative status row {index} does not cover the retained comparison time"
        if not checked_at <= comparison_time <= checked_at + bound_delta:
            return f"cumulative status row {index} does not cover the retained comparison time"
    return None


def _retained_request_adapter(
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> str | None:
    """Return the one adapter retained by the authenticated native request."""
    candidates: list[Any] = [receipt.get("adapter_id")]
    envelope = evidence.get("request_envelope")
    if isinstance(envelope, Mapping):
        candidates.append(envelope.get("adapter_id"))
    present = [candidate for candidate in candidates if candidate is not None]
    if not present or any(not isinstance(candidate, str) or not candidate for candidate in present):
        return None
    adapter_id = present[0]
    return adapter_id if all(candidate == adapter_id for candidate in present) else None


def verify_execution_authority(
    receipt: Mapping[str, Any],
    *,
    admission_trust_roots: Mapping[str, Any],
    expected_domain: str,
    expected_ledger_id: str,
    minimum_version: int = 1,
    expected_previous_hash: str | None = None,
    revocation_epoch_floor: int = 0,
    escalation_record: Mapping[str, Any] | None = None,
) -> ExecutionAuthorityVerification:
    """Verify retained v5 live-authority joins, without asserting an effect.

    This is intentionally stronger than :func:`verify_receipt_credentials`.
    It requires live-profile provenance, exact admitted origin/path, retained
    request proof, and signed mutable-status facts.  Historical credential
    verification remains available for its recorded v3/v4 meaning.
    """
    checks = {
        "profile": False,
        "receipt_time": False,
        "admission": False,
        "request_artifact_binding": False,
        "enforcement_point_binding": False,
        "configuration": False,
        "resource_binding": False,
        "retained_credentials": False,
        "delegation_path": False,
        "holder_request": False,
        "revocation_status": False,
        "cumulative_status": False,
    }
    errors: list[str] = []
    if (
        not isinstance(revocation_epoch_floor, int)
        or isinstance(revocation_epoch_floor, bool)
        or revocation_epoch_floor < 0
    ):
        return ExecutionAuthorityVerification(
            False, checks, ("invalid independently accepted revocation epoch floor",)
        )
    if not isinstance(receipt, Mapping):
        return ExecutionAuthorityVerification(False, checks, ("receipt is not an object",))
    evidence = receipt.get("evidence")
    if not isinstance(evidence, Mapping):
        return ExecutionAuthorityVerification(False, checks, ("receipt evidence is not an object",))
    evidence_schema = evidence.get("schema_version")
    if evidence_schema not in {"5", "6"}:
        return ExecutionAuthorityVerification(
            False, checks, ("receipt is not schema-v5 or schema-v6 evidence",)
        )
    if evidence.get("execution_profile") != "live":
        errors.append("receipt is not a retained live execution profile")
    else:
        checks["profile"] = True
    at = _receipt_moment(receipt)
    if at is None:
        errors.append("receipt lacks a timezone-aware decision.evaluated_at")
        return ExecutionAuthorityVerification(False, checks, tuple(errors))
    checks["receipt_time"] = True
    admission_evidence = evidence.get("authority_admission")
    if not isinstance(admission_evidence, Mapping):
        errors.append("required authority admission evidence is missing")
        return ExecutionAuthorityVerification(False, checks, tuple(errors))
    token = admission_evidence.get("artifact")
    if not isinstance(token, str) or not token:
        errors.append("authority admission artifact is missing")
        return ExecutionAuthorityVerification(False, checks, tuple(errors))
    admission_result = verify_authority_admission(
        token,
        admission_trust_roots=admission_trust_roots,
        expected_domain=expected_domain,
        expected_ledger_id=expected_ledger_id,
        at=at,
        minimum_version=minimum_version,
        expected_previous_hash=expected_previous_hash,
    )
    admission = admission_result.admission
    if not admission_result.valid or admission is None:
        errors.extend(admission_result.errors)
        return ExecutionAuthorityVerification(False, checks, tuple(errors))
    if evidence_schema == "6" and admission.claims.get("schema_version") not in {2, 3}:
        errors.append("schema-v6 execution evidence requires admission schema 2 or 3")
    admission_summary_matches = (
        admission_evidence.get("admission_hash") == admission.admission_hash
        and admission_evidence.get("trust_configuration_hash") == admission.trust_configuration_hash
        and admission_evidence.get("domain_id") == expected_domain
        and admission_evidence.get("ledger_id") == expected_ledger_id
        and admission_evidence.get("enforcement_point_id")
        == admission.claims.get("enforcement_point_id")
        and admission_evidence.get("minimum_version") == minimum_version
        and admission_evidence.get("expected_previous_hash") == expected_previous_hash
        and admission_evidence.get("revocation_epoch_floor") == revocation_epoch_floor
    )
    if not admission_summary_matches:
        errors.append(
            "retained authority admission summaries do not match caller or signed admission"
        )
    expected_admission_evidence_fields = {
        "artifact",
        "admission_hash",
        "trust_configuration_hash",
        "domain_id",
        "ledger_id",
        "enforcement_point_id",
        "minimum_version",
        "expected_previous_hash",
        "revocation_epoch_floor",
        "origin_grant_hash",
        "origin_artifacts",
        "verification_configuration",
        "resource_binding",
    }
    if evidence_schema == "6":
        expected_admission_evidence_fields.add("max_actor_proof_age_seconds")
    admission_fields_match = set(admission_evidence) == expected_admission_evidence_fields
    if not admission_fields_match:
        errors.append(f"authority admission evidence fields do not match schema-v{evidence_schema}")
    if evidence_schema == "6" and admission_evidence.get(
        "max_actor_proof_age_seconds"
    ) != admission.claims.get("max_actor_proof_age_seconds"):
        errors.append("retained actor-proof freshness bound differs from signed admission")
    if admission_summary_matches and admission_fields_match:
        checks["admission"] = True
    if admission_evidence.get("enforcement_point_id") == admission.claims.get(
        "enforcement_point_id"
    ):
        checks["enforcement_point_binding"] = True
    else:
        errors.append("retained enforcement point differs from signed admission")
    configuration = admission_evidence.get("verification_configuration")
    if (
        not isinstance(configuration, Mapping)
        or set(configuration) != set(_ROOT_FIELDS)
        or not admission_configuration_matches(admission, configuration)
    ):
        errors.append("retained verification configuration differs from signed admission")
    else:
        checks["configuration"] = True
    retained_adapter = _retained_request_adapter(receipt, evidence)
    if (
        retained_adapter is None
        or not _same_json(
            admission_evidence.get("resource_binding"), admission.claims.get("resource_binding")
        )
        or retained_adapter != admission.claims["resource_binding"].get("adapter_id")
    ):
        errors.append("retained resource binding does not match the authenticated request adapter")
    else:
        checks["resource_binding"] = True
    delegation = receipt.get("delegation")
    if not isinstance(delegation, Mapping):
        errors.append("retained delegation evidence is missing")
        return ExecutionAuthorityVerification(False, checks, tuple(errors))
    leaf_token = _evidence_artifact(delegation)
    parents_raw = delegation.get("credential_chain")
    if not isinstance(parents_raw, list):
        errors.append("retained delegation ancestry is missing")
        return ExecutionAuthorityVerification(False, checks, tuple(errors))
    parents = [
        _evidence_artifact(entry) if isinstance(entry, Mapping) else None for entry in parents_raw
    ]
    artifacts = _artifact_bytes(admission_evidence.get("origin_artifacts"))
    if leaf_token is None or any(token is None for token in parents) or artifacts is None:
        errors.append("retained delegation path or exact origin artifacts are missing")
        return ExecutionAuthorityVerification(False, checks, tuple(errors))
    path = verify_admitted_path(
        leaf_token,
        [token for token in parents if token is not None],
        artifacts,
        admission=admission,
        at=at,
    )
    if not path.valid or path.origin_grant_hash != admission_evidence.get("origin_grant_hash"):
        errors.extend(
            path.errors or ("retained origin grant hash does not match the admitted path",)
        )
        return ExecutionAuthorityVerification(False, checks, tuple(errors))
    checks["delegation_path"] = True
    credentials = verify_receipt_credentials(
        receipt,
        admission.claims["credential_trust_roots"],
        registration_public_keys=admission.claims["credential_registration_public_keys"],
        escalation_record=escalation_record,
        audience=expected_ledger_id,
    )
    if credentials.valid:
        checks["retained_credentials"] = True
    else:
        errors.extend(credentials.errors)
    leaf_ok, leaf = parse_delegation(
        leaf_token, trust_roots=admission.claims["credential_trust_roots"]
    )
    if not leaf_ok or leaf is None:
        errors.append("retained delegation leaf no longer verifies")
        return ExecutionAuthorityVerification(False, checks, tuple(errors))
    request_envelope = evidence.get("request_envelope")
    proof = evidence.get("actor_proof")
    actor_id = _receipt_decision(receipt).get("actor_id")
    native_actor_id, carried_proof, native_carries_proof = (
        _native_holder(request_envelope)
        if isinstance(request_envelope, Mapping)
        else (None, None, False)
    )
    original_proof = (
        {name: value for name, value in proof.items() if name != "request_hash"}
        if isinstance(proof, Mapping)
        else None
    )
    native_call_shape = (
        isinstance(request_envelope, Mapping)
        and isinstance(request_envelope.get("actor"), Mapping)
        and isinstance(request_envelope.get("call"), Mapping)
        and isinstance(request_envelope["call"].get("name"), str)
        and (
            request_envelope["call"].get("arguments") is None
            or isinstance(request_envelope["call"].get("arguments"), Mapping)
        )
    )
    native_shape_valid = isinstance(request_envelope, Mapping) and (
        native_call_shape
        or (
            native_carries_proof
            and isinstance(carried_proof, Mapping)
            and "authority_envelope_version" in request_envelope
        )
    )
    approval = receipt.get("approval")
    retained_approval = _evidence_artifact(approval) if isinstance(approval, Mapping) else None
    retained_arguments = receipt.get("arguments", {})
    links_match = (
        isinstance(request_envelope, Mapping)
        and isinstance(retained_arguments, Mapping)
        and request_binding_matches(
            request_envelope,
            actor_id=actor_id if isinstance(actor_id, str) else "",
            delegation_token=leaf_token,
            parent_tokens=[token for token in parents if token is not None],
            approval_token=retained_approval,
            tool_name=receipt.get("tool_name"),
            arguments=retained_arguments,
            actor_proof=proof if isinstance(proof, Mapping) else None,
        )
    )
    if links_match:
        checks["request_artifact_binding"] = True
    else:
        errors.append(
            "native request credential or call fields differ from retained receipt evidence"
        )
    if (
        not native_shape_valid
        or not isinstance(request_envelope, Mapping)
        or not isinstance(proof, Mapping)
        or actor_id != leaf.sub
        or native_actor_id != actor_id
        or (native_carries_proof and not _same_json(carried_proof, original_proof))
    ):
        errors.append(
            "retained native request preimage, holder proof, or leaf-subject linkage is missing"
        )
    else:
        request_hash = actor_proof_request_hash(request_envelope)
        holder = verify_actor_proof(
            {"actor_id": actor_id, "actor_proof": proof},
            admission.claims["credential_trust_roots"],
            request_hash=request_hash,
            audience=expected_ledger_id,
            now=at,
            freshness_seconds=int(admission.claims["max_actor_proof_age_seconds"]),
            registration_public_keys=admission.claims["credential_registration_public_keys"],
        )
        if proof.get("request_hash") != request_hash or not holder.valid:
            errors.append("retained holder proof does not bind the exact native request preimage")
        else:
            checks["holder_request"] = True
    chain_claims: Sequence[DelegationClaims] = ()
    leaf_status = delegation.get("revocation_status")
    status_error = _verify_revocation_status(
        leaf_status,
        jti=leaf.jti,
        roots=admission.claims["revocation_attestation_public_keys"],
        at=at,
        admission_age_limit_ms=int(admission.claims["max_revocation_age_ms"]),
        grant_age_limit_ms=leaf.max_revocation_age_ms,
        epoch_floor=revocation_epoch_floor,
    )
    if status_error is None:
        chain_claims = validate_delegation_chain(
            leaf,
            [token for token in parents if token is not None],
            trust_roots=admission.claims["credential_trust_roots"],
            evaluation_time=at,
        ).parent_claims
        for parent, parent_claims in zip(parents_raw, chain_claims, strict=True):
            status_error = _verify_revocation_status(
                parent.get("revocation_status") if isinstance(parent, Mapping) else None,
                jti=parent_claims.jti,
                roots=admission.claims["revocation_attestation_public_keys"],
                at=at,
                admission_age_limit_ms=int(admission.claims["max_revocation_age_ms"]),
                grant_age_limit_ms=parent_claims.max_revocation_age_ms,
                epoch_floor=revocation_epoch_floor,
            )
            if status_error is not None:
                break
    if status_error is None:
        status_rows: list[Mapping[str, Any]] = []
        if isinstance(leaf_status, Mapping):
            status_rows.append(leaf_status)
        for parent in parents_raw:
            if not isinstance(parent, Mapping):
                continue
            parent_status = parent.get("revocation_status")
            if isinstance(parent_status, Mapping):
                status_rows.append(parent_status)
        regressed = epoch_regression(status_rows)
        if regressed is not None:
            status_error = f"revocation epoch regressed at {regressed}"
    if status_error is not None:
        errors.append(status_error)
    else:
        checks["revocation_status"] = True
    rows = evidence.get("cumulative_status")
    if evidence_schema == "6":
        action = _receipt_decision(receipt).get("action")
        if not isinstance(action, Mapping):
            errors.append("schema-v6 receipt lacks an action for complete account verification")
        else:
            try:
                expected_accounts = required_account_bounds(
                    [leaf, *chain_claims],
                    action_type=action["type"],
                    action_boundary=action["boundary"],
                )
            except (KeyError, TypeError, ValueError) as error:
                errors.append(f"schema-v6 required account bounds are invalid: {error}")
                expected_accounts = ()
            if not expected_accounts and rows is None:
                checks["cumulative_status"] = True
            elif not isinstance(rows, list):
                errors.append("schema-v6 cumulative status evidence is missing")
            else:
                remaining_rows = list(rows)
                cumulative_error: str | None = None
                for jti in {str(account["jti"]) for account in expected_accounts}:
                    account_group = [
                        account for account in expected_accounts if account["jti"] == jti
                    ]
                    bound_group = [
                        {
                            "kind": account["kind"],
                            "unit": account["unit"],
                            "window_duration_ms": account["window_duration_ms"],
                            "aggregation": account["scope"],
                        }
                        for account in account_group
                    ]
                    group_rows = [
                        row
                        for row in remaining_rows
                        if isinstance(row, Mapping)
                        and isinstance(row.get("signed_payload"), Mapping)
                        and row["signed_payload"].get("jti") == jti
                    ]
                    entry_scope_ids = {
                        account["scope_id"]
                        for account in account_group
                        if account["scope"] == "entry"
                    }
                    if len(entry_scope_ids) > 1:
                        cumulative_error = (
                            f"schema-v6 account owner {jti} has contradictory entry scope ids"
                        )
                        break
                    cumulative_error = _verify_cumulative_rows(
                        group_rows,
                        jti=jti,
                        roots=admission.claims["cumulative_attestation_public_keys"],
                        at=at,
                        age_limit_ms=int(admission.claims["max_cumulative_age_ms"]),
                        expected_bounds=bound_group,
                        authority_entry_hash=next(iter(entry_scope_ids), None),
                    )
                    if cumulative_error is not None:
                        break
                    for row in group_rows:
                        remaining_rows.remove(row)
                if cumulative_error is not None:
                    errors.append(cumulative_error)
                elif remaining_rows:
                    errors.append("schema-v6 cumulative status evidence has unbound account rows")
                else:
                    checks["cumulative_status"] = True
    else:
        expected_cumulative_bounds = [
            bound
            for bound in leaf.bounds
            if bound.get("window_epoch") is not None and bound.get("window_duration_ms") is not None
        ]
        if not expected_cumulative_bounds and rows is None:
            checks["cumulative_status"] = True
        else:
            cumulative_error = _verify_cumulative_rows(
                rows,
                jti=leaf.jti,
                roots=admission.claims["cumulative_attestation_public_keys"],
                at=at,
                age_limit_ms=int(admission.claims["max_cumulative_age_ms"]),
                expected_bounds=expected_cumulative_bounds,
                authority_entry_hash=leaf.authority_entry_hash,
            )
            if cumulative_error is not None:
                errors.append(cumulative_error)
            else:
                checks["cumulative_status"] = True
    return ExecutionAuthorityVerification(
        not errors and all(checks.values()), checks, tuple(errors)
    )
