# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0
# A compiled build must not enforce or coerce annotated argument types.
# cython: annotation_typing=False

"""The standalone ratification-bundle verifier.

Written before the producers in ``ratification.py``, so its requirements decided
what a ratification must retain and bind: a gap shows here as a failing check
rather than as a reviewer's finding.

A stranger holding one bundle directory and the public trust roots checks entry
-> ratification -> grant with this module alone. It reads no issuance ledger, no
revocation store, and no network. Trust roots come from the caller; a bundle may
carry a ``trust_roots.json``, which is compared and reported, never used, so a
bundle re-signed under substituted roots fails.

It lives beside ``ratification.py`` rather than inside it only because the two
together exceed this repository's file-size budget. The boundary that matters is
the one ``test_bundle_verifier_needs_no_ledger`` enforces on both modules.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .attenuation import _holds_right
from .authority_entry import AuthorityEntry, authority_entry_hash, parse_authority_entry
from .claim_shapes import delegation_content_hash
from .credential_registration import credential_registration_error
from .hashing import canonical_iso, canonical_json_bytes, strict_json_loads
from .models import DelegationClaims
from .ratification import (
    RatificationClaims,
    _candidate_claims,
    _verify_ratification_contract,
    build_candidate_core,
    parents_content_hash,
    parse_ratification,
    ratification_hash,
    ratifier_reach_widening_axis,
)
from .revocation_types import verify_revocation_attestation
from .status_evidence import (
    _status_from_evidence,
    epoch_regression,
    status_artefact_hash,
)
from .tokens import MAX_VERIFICATION_CHAIN_DEPTH, validate_delegation_chain
from .tokens_slips import (
    _b64url_decode,
    _canonical_key_identity,
    parse_delegation,
    verified_slip_trust_root_id,
)

# One bundle is one directory. The names are part of the published layout: a
# stranger's verifier finds the parts by name, and the CLI writes them by name.
ENTRY_FILE = "entry.json"
CANDIDATE_FILE = "candidate.json"
RATIFICATION_FILE = "ratification.slip"
RATIFIER_LEAF_FILE = "ratifier-leaf.slip"
RATIFIER_PARENT_PREFIX = "ratifier-parent-"
STATUS_PREFIX = "status-"
GRANT_FILE = "grant.slip"
TRUST_ROOTS_FILE = "trust_roots.json"

BundleSource = Path | Mapping[str, bytes]

_MAX_BUNDLE_FILE_BYTES = 1_048_576
_MAX_JSON_ITEMS = 10_000


def ratifier_parent_file(index: int) -> str:
    """Return the bundle file name for the parent at *index*, nearest first."""
    return f"{RATIFIER_PARENT_PREFIX}{index}.slip"


def status_file(index: int) -> str:
    """Return the bundle file name for the status artefact at *index*."""
    return f"{STATUS_PREFIX}{index}.json"


# --------------------------------------------------------------------------
# The standalone bundle verifier
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BundleCheck:
    """One named check over one part of a bundle."""

    ok: bool
    reason: str = ""


@dataclass(frozen=True, slots=True)
class BundleVerification:
    """Every named check a bundle must pass, and why each one stands or fails."""

    trust_roots: BundleCheck
    ratification: BundleCheck
    ratifier_registration: BundleCheck
    entry: BundleCheck
    candidate: BundleCheck
    ratifier_chain: BundleCheck
    status_evidence: BundleCheck
    grant: BundleCheck

    @property
    def checks(self) -> tuple[tuple[str, BundleCheck], ...]:
        """Return every named check in verification order."""
        return (
            ("trust_roots", self.trust_roots),
            ("ratification", self.ratification),
            ("ratifier_registration", self.ratifier_registration),
            ("entry", self.entry),
            ("candidate", self.candidate),
            ("ratifier_chain", self.ratifier_chain),
            ("status_evidence", self.status_evidence),
            ("grant", self.grant),
        )

    @property
    def ok(self) -> bool:
        """Return whether every named check passed."""
        return all(check.ok for _, check in self.checks)

    @property
    def failures(self) -> list[str]:
        """Return ``name: reason`` for every failed check."""
        return [f"{name}: {check.reason}" for name, check in self.checks if not check.ok]


_NOT_CHECKED = BundleCheck(False, "not checked: an earlier part of the bundle failed")
_CHECK_COUNT = len(fields(BundleVerification))


def _partial_verification(*checks: BundleCheck) -> BundleVerification:
    """Return a verification of *checks* in order, with every later check not reached."""
    return BundleVerification(*checks, *([_NOT_CHECKED] * (_CHECK_COUNT - len(checks))))


def _has_file(bundle_dir: BundleSource, name: str) -> bool:
    return name in bundle_dir if isinstance(bundle_dir, Mapping) else (bundle_dir / name).exists()


def _read_bytes(bundle_dir: BundleSource, name: str) -> bytes:
    """Return one bounded bundle file, rejecting oversized input before parsing."""
    if isinstance(bundle_dir, Mapping):
        if name not in bundle_dir:
            raise FileNotFoundError(name)
        value = bundle_dir[name]
        if not isinstance(value, bytes):
            raise ValueError(f"{name} must contain bytes")
    else:
        with (bundle_dir / name).open("rb") as handle:
            value = handle.read(_MAX_BUNDLE_FILE_BYTES + 1)
    if len(value) > _MAX_BUNDLE_FILE_BYTES:
        raise ValueError(f"{name} exceeds {_MAX_BUNDLE_FILE_BYTES} bytes")
    return value


def _check_json_items(value: Any, remaining: list[int]) -> None:
    remaining[0] -= 1
    if remaining[0] < 0:
        raise ValueError(f"JSON value exceeds {_MAX_JSON_ITEMS} items")
    if isinstance(value, Mapping):
        for key, item in value.items():
            _check_json_items(key, remaining)
            _check_json_items(item, remaining)
    elif isinstance(value, list):
        for item in value:
            _check_json_items(item, remaining)


def _strict_json_bytes(raw: bytes) -> Any:
    value = strict_json_loads(raw.decode("utf-8"))
    _check_json_items(value, [_MAX_JSON_ITEMS])
    return value


def _public_key(trust_roots: Mapping[str, Any], trust_root_id: str | None) -> bytes | None:
    """Return a raw Ed25519 key from either explicit status or credential root shapes."""
    if not trust_root_id:
        return None
    configured = trust_roots.get(trust_root_id)
    if isinstance(configured, Mapping):
        if configured.get("scheme") not in (None, "ed25519"):
            return None
        configured = configured.get("public_key")
    try:
        public_key = bytes.fromhex(configured) if isinstance(configured, str) else configured
    except ValueError:
        return None
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        return None
    return public_key


def _verified_slip_claims(token: str) -> dict[str, Any]:
    """Return the claims of a slip whose signature has already verified.

    The payload bytes are signature-covered at this point, so decoding them is
    reading verified data -- the same rule ``verified_slip_trust_root_id``
    states for the trust root it reads.
    """
    raw = _b64url_decode(token.split(".", 1)[0])
    if len(raw) > _MAX_BUNDLE_FILE_BYTES:
        raise ValueError("slip payload is oversized")
    payload = _strict_json_bytes(raw)
    if not isinstance(payload, dict):
        raise ValueError("slip payload is not an object")
    return payload


def _check_trust_roots(bundle_dir: BundleSource, trust_roots: Mapping[str, Any]) -> BundleCheck:
    """Compare a bundled root list with the supplied one; never adopt it."""
    if not _has_file(bundle_dir, TRUST_ROOTS_FILE):
        return BundleCheck(True, "the bundle carries no trust roots to compare")
    try:
        bundled = _strict_json_bytes(_read_bytes(bundle_dir, TRUST_ROOTS_FILE))
    except (OSError, ValueError) as error:
        return BundleCheck(False, f"bundled trust roots are unreadable: {error}")
    try:
        roots_match = canonical_json_bytes(bundled) == canonical_json_bytes(dict(trust_roots))
    except (TypeError, ValueError, OverflowError) as error:
        return BundleCheck(False, f"supplied trust roots are not canonical JSON: {error}")
    if not roots_match:
        return BundleCheck(False, "bundled trust roots differ from the roots the caller supplied")
    return BundleCheck(True, "bundled trust roots match the roots the caller supplied")


def _check_ratification(
    bundle_dir: BundleSource, trust_roots: Mapping[str, Any]
) -> tuple[BundleCheck, RatificationClaims | None]:
    """Verify the ratification slip and its bound signing root."""
    try:
        token = _read_bytes(bundle_dir, RATIFICATION_FILE).decode("utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as error:
        return BundleCheck(False, f"ratification slip unreadable: {error}"), None
    ok, claims = parse_ratification(token, trust_roots=trust_roots)
    if not ok or claims is None:
        return (
            BundleCheck(False, "ratification slip does not verify under the supplied roots"),
            None,
        )
    return BundleCheck(True, "ratification slip verified"), claims


def _check_ratifier_registration(
    claims: RatificationClaims,
    trust_roots: Mapping[str, Any],
    registration_public_keys: Mapping[str, str] | None,
) -> BundleCheck:
    """Require an enrolled credential behind a P-256 ratification signature."""
    error = credential_registration_error(
        trust_roots,
        claims.ratifier_trust_root_id,
        registration_public_keys=registration_public_keys,
        evaluation_time=claims.ratified_at,
    )
    if error is not None:
        return BundleCheck(False, error)
    root = trust_roots.get(claims.ratifier_trust_root_id)
    if not isinstance(root, Mapping) or root.get("scheme") != "p256":
        return BundleCheck(True, "the ratifier root is not a P-256 credential")
    return BundleCheck(True, "the ratifier credential registration verified")


def _check_entry(
    bundle_dir: BundleSource, claims: RatificationClaims
) -> tuple[BundleCheck, AuthorityEntry | None]:
    """Parse the entry and bind it to the hash the ratification signed."""
    try:
        mapping = _strict_json_bytes(_read_bytes(bundle_dir, ENTRY_FILE))
    except (OSError, ValueError) as error:
        return BundleCheck(False, f"entry unreadable: {error}"), None
    try:
        entry = parse_authority_entry(mapping)
    except (TypeError, ValueError) as error:
        return BundleCheck(False, f"entry refused: {error}"), None
    if authority_entry_hash(entry) != claims.authority_entry_hash:
        return BundleCheck(False, "entry hash differs from the ratified entry hash"), None
    if entry.entry_id != claims.entry_id or entry.revision != claims.revision:
        return (
            BundleCheck(False, "entry identifier or revision differs from the ratification"),
            None,
        )
    if entry.issuer_trust_root_id != claims.issuer_trust_root_id:
        return BundleCheck(False, "entry names an issuer the ratification did not bind"), None
    if canonical_iso(entry.effective_at) != canonical_iso(claims.effective_at):
        return BundleCheck(False, "entry effective_at differs from the ratification"), None
    return BundleCheck(True, "entry matches the hash the ratification signed"), entry


def _check_candidate(
    bundle_dir: BundleSource, entry: AuthorityEntry, claims: RatificationClaims
) -> tuple[BundleCheck, bytes | None, DelegationClaims | None]:
    """Rebuild the candidate from the entry and require byte equality."""
    try:
        raw = _read_bytes(bundle_dir, CANDIDATE_FILE)
    except (OSError, ValueError) as error:
        return BundleCheck(False, f"candidate unreadable: {error}"), None, None
    try:
        core, core_bytes, core_hash = build_candidate_core(entry, attempt=claims.attempt)
        candidate = _candidate_claims(core)
    except (KeyError, TypeError, ValueError) as error:
        return BundleCheck(False, f"candidate cannot be rebuilt: {error}"), None, None
    if raw != core_bytes:
        return (
            BundleCheck(False, "candidate bytes differ from the rebuild from entry and attempt"),
            None,
            None,
        )
    if core_hash != claims.candidate_core_hash:
        return BundleCheck(False, "candidate hash differs from the ratified hash"), None, None
    passed = BundleCheck(True, "candidate rebuilds byte for byte from the entry")
    return passed, core_bytes, candidate


def _check_ratifier_chain(
    bundle_dir: BundleSource,
    claims: RatificationClaims,
    candidate: DelegationClaims,
    trust_roots: Mapping[str, Any],
) -> tuple[BundleCheck, list[DelegationClaims] | None]:
    """Re-verify the ratifier's own grant, its ancestry, and its reach.

    The signed chain depth is also bounded by the verifier resource profile
    before any retained parent artefacts are acquired.
    """
    try:
        leaf_token = _read_bytes(bundle_dir, RATIFIER_LEAF_FILE).decode("utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as error:
        return BundleCheck(False, f"ratifier grant unreadable: {error}"), None
    leaf_ok, leaf = parse_delegation(leaf_token, trust_roots=trust_roots)
    if not leaf_ok or leaf is None:
        return BundleCheck(False, "ratifier grant does not verify under the supplied roots"), None
    if leaf.chain_depth > MAX_VERIFICATION_CHAIN_DEPTH:
        return (
            BundleCheck(
                False,
                f"ratifier chain exceeds verifier resource limit {MAX_VERIFICATION_CHAIN_DEPTH}",
            ),
            None,
        )
    try:
        _verify_ratification_contract(claims, candidate, leaf)
    except ValueError as error:
        return BundleCheck(False, str(error)), None
    parent_tokens: list[str] = []
    for index in range(leaf.chain_depth):
        try:
            parent_tokens.append(_read_bytes(bundle_dir, ratifier_parent_file(index)).decode())
        except (OSError, UnicodeDecodeError, ValueError) as error:
            return BundleCheck(False, f"ratifier parent {index} unreadable: {error}"), None
    chain = validate_delegation_chain(
        leaf, parent_tokens, trust_roots=trust_roots, evaluation_time=claims.ratified_at
    )
    if not chain.valid:
        return BundleCheck(False, f"ratifier chain invalid: {chain.reason}"), None
    if chain.depth_exceeded:
        return BundleCheck(False, "ratifier chain exceeds its own max_depth"), None
    if leaf.jti != claims.ratifier_jti or leaf.sub != claims.ratifier_sub:
        return BundleCheck(False, "ratifier grant is not the one the ratification names"), None
    if leaf.sub != claims.ratifier_trust_root_id:
        return BundleCheck(False, "the ratification key is not the grant's subject"), None
    if delegation_content_hash(leaf) != claims.ratifier_leaf_content_hash:
        return BundleCheck(False, "ratifier grant content differs from the bound hash"), None
    if parents_content_hash(chain.parent_claims) != claims.ratifier_parents_content_hash:
        return BundleCheck(False, "ratifier ancestry content differs from the bound hash"), None
    if not _holds_right(leaf, "delegate", claims.ratified_at):
        return BundleCheck(False, "ratifier grant lacks delegate"), None
    axis = ratifier_reach_widening_axis(candidate, leaf, rule_version=claims.rule_version)
    if axis is not None:
        return BundleCheck(False, f"candidate widens the ratifier grant on {axis}"), None
    if candidate.sub == leaf.sub:
        return BundleCheck(False, "the ratifier is the candidate's subject"), None
    issuer_key_identity = _canonical_key_identity(trust_roots, claims.issuer_trust_root_id)
    ratifier_key_identity = _canonical_key_identity(trust_roots, claims.ratifier_trust_root_id)
    if (
        issuer_key_identity is None
        or ratifier_key_identity is None
        or issuer_key_identity == ratifier_key_identity
    ):
        return BundleCheck(False, "the approved issuer key is the ratifier key"), None
    return (
        BundleCheck(True, "ratifier chain, reach, and key binding re-verified"),
        [leaf, *chain.parent_claims],
    )


def _check_one_status(
    bundle_dir: BundleSource,
    index: Any,
    jti: Any,
    bound: Mapping[str, Any],
    trust_roots: Mapping[str, Any],
    ratified_at: datetime,
) -> BundleCheck | Mapping[str, Any]:
    """Re-verify the status artefact at *index* for *jti*: return its failed check or the artefact.

    *bound* is the ``{"jti", "hash"}`` entry the ratification binds at *index*.
    """
    try:
        artefact = _strict_json_bytes(_read_bytes(bundle_dir, status_file(index)))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        return BundleCheck(False, f"status artefact {index} unreadable: {error}")
    if not isinstance(artefact, dict) or artefact.get("jti") != jti:
        return BundleCheck(False, f"status artefact {index} does not name {jti}")
    if bound["jti"] != jti:
        return BundleCheck(False, f"the ratification binds no status for {jti}")
    try:
        status = _status_from_evidence(artefact)
        actual_hash = status_artefact_hash(artefact)
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return BundleCheck(False, f"status artefact for {jti} is malformed: {error}")
    if actual_hash != bound["hash"]:
        return BundleCheck(False, f"status artefact for {jti} differs from the bound hash")
    if status.is_revoked:
        return BundleCheck(False, f"{jti} was revoked at the ratification time")
    if not status.verifiable or status.attestation is None:
        return BundleCheck(False, f"status for {jti} is not verifiable")
    if status.freshness_bound_ms is None:
        return BundleCheck(False, f"status for {jti} carries no freshness bound")
    public_key = _public_key(trust_roots, status.trust_root_id)
    if public_key is None:
        return BundleCheck(False, f"no supplied root resolves the status for {jti}")
    if not verify_revocation_attestation(status, jti, public_key):
        return BundleCheck(False, f"status attestation for {jti} does not verify")
    horizon = status.checked_at + timedelta(milliseconds=status.freshness_bound_ms)
    if not status.checked_at <= ratified_at <= horizon:
        return BundleCheck(False, f"status for {jti} does not cover the ratification time")
    return artefact


def _check_status_evidence(
    bundle_dir: BundleSource,
    claims: RatificationClaims,
    ratifier_claims: Sequence[DelegationClaims],
    trust_roots: Mapping[str, Any],
) -> BundleCheck:
    """Re-verify one signed status per ratifier identifier, at the ratification time."""
    identifiers = [entry.jti for entry in ratifier_claims]
    bound = claims.status_evidence_hashes
    artefacts: list[Mapping[str, Any]] = []
    if len(bound) != len(identifiers):
        return BundleCheck(
            False,
            f"the ratification binds {len(bound)} status artefacts for "
            f"{len(identifiers)} identifiers",
        )
    for index, jti in enumerate(identifiers):
        checked = _check_one_status(
            bundle_dir, index, jti, bound[index], trust_roots, claims.ratified_at
        )
        if isinstance(checked, BundleCheck):
            return checked
        artefacts.append(checked)
    # The same rule ``ratify`` applies before it binds this evidence. A
    # ratification signed before the rule existed can carry a regressed set, and
    # its bound hashes make that set self-consistent, so the hash check above
    # cannot see it. This check can.
    regressed = epoch_regression(artefacts)
    if regressed is not None:
        return BundleCheck(
            False,
            f"revocation_epoch_regressed: the status for {regressed} states an "
            "epoch below one already pinned",
        )
    return BundleCheck(True, "every ratifier identifier carries signed status at that moment")


def _check_grant(
    bundle_dir: BundleSource,
    claims: RatificationClaims,
    core_bytes: bytes,
    trust_roots: Mapping[str, Any],
) -> BundleCheck:
    """Verify the issued grant is the ratified candidate plus one provenance field."""
    if not _has_file(bundle_dir, GRANT_FILE):
        return BundleCheck(True, "no grant present: this is a ratification bundle")
    try:
        token = _read_bytes(bundle_dir, GRANT_FILE).decode("utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as error:
        return BundleCheck(False, f"grant unreadable: {error}")
    ok, grant = parse_delegation(token, trust_roots=trust_roots)
    if not ok or grant is None:
        return BundleCheck(False, "grant does not verify under the supplied roots")
    signing_root = verified_slip_trust_root_id(token)
    if signing_root != claims.issuer_trust_root_id:
        return BundleCheck(
            False,
            f"grant signing root '{signing_root}' is not the approved issuer "
            f"'{claims.issuer_trust_root_id}'",
        )
    if grant.authority_entry_hash != claims.authority_entry_hash:
        return BundleCheck(False, "grant carries another entry hash")
    if grant.ratification_hash != ratification_hash(claims):
        return BundleCheck(False, "grant carries another ratification hash")
    try:
        signed = _verified_slip_claims(token)
        stripped = {
            key: value
            for key, value in signed.items()
            if key not in {"ratification_hash", "trust_root_id"}
        }
        exact_candidate = canonical_json_bytes(stripped) == core_bytes
    except TypeError, ValueError, OverflowError:
        return BundleCheck(False, "grant claims are outside the canonical JSON domain")
    if not exact_candidate:
        return BundleCheck(False, "grant carries claims beyond the ratified candidate")
    return BundleCheck(True, "grant is the ratified candidate plus its provenance")


def verify_ratification_bundle(
    bundle_dir: BundleSource,
    *,
    trust_roots: Mapping[str, Any],
    revocation_trust_roots: Mapping[str, Any],
    registration_public_keys: Mapping[str, str] | None = None,
) -> BundleVerification:
    """Verify one ratification or completed issuance bundle against supplied roots.

    *trust_roots* verifies credential slips. *revocation_trust_roots* is the
    independent namespace for retained status attestations. A
    ``trust_roots.json`` inside the bundle is compared and reported, never used.

    *registration_public_keys* is the organisational enrolment root map. A
    P-256 ratifier root must carry a registration that verifies under it; an
    Ed25519 ratifier root needs neither, and the check reports that it does not
    apply.

    Reads nothing but the bundle directory: no issuance ledger, no revocation
    store, no network. Every failure is a named check with its reason; the
    function does not raise.
    """
    credential_keys = {
        key
        for root_id in trust_roots
        if (key := _public_key(trust_roots, str(root_id))) is not None
    }
    revocation_keys = {
        key
        for root_id in revocation_trust_roots
        if (key := _public_key(revocation_trust_roots, str(root_id))) is not None
    }
    roots_are_independent = not bool(credential_keys & revocation_keys)
    trust_roots_check = _check_trust_roots(bundle_dir, trust_roots)
    ratification_check, claims = _check_ratification(bundle_dir, trust_roots)
    if claims is None:
        return _partial_verification(trust_roots_check, ratification_check)
    registration_check = _check_ratifier_registration(claims, trust_roots, registration_public_keys)
    entry_check, entry = _check_entry(bundle_dir, claims)
    if entry is None:
        return _partial_verification(
            trust_roots_check, ratification_check, registration_check, entry_check
        )
    candidate_check, core_bytes, candidate = _check_candidate(bundle_dir, entry, claims)
    if core_bytes is None or candidate is None:
        return _partial_verification(
            trust_roots_check, ratification_check, registration_check, entry_check, candidate_check
        )
    chain_check, ratifier_claims = _check_ratifier_chain(bundle_dir, claims, candidate, trust_roots)
    if ratifier_claims is None:
        return _partial_verification(
            trust_roots_check,
            ratification_check,
            registration_check,
            entry_check,
            candidate_check,
            chain_check,
        )
    status_check = (
        _check_status_evidence(bundle_dir, claims, ratifier_claims, revocation_trust_roots)
        if roots_are_independent
        else BundleCheck(False, "credential and revocation trust roots overlap")
    )
    return BundleVerification(
        trust_roots_check,
        ratification_check,
        registration_check,
        entry_check,
        candidate_check,
        chain_check,
        status_check,
        _check_grant(bundle_dir, claims, core_bytes, trust_roots),
    )


__all__ = [
    "CANDIDATE_FILE",
    "ENTRY_FILE",
    "GRANT_FILE",
    "RATIFICATION_FILE",
    "RATIFIER_LEAF_FILE",
    "RATIFIER_PARENT_PREFIX",
    "STATUS_PREFIX",
    "TRUST_ROOTS_FILE",
    "BundleCheck",
    "BundleVerification",
    "ratifier_parent_file",
    "status_file",
    "verify_ratification_bundle",
]
