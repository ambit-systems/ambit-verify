# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Standalone verification of retained Ambit authority and ledger evidence.

Checks admitted origins, credential paths and historical evidence using
caller-supplied public trust. Ledger hash, head, witness and checkpoint checks
remain separate from credential or admission checks. No result by itself
proves hidden-history absence or a resource effect. Nothing here issues
credentials, executes policy, writes ledgers or signs evidence.

Three parties appear in the checks:

- The writer appends records and attests the ledger head with its key. In an
  Ambit deployment this is the Authority plane.
- The witness records, in a ledger of its own, the heads it saw and attests
  that ledger with a second key. In an Ambit deployment this is the
  Observatory plane.
- The holder keeps a checkpoint (one head, the writer's attestation, the
  witness record) countersigned with a third key that neither of the other
  parties holds.

The Ed25519 verifiers hold public keys only. ``HmacHeadVerifier`` holds the
shared secret a reference deployment attests with; that secret can also sign,
so a pass under it proves nothing against the writer.
"""

from __future__ import annotations

from .admission import (
    AdmissionVerification,
    AuthorityAdmission,
    ExecutionAuthorityVerification,
    OriginVerification,
    request_binding_matches,
    verify_admitted_origin,
    verify_admitted_path,
    verify_authority_admission,
    verify_execution_authority,
)
from .consumption import (
    CONSUMPTION_PROFILE,
    bound_applies,
    required_account_bounds,
    validate_consumption_record,
)
from .credential_evidence import ReceiptCredentialVerification, verify_receipt_credentials
from .execution_evidence import ExecutionBundleVerification, verify_execution_bundle
from .hashing import canonical_json_bytes, hash_object
from .head_attestation import (
    CheckpointVerifier,
    HeadAttestation,
    HeadVerifier,
    HmacHeadVerifier,
    attestation_block,
    attestation_payload,
    checkpoint_payload,
)
from .head_attestation_ed25519 import Ed25519CountersignVerifier, Ed25519HeadVerifier
from .models import ApprovalClaims, Capability, DelegationClaims
from .ratification import RATIFICATION_RULE_VERSION, ratifier_reach_widening_axis
from .ratification_bundle import BundleCheck, BundleVerification, verify_ratification_bundle
from .receipt_links import (
    ReceiptConsequence,
    ReceiptLinkIssue,
    ReceiptLinkReport,
    ReceiptRefusal,
    verify_receipt_links,
    verify_receipt_records,
)
from .resource_protocol import (
    GIT_PUBLICATION_PROFILE,
    RESOURCE_PROFILE,
    dispatch_message,
    outcome_message,
    payload_bytes,
    reconciliation_message,
    resource_binding_hash,
    verify_dispatch,
    verify_reconciliation,
    verify_resource_outcome,
)
from .status_evidence import CUMULATIVE_STATUS_CONTEXT, verify_cumulative_status_payload
from .tokens import (
    MAX_VERIFICATION_CHAIN_DEPTH,
    ChainReplayResult,
    ChainValidationResult,
    replay_delegation_chain,
    validate_delegation_chain,
)
from .verify import (
    GENESIS_HASH,
    LedgerReadError,
    ledger_files,
    read_attestation,
    read_attestation_file,
    read_head,
    read_verified_records,
    verify_chain,
    verify_checkpoint,
    verify_witnessed_head,
)

__version__ = "0.1.0"

__all__ = [
    "CONSUMPTION_PROFILE",
    "CUMULATIVE_STATUS_CONTEXT",
    "GENESIS_HASH",
    "GIT_PUBLICATION_PROFILE",
    "MAX_VERIFICATION_CHAIN_DEPTH",
    "RATIFICATION_RULE_VERSION",
    "RESOURCE_PROFILE",
    "AdmissionVerification",
    "ApprovalClaims",
    "AuthorityAdmission",
    "BundleCheck",
    "BundleVerification",
    "Capability",
    "ChainReplayResult",
    "ChainValidationResult",
    "CheckpointVerifier",
    "DelegationClaims",
    "Ed25519CountersignVerifier",
    "Ed25519HeadVerifier",
    "ExecutionAuthorityVerification",
    "ExecutionBundleVerification",
    "HeadAttestation",
    "HeadVerifier",
    "HmacHeadVerifier",
    "LedgerReadError",
    "OriginVerification",
    "ReceiptConsequence",
    "ReceiptCredentialVerification",
    "ReceiptLinkIssue",
    "ReceiptLinkReport",
    "ReceiptRefusal",
    "__version__",
    "attestation_block",
    "attestation_payload",
    "bound_applies",
    "canonical_json_bytes",
    "checkpoint_payload",
    "dispatch_message",
    "hash_object",
    "ledger_files",
    "outcome_message",
    "payload_bytes",
    "ratifier_reach_widening_axis",
    "read_attestation",
    "read_attestation_file",
    "read_head",
    "read_verified_records",
    "reconciliation_message",
    "replay_delegation_chain",
    "request_binding_matches",
    "required_account_bounds",
    "resource_binding_hash",
    "validate_consumption_record",
    "validate_delegation_chain",
    "verify_admitted_origin",
    "verify_admitted_path",
    "verify_authority_admission",
    "verify_chain",
    "verify_checkpoint",
    "verify_cumulative_status_payload",
    "verify_dispatch",
    "verify_execution_authority",
    "verify_execution_bundle",
    "verify_ratification_bundle",
    "verify_receipt_credentials",
    "verify_receipt_links",
    "verify_receipt_records",
    "verify_reconciliation",
    "verify_resource_outcome",
    "verify_witnessed_head",
]
