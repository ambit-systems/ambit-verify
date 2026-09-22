# Changelog

All notable changes to `ambit-verify` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Dispatch claims in every resource profile may carry the revocation identity
  the decision stood on: `delegation_jtis` (the validated delegation jti chain,
  nearest grant first) and `revocation_epoch` (the store's epoch at ALLOW).
  The pair is present together or absent together, so retained dispatches
  signed before it existed still verify. `dispatch_revocation_identity` reads
  the pair for a resource door that re-checks revocation at commit time.
- The `customer-delete/1` resource profile accepts a `not_executed` outcome
  with `before_state` and `after_state` both `unknown` and reason
  `delegation_revoked`. The door records this outcome when its commit-time
  revocation check finds the authorising delegation revoked and refuses to
  commit.
- The `git-publication/1` terminal outcome grammar accepts an optional
  `reason` field, allowed only on `not_executed`: one of `delegation_revoked`,
  `static_obligation_failed`, `compare_and_swap_mismatch`,
  `plan_hash_mismatch`, or `dispatch_expired`. The door writes
  `delegation_revoked` when its commit-time revocation gate refuses.
- Dispatch claims may also carry `max_revocation_age_ms`, a copy of the leaf
  grant's own bound on revocation-answer age. It travels only alongside the
  `delegation_jtis`/`revocation_epoch` pair, never alone, and `verify_dispatch`
  refuses a malformed value. `dispatch_max_revocation_age_ms` reads it for a
  resource door that applies the stricter of the principal's bound and its own
  freshness bound.
- A regression test proves `verify_admitted_path` refuses an otherwise-valid
  two-hop admitted path whose child delegation is signed under a different
  credential root than the admitted origin grant.

### Changed

- `verify_receipt_credentials` returns `origin_admission` (`not_established`, `valid` or `failed`) and accepts `admission_trust_roots`; a `valid` chain result does not establish origin unless `origin_admission` is `valid`.
- Cache admitted-origin verification per origin token, admission hash and artifact bytes, so repeated live checks of one origin do not re-verify its ratification bundle.
- Require Python 3.14.

- Add complete canonical-operation bundle verification with caller-pinned head,
  enforcement-point registration keys, and per-adapter admission-root maps.
  The bundle API refuses unknown adapters and never flattens adapter-specific
  outside trust. Per-receipt admission verification continues to use one
  selected admission-root map.

- Expose caller-pinned canonical-operation verification through
  `ambit-verify execution`; independent admission roots, registration roots,
  and head are required inputs and the JSON report preserves per-check
  `valid`/`failed`/`not_established` states.

- Treat a signed `not_executed` terminal outcome as authenticated release
  evidence rather than an effect claim. Bundle `valid` is reserved for complete
  committed-effect evidence; unresolved operations and signed releases retain
  their successful applicable checks without being relabelled as effects.

- Document `customer-delete/1` as a signed, canonical customer effect: exact
  HTTP dispatch selection, durable terminal-token retries, the committed and
  no-change field sets, caller-pinned bundle verification, and the
  `before_hash` privacy/custody limits. Keep `record-egress/1` separate.

### Fixed

- Verify generic, zero-obligation prefix operations without interpreting them
  as customer-deletion dispatches. Generic quantitative accounting remains
  unestablished rather than being silently accepted.

- Verify Git-publication execution evidence against the exact admitted remote,
  agent ref, non-forced old..new plan, native `git_push` quantity, and matching
  signed outcome. Approval evidence now binds the retained escalation and its
  canonical request fingerprint before a complete effect can verify.

### Added

- Expose `validate_authority_admission_claims` for signature-independent schema
  and validity-interval validation. It returns UTC `(nbf, exp)` values and is
  shared with the private admission producer; signature, caller-time, domain,
  ledger, and rollback checks remain in `verify_authority_admission`.
- Authenticate bounded behavioural snapshots against explicit observer/source
  keys, actor/domain/audience, model configuration and evaluation time. Retained
  source verification checks the full chain against its signed head; it does
  not prove the numerical model or confer action authority.

### Security

- Retain the parsed record that passed the source hash check. A later mutation
  of the caller's source object cannot substitute another actor's observation.

- Reject noncanonical, duplicate-key, malformed, and over-deep signed slip
  payloads; require independently countersigned, P-256 workload enrolment for
  every retained actor proof.

- Reject duplicate-key, non-finite, unpaired-surrogate, overflowing, over-deep,
  oversized, and over-count JSON evidence through terminal-safe controlled failures.
- Discover suffixless and suffixed ASCII-numbered rotation segments, bound
  descriptor-relative streaming enumeration of every directory entry, and
  reject lexical active-file or directory symlinks without reopening checked
  ledger descriptors.
- Bind witness selection to its authenticated ledger snapshot, reject
  equal-sequence witness equivocation, and require every checkpoint authority,
  witness-attestation, and witness-record ledger identity to be present and
  equal.
- Validate causal receipt ordering, concrete actor/adapter identities, signed
  digests, and explicit typed enforcement state; derive decision-mode
  delegation blocks from the complete typed reasons and reject consequences
  claimed by any dry-run decision.
- Replace unauthenticated `genuine` refusal claims with explicitly structural
  `blocked` observations and `blocked_refusal_count`.
- Snapshot immutable checkpoint mappings and tuples into a bounded strict-JSON
  domain, failing closed on unsupported, cyclic, or over-deep values.
- Declare the POSIX descriptor-admission platform requirement and smoke-test
  supported Linux and macOS runners.
- Pin CI and release workflow actions to reviewed commit SHAs, install one
  exact checksum-verified uv artifact, and build with the lock-pinned backend
  in a non-isolated environment.

## [0.1.0] - 2026-09-02

### Added

- `verify_chain`: record-hash and chain verification across rotated segments,
  with optional head-attestation verification.
- `verify_witnessed_head`: check against the head an independent witness
  ledger recorded.
- `ledger_files`: the files that make up one ledger, in chain order.
- A file that is not UTF-8 fails as `<file>: file is not UTF-8`; it never
  raises.
- `verify_checkpoint`: check against a holder-retained, countersigned
  checkpoint.
- `read_head`, `read_attestation`, and `read_attestation_file`.
- `LedgerReadError`, raised by `read_head` for an empty or invalid ledger.
- `Ed25519HeadVerifier` and `Ed25519CountersignVerifier` (public-key side
  only), `HmacHeadVerifier` (shared-secret side), and the `HeadVerifier` and
  `CheckpointVerifier` protocols.
- `HeadAttestation`, `attestation_payload`, `attestation_block`,
  `checkpoint_payload`, and `GENESIS_HASH`.
- Canonical JSON and SHA-256 helpers: `canonical_json_bytes`, `hash_object`.
- `__version__`.
- `ambit-verify` command with exit codes 0 (pass), 1 (fail), 2 (usage or I/O).

### Notes

- The verification logic is the one the Ambit authority core engine runs; the
  engine now depends on this package. No signer ships here.
