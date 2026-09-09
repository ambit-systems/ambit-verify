# Changelog

All notable changes to `ambit-verify` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Authenticate bounded behavioural snapshots against explicit observer/source
  keys, actor/domain/audience, model configuration and evaluation time. Retained
  source verification checks the full chain against its signed head; it does
  not prove the numerical model or confer action authority.

### Security

- Retain the parsed record that passed the source hash check. A later mutation
  of the caller's source object cannot substitute another actor's observation.

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
