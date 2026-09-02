# Changelog

All notable changes to `ambit-verify` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/).

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
