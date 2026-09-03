# ambit-verify

Standalone verifier for Ambit evidence ledgers.

`ambit-verify` reads a hash-chained JSONL ledger and checks it without the
engine that wrote it. It depends on the Python standard library and
`cryptography` only. It writes nothing and ships no signer: the Ed25519
verifiers hold public keys only.

## What the command verifies

| Check | Input | What a pass proves |
| --- | --- | --- |
| Record hashes | the ledger | Every record hashes to its own `record_hash`. No field of any record changed after it was written. |
| Chain | the ledger | Every `prev_hash` equals the previous `record_hash`, `seq` runs 1, 2, 3, ... with no gap, and the first record links to the genesis hash. No record was removed from the middle or reordered. Rotated segments (`ledger.<seq>.jsonl`) are verified in order before the active file. |
| Head attestation | `--public-key`, optional `--attestation` | An Ed25519 signature by the named key covers the head (`max_seq`, `head_record_hash`), the ledger is exactly at that head, and the record at that `seq` hashes to the attested value. No record was appended, removed, or replaced after the attestation. |
| Witness | `--witness`, `--witnessed-ledger-id`, `--witness-public-key` | The witness ledger verifies under the witness key, it carries a valid `head_witness` record for the named ledger, and the ledger is exactly at the highest witnessed head. A rollback below an independently witnessed head fails, even when the ledger's own attestation was rolled back with it. |
| Checkpoint | `--checkpoint`, `--witness-public-key`, `--countersign-public-key`, optional `--witness-trust-root-id`, optional `--public-key` | The checkpoint names one head, its witness record hashes and verifies, its countersignature verifies under the holder's key, and the ledger still carries the checkpointed record at the checkpointed `seq`. Appends after the checkpoint pass. Truncation below it and rollback at it fail. With `--public-key`, the writer's attestation inside the checkpoint is also signature-checked, and the head-attestation check above runs as well. |

## What a pass does not prove

- That any record is true. A ledger records what a writer wrote. The verifier proves the bytes are unchanged; it does not judge their content.
- That the ledger is complete, unless a head check runs. Without `--public-key`, `--witness`, or `--checkpoint`, a ledger with its tail removed still passes. Bare-chain verification pins only the genesis.
- Anything about the key. The verifier trusts the public key you pass. Obtain it from the party that signs, over a channel you trust.
- That the signer was honest at signing time. A head attestation proves the key holder saw this head. It does not prove the key holder is independent of the writer. Use a witness or a checkpoint for that.

## Verify receipt links

The package also exposes a semantic verifier for code that needs to check
decision → consequence-intent → outcome relationships:

```python
from ambit_verify import verify_receipt_links

report = verify_receipt_links("ledger.jsonl")
print(report.is_valid, report.genuine_refusal_count)
```

It verifies the hash chain first. It then checks that non-dry-run ALLOW
decisions have one intent and outcome, linked records agree on the actor,
adapter, fingerprint, and verdict, and blocked decisions have no downstream
consequence records.

The `ambit-cli` package exposes this API as `ambit receipts verify`,
`ambit receipts consequences`, and `ambit receipts refusals`. The standalone
`ambit-verify` command remains the smaller chain, head, witness, and checkpoint
verifier described below.

## Install

```
pip install ambit-verify
```

Python 3.12 or later.

## Try it on the shipped sample

`samples/five-receipts/` holds a ledger the Ambit Authority engine wrote during a retained run: nine records (five decisions, two consequence intents and two outcomes), the head attestation and the attesting public key. The actions in it are synthetic; the records and signatures are real engine output.

```
$ ambit-verify samples/five-receipts/evidence.jsonl \
    --public-key "$(cat samples/five-receipts/evidence.jsonl.attest-public-key)"
PASS count=9
```

Change one byte in `evidence.jsonl` and run it again: the line number and `record_hash mismatch` name the record you touched. Delete the last line and run without `--public-key`: the bare chain still passes, because a chain check pins only the genesis; add `--public-key` back and the head attestation fails, because the attested `max_seq` is 9.

## Usage

```
ambit-verify LEDGER
  [--attestation PATH] [--public-key HEX] [--trust-root-id ID]
  [--witness PATH --witnessed-ledger-id ID --witness-public-key HEX [--witness-trust-root-id ID]]
  [--checkpoint PATH --witness-public-key HEX --countersign-public-key HEX [--witness-trust-root-id ID]]
```

Verify the chain:

```
$ ambit-verify ledger.jsonl
PASS count=7
```

Verify the chain and the head attestation. Without `--attestation`, the
verifier reads the `.attest` sidecar beside the ledger:

```
$ ambit-verify ledger.jsonl --public-key 3f1c...e9a0
PASS count=7
```

Verify against a retained attestation file and a witness ledger:

```
$ ambit-verify ledger.jsonl \
    --attestation ledger-2026-06-15.attest --public-key 3f1c...e9a0 \
    --witness witness.jsonl --witnessed-ledger-id authority-prod \
    --witness-public-key 8b02...c417
PASS count=7
```

Verify against a countersigned checkpoint:

```
$ ambit-verify ledger.jsonl \
    --checkpoint checkpoint.json \
    --witness-public-key 8b02...c417 \
    --countersign-public-key d4e5...0b6f
PASS count=7
```

A failure names the first check that failed and stops:

```
$ ambit-verify ledger.jsonl
FAIL: ledger.jsonl:2: record_hash mismatch
```

Keys are raw 32-byte Ed25519 public keys in hex. The trust root id defaults
to the id the attestation names; `--trust-root-id` and
`--witness-trust-root-id` pin it. The checkpoint countersignature binds to
the key, so no id is asked for it. `--public-key` turns on the head-attestation
check in every mode, so a checkpoint run with `--public-key` also needs the
`.attest` sidecar or `--attestation`.

### Output and exit codes

Stdout carries exactly one line.

| Exit | Stdout | Meaning |
| --- | --- | --- |
| 0 | `PASS count=N` | Every requested check passed. `N` is the number of records in the chain. |
| 1 | `FAIL: <reason>` | A check failed. Witness and checkpoint reasons are prefixed `witness:` and `checkpoint:`. |
| 2 | nothing (message on stderr) | Usage error (bad flag combination, a key that is not 32 hex bytes, an empty id), a named file does not exist, or an I/O error. Usage errors are reported before any check runs. |

Order of checks: chain, head attestation, witness, checkpoint. The first
failure is reported.

## Library

```python
from ambit_verify import (
    Ed25519HeadVerifier,
    read_attestation_file,
    verify_chain,
    verify_receipt_links,
)

ok, count, error = verify_chain("ledger.jsonl")

verifier = Ed25519HeadVerifier(public_key=bytes.fromhex(hex_key), trust_root_id="customer-1")
ok, count, error = verify_chain("ledger.jsonl", verifier=verifier)

retained = read_attestation_file("ledger-2026-06-15.attest")
ok, count, error = verify_chain("ledger.jsonl", verifier=verifier, attestation=retained)

links = verify_receipt_links("ledger.jsonl")
```

`verify_witnessed_head` and `verify_checkpoint` take the same verifier
objects; `Ed25519CountersignVerifier(public_key=...)` verifies the checkpoint
countersignature. Any object with a `verify_head(attestation) -> bool` method
is a head verifier; `HmacHeadVerifier` is included for reference deployments
that attest with a shared secret. A pass under it proves only that a holder of
the secret attested the head.

## File formats

**Ledger**: one JSON object per line. Each record carries `seq` (integer,
1-based), `prev_hash` (64 hex characters; `0` x 64 for `seq` 1) and
`record_hash` (SHA-256 of the canonical JSON of every other key: keys sorted,
no whitespace, ASCII-escaped). Other keys are the writer's contract; the
verifier does not read them; `verify_receipt_links` reads the decision and consequence fields after the chain passes.

**Attestation** (`.attest` sidecar or a retained copy): a JSON object with
`max_seq`, `head_record_hash`, `recorded_at`, `trust_root_id`, `signature`
and optional `ledger_id`. Ed25519 signatures are `ed25519:<base64>`; HMAC
signatures are `hmac-sha256:<hex>`.

**Checkpoint**: a JSON object with exactly `seq`, `record_hash`,
`attestation`, `witness_record` and `countersignature`.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
