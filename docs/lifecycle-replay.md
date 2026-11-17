# Canonical lifecycle replay

`canonical-lifecycle/1` verifies a complete local canonical prefix. The historical terminal-bundle API keeps its original contract. No historical record is converted to the new evidence format.

`verify_execution_prefix` checks a caller-pinned head, its signature, and the registered enforcement point. It then calls `replay_execution_prefix`. The latter is a pure semantic function. Its caller must authenticate the complete snapshot before use. The recovery worker also checks an independently retained continuity anchor.

The result separates these properties:

- `valid`: all checks that ran accepted their inputs.
- `coverage_complete`: every supplied record has a supported semantic check.
- `record_coverage`: one result per supplied record, including unsupported records.
- `operations`: exact operation identities, original actor, evidence links, and terminal or unresolved state.
- `accounts`: pending, committed, released, and charged capacity by account and period.
- `consumed_identifiers`: retained nonce and entitlement consumption.
- `issuances`: verified child allocations and pending, committed, or released state.
- `external_history_completeness`: always `not_established`.

An unresolved operation can have valid and complete prefix coverage. This does not establish progress. Unknown execution remains charged. A pre-dispatch release needs the recorded no-dispatch basis. A fenced release needs an independently signed `not_executed` outcome. A current Git commitment also needs the exact native Start record and its accepted time.

An unsigned generic fence can establish only the existing unresolved transport state. It must retain the exact operation, request and payload hashes. It cannot establish native Start, settlement or release. A transport reply does not resolve its external result.

Generic numeric obligations require `generic_quantity_policy` from independent installed configuration. This policy has the same `enabled`, `records_field_by_action`, and `argument_quantity_by_action` fields as Authority's magnitude resolver. Replay derives payload bytes from the exact canonical arguments. It counts records in the configured list field. It scales a configured non-negative integer argument by the configured decimal scale. Replay checks each debit against every applicable signed bound, cohort and period. Missing policy, missing derivations, changed quantities and changed accounts fail. The policy must use the installed ontology's unit scale. These quantities measure forwarded arguments, not external effects. A generic operation can release before dispatch under the existing no-dispatch contract; after an unsigned fence its numeric obligations stay charged.

Each intent, transport observation, dispatch, native Start, and terminal must join its exact earlier operation. Transport success is an observation, not executor confirmation. Independent executor evidence establishes the retained terminal claim. The verifier checks every operation in the prefix, including earlier operations and cross-party clearance. It does not check only a selected terminal.

Live child issuance uses `admitted-child-issuance/1`. A reservation retains the exact child claims, prior holder-authentication hash, admitted origin artefacts, and signed parent status evidence. Commitment retains the exact signed child token. Replay checks authority, narrowing, permanent identity pins, and aggregate sibling allocation. Legacy issuance records retain their original meaning and remain unsupported for complete authority verification. Offline activation and legacy allocation migration records also remain unsupported.

Live revocation intents retain `revocation-authority/1` status evidence for the revoker and all parents. Replay checks the signed request, target, holder, ancestry, delegated reach, status signatures, freshness, and order. A missing outcome remains explicit uncertainty. Refusal records establish a refused signed request; they do not prove that the discarded request was invalid. Ordinary rejection records establish no authority transition.

Supply `revocation_policy` from independent installed configuration when the prefix contains revocation records. It contains `credential_trust_roots`, `revoker_trust_roots`, `revocation_attestation_public_keys`, and `credential_registration_public_keys`. Cross-party fences also require `revocation_fence_doors`, keyed by resource-binding hash. A retained public key is not an independent trust root.

The Authority live emitter inventory includes decisions, intents, dispatch and consumption events, native Start, transport outcomes, rejection, child issuance, revocation intent/outcome/refusal, and cross-party revocation fences. Other Core append APIs also accept witness, score, invalidation, policy-attestation, and administration records. These do not acquire lifecycle coverage because their chain hashes verify. An unknown or unsupported record blocks complete qualification.

This verifier does not rerun the policy evaluator. Observatory's lifecycle profile also reruns every decision and compares the full ordered rule trace. The verifier does not prove that an executor reported physical effects truthfully, that a producer recorded every effect, or that a newer remote head does not exist. Key custody, independent head retention, exclusive writers, service scheduling, and external resource behavior remain operating obligations.

An authenticated genesis prefix is healthy for recovery discovery and returns no work. A qualification workload must be nonempty. No finite test result is a universal proof.

A foreign request can produce `DENY` or `ESCALATE` before it reserves authority. Foreign identity verification accepts an absent consumption block only for these two decisions. It still verifies the signed dispatch, exact actor and action, B's signed context, admitted point map, and fresh statuses. `ALLOW` requires the operation and its actor-key fingerprint. A malformed consumption block is not equivalent to an absent block.
