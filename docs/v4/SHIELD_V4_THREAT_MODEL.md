# Shield v4 PQC Threat Model

Author attribution: DarekDGB

## Status

This document locks the threat model for the implemented Shield v4 PQC
contract surface.

Baseline tag: `ecosystem-pre-v4-audit-lock`

Shield v4 remains controlled pre-release work. Cryptographic evidence does not
grant execution authority.

## Security Goal

Shield v4 must make Shield decision evidence cryptographically verifiable without creating signing, broadcasting, consensus, custody, wallet, AI, or upstream execution authority.

AdamantineOS remains the final execution boundary.

## Protected Assets

Shield v4 protects:

- component verdict integrity
- Orchestrator receipt integrity
- context-hash binding
- request binding
- freshness / anti-replay binding
- reason ID integrity
- evidence-family integrity
- final Shield aggregation evidence
- key-role separation
- trust-registry validity
- downgrade resistance
- auditability of verification results

Shield v4 does not protect by taking custody of:

- wallet private keys
- wallet seeds
- recovery phrases
- transaction-signing keys
- DigiByte consensus rules

## Trust Boundaries

### Shield Components

Shield components produce signed decision evidence only.

A component signature proves that a component role produced a verdict for a specific request, context, policy, freshness window, and payload hash.

A component signature does not prove final wallet authority.

### Shield Orchestrator

The Orchestrator verifies signed component verdicts, aggregates them, and produces a signed Shield receipt.

The Orchestrator receipt is the only Shield artifact AdamantineOS may consume.

### AdamantineOS

AdamantineOS verifies the Shield receipt and remains the final execution boundary.

No Shield v4 field may override AdamantineOS final policy.

### Wallet / External Integrator

The wallet must not treat Shield v4 artifacts as final authority.

The wallet should display or act on AdamantineOS final outcome only unless a future external verification contract is explicitly implemented and tested.

### AI Gateway / AI Output

AI output is untrusted evidence only.

AI may not approve, override, downgrade, sign, broadcast, or create missing cryptographic evidence.

## Adversary Model

Assume an attacker may attempt to:

- modify component verdicts after signing
- modify Orchestrator receipts after signing
- replay old valid receipts
- submit stale receipts
- change `context_hash` or `request_id`
- splice a valid signature from another receipt
- use a valid component signature as an Orchestrator signature
- use a valid Orchestrator signature as a component signature
- use the wrong key for a role
- use a revoked or expired key
- roll back the trust registry
- weaken the signature policy
- strip ML-DSA and present only classical signatures
- present FN-DSA evidence as if it satisfies ML-DSA
- flip an FN-DSA `standard_profile` after signing
- reinterpret a draft Falcon-1024 profile as another Falcon/FN-DSA profile
- reorder required signatures or place optional FN-DSA before a required path
- duplicate algorithm entries in a signature bundle
- include unknown algorithms
- trigger canonicalization ambiguity
- exploit Unicode or numeric serialization differences
- inject authority through metadata
- submit raw component outputs directly to AdamantineOS
- downgrade v4-required mode to v3-allowed mode
- flood verification with malformed PQC payloads
- make the wallet treat unverified Shield output as verified

## Out-of-Scope Attacks

Shield v4 does not claim to solve:

- compromise of a user's wallet private key outside Shield
- compromise of DigiByte consensus
- compromise of production signing key custody outside the trust-registry model
- attacks caused by a wallet ignoring AdamantineOS final outcome
- malicious changes merged into repository code without review, tests, or signed release process

These remain separate security domains.

## Threats and Required Controls

### Transaction Authority Confusion

Threat: an integrator or attacker treats a Shield signature as transaction-signing authority.

Controls:

- Shield v4 never signs transaction bytes.
- Shield v4 never broadcasts.
- Shield v4 never holds wallet private keys.
- AdamantineOS remains final boundary.
- Docs and tests must reject authority-injection fields.

### Canonicalization Divergence

Threat: two verifiers compute different signed bytes for the same semantic payload.

Controls:

- `shield-v4-canon.v1` canonicalization profile.
- frozen field sets.
- no floats, NaN, Infinity, or ambiguous numeric encodings in signed fields.
- Unicode NFC normalization.
- canonical set/list handling.
- frozen Known-Answer Test vectors.

### Cross-Domain Signature Replay

Threat: a valid component signature is replayed as an Orchestrator signature, or the reverse.

Controls:

- domain tag is part of signed bytes.
- component verdict tag differs from Orchestrator receipt tag.
- verifier checks role, schema, key, policy, and domain tag together.

### Replay and Staleness

Threat: an old valid receipt is reused.

Controls:

- signed `request_id`.
- signed `freshness_nonce`.
- signed `not_before` and `not_after`.
- verifier-side duplicate tracking inside freshness window.
- stale, future, duplicated, or out-of-window receipts fail closed.

### Key-Role Confusion

Threat: a key authorized for one component signs for another role.

Controls:

- key registry binds `role`, `key_id`, `key_version`, and `algorithm`.
- component roles are distinct from Orchestrator role.
- Q-ID identity keys must not be reused as Shield decision keys.
- wrong-role signatures fail closed.

### Key Revocation and Registry Rollback

Threat: an old registry re-activates a revoked key.

Controls:

- registry is versioned.
- key status is checked.
- revoked keys fail closed.
- lower registry versions cannot re-activate a key that a verifier has already seen revoked.
- verifier-required trust state is authoritative.

### Signature Policy Downgrade

Threat: an attacker strips required signatures or presents a weaker policy.

Controls:

- verifier-required policy is authoritative.
- embedded `signature_policy` is signed evidence only.
- required classical and ML-DSA paths must both verify for `policy.v1`.
- FN-DSA evidence is optional and cannot override required-path failure.

### Signature Bundle Reordering and Splicing

Threat: valid signatures are reordered, or signatures from different receipts
are mixed into one bundle, to create a different accepted representation.

Controls:

- every signature signs the same domain-separated `signed_payload_hash`.
- canonical order is derived from the active policy's `allowed_algorithms`.
- `policy.v1` requires `classical-ed25519`, then `ml-dsa`, with optional
  `fn-dsa` last.
- builders emit canonical order; verifiers reject reordered arrays before
  per-signature key selection, role/status/window checks, or cryptographic
  verification.
- duplicate algorithms fail closed.
- unknown algorithms fail closed.
- key id, key version, algorithm, role, policy, profile, and payload hash are checked together.

### FN-DSA Profile Confusion

Threat: a valid `fn-dsa` signature is re-labelled from its authenticated draft
Falcon-1024 profile to another draft or future final profile.

Controls:

- every signature entry carries `standard_profile`.
- the real-signature input signs `standard_profile`, not just the payload hash.
- V4.8H allow-lists `fips206-draft-falcon1024-v1` for `fn-dsa`.
- unsupported profiles fail closed.
- profile changes after signing fail closed.
- FN-DSA remains optional evidence and cannot rescue classical or ML-DSA failure.

### Metadata Authority Injection

Threat: metadata fields claim approval, signing permission, broadcast permission, bypass authority, or trusted status.

Controls:

- metadata is evidence only.
- forbidden authority keys fail closed.
- nested metadata is recursively checked.
- AdamantineOS ignores upstream final authority claims.

### v4-to-v3 Downgrade

Threat: untrusted input flips v4-required mode to v3-allowed mode.

Controls:

- mode governance belongs to AdamantineOS / trusted verifier configuration.
- upstream mode fields are evidence only.
- v3 receipts are rejected when v4 is required.
- rollback is fail-closed unless future versioned governance explicitly permits it.

### Verification DoS

Threat: attackers use oversized or cyclic JSON graphs, canonicalization escape
expansion, signature multiplication, registry growth, hostile container
subclasses, oversized encoded material, or malformed late bundles to trigger
unbounded validation or PQC work.

Controls:

- accept only a bounded acyclic graph of exact built-in JSON types;
- count depth, nodes, every scalar, and every object key before copying an
  over-budget graph;
- enforce separate text, encoded-field, canonical-bundle, canonical-receipt,
  signed-integer, bundle, signature, registry, total-callback, and PQC-callback
  ceilings;
- prepare all six bundles and resolve every key role, status, and time window
  before signed-payload canonicalization, hashing, or backend work;
- reject noncanonical or duplicate signature entries before backend work;
- run complete global classical, ML-DSA, and optional FN-DSA waves under a
  shared counter that increments immediately before each actual callback;
- reuse cached verifier results so existing validators cannot duplicate crypto;
- record a cheap failure as one failed preflight event with zero backend calls;
- gate release evidence with the pinned benchmark in
  `SHIELD_V4_PERFORMANCE_DOS_ENVELOPE_V1.md` and the separate real-OQS proof.

Residual risk: hosted-runner CPU performance and native crypto-provider latency
remain platform-controlled. The structural p95 gate excludes crypto latency;
the hard callback ceilings bound amplification, and the two-node OQS workflow
proves the live ML-DSA and Falcon-1024 paths without skips.

### Real Backend Proof Over-Claim

Threat: deterministic fake-backend CI is described as proof that live liboqs ML-DSA has run.

Controls:

- default CI is described as interface-contract and fail-closed proof only;
- live liboqs ML-DSA proof is an optional gated job using `SHIELD_V4_REAL_OQS=1`;
- the gated job must use a JUnit not-skipped guard so import-skipped OQS tests cannot read as a pass;
- release-grade real-backend proof remains part of the V4.10 proof pack before public release claims.

## Negative Tests Required Before v4 Lock

Minimum negative tests:

- missing component signature -> DENY
- missing Orchestrator signature -> DENY
- wrong component key id -> DENY
- wrong Orchestrator key id -> DENY
- unknown algorithm -> DENY
- unsupported algorithm -> DENY
- signature algorithm downgrade -> DENY
- reversed required signature order -> DENY
- FN-DSA before or between required signatures -> DENY
- v3 receipt submitted where v4 is required -> DENY
- signed payload changed after signing -> DENY
- receipt hash changed after signing -> DENY
- context hash changed after signing -> DENY
- request id changed after signing -> DENY
- reason id changed after signing -> DENY
- metadata authority injection -> DENY
- forged `handoff_allowed` -> DENY
- replay / stale receipt -> DENY
- malformed base64 or signature encoding -> DENY
- empty signature bundle -> DENY
- duplicate component verdict with valid-looking signatures -> DENY
- valid component signatures but missing required component -> DENY
- valid component signature from wrong component role -> DENY
- FN-DSA valid but ML-DSA invalid -> DENY
- FN-DSA unsupported `standard_profile` -> DENY
- FN-DSA `standard_profile` changed after signing -> DENY
- classical valid but ML-DSA invalid -> DENY
- ML-DSA valid but classical invalid -> DENY
- domain tag mismatch -> DENY
- trust-registry rollback -> DENY
- key revoked at verification time -> DENY
- receipt produced outside key validity window -> DENY

## Threat Model Summary

The main Shield v4 risk is not adding cryptography.

The main risk is accidentally creating signed authority where only signed evidence should exist.

Shield v4 must prove decision evidence and still fail closed.

AdamantineOS remains the final boundary.

## V4.8H-E live-Falcon and profile-summary threats

V4.8H-E adds the optional live Falcon-1024 backend path for FN-DSA draft-profile evidence and closes profile-summary drift as an explicit integration threat.

The Orchestrator must deny:

- FN-DSA signed with a profile other than `fips206-draft-falcon1024-v1`;
- component summaries that list `fn-dsa` without the matching FN-DSA profile;
- summaries that claim a profile not independently verified from the component bundle;
- live backend disabled-mechanism or native liboqs exceptions;
- any attempt to treat Falcon/FN-DSA as required ML-DSA, final FIPS 206 proof, transaction-signing authority, broadcast authority, or DigiByte consensus authority.
