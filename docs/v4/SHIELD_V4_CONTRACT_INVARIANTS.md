# Shield v4 PQC Contract Invariants

Author attribution: DarekDGB

## Status

This document locks the implemented Shield v4 PQC contract invariants.

Baseline tag: `ecosystem-pre-v4-audit-lock`

Shield v4 remains controlled pre-release work. Cryptographic evidence does not
grant execution authority.

## Single Source of Truth Rule

For Shield v4, tests and contract documents define truth.

If implementation code conflicts with these invariants, the implementation is wrong.

If an implementation cannot satisfy an invariant, the build must stop and the
contract must be reviewed before the affected signing or verification change
is accepted.

## V4-INV-001 — Evidence Only

Shield v4 produces cryptographically verifiable decision evidence only.

It must not sign transactions, broadcast transactions, hold transaction keys, alter DigiByte consensus, or grant final execution authority.

## V4-INV-002 — AdamantineOS Final Boundary

AdamantineOS remains the final execution boundary.

No Shield component, Orchestrator receipt, wallet field, AI output, metadata field, or signature policy may override AdamantineOS final policy.

## V4-INV-003 — Parallel v4 Surface

Shield v4 must be built as a parallel v4 contract surface.

Existing v3 schemas remain intact:

- `shield.verdict.v1`
- `shield.receipt.v1`

Shield v4 schemas are:

- `shield.verdict.v2`
- `shield.receipt.v2`
- `shield.signature_bundle.v1`
- `shield.key_registry.v1`

A v3 receipt submitted where v4 is required must fail closed.

## V4-INV-004 — Canonicalization Profile

The Shield v4 canonicalization profile is `shield-v4-canon.v1`.

Signed payload canonicalization must use:

- UTF-8 encoding only
- Unicode NFC normalization before serialization
- JSON object keys sorted lexicographically by Unicode code point
- compact JSON separators with no insignificant whitespace
- deterministic escaping only
- `allow_nan=false` behavior
- no floats in signed fields
- no NaN or Infinity values
- integers encoded as exact JSON integers only
- no leading zero numeric encodings outside the value `0`
- no plus signs in numeric encodings
- absent optional fields omitted from signed payloads
- `null` rejected for signed fields unless a future schema explicitly permits it
- arrays ordered only by schema-defined rules
- set-valued fields serialized as sorted unique lists
- duplicate keys rejected before canonicalization
- `signature_bundle` excluded from the payload it signs
- `signed_payload_hash` excluded from the payload it signs

Field sets must be schema-defined and versioned. Unrecognized signed fields fail closed.

Known-Answer Test vectors must freeze canonical bytes before v4 is called locked.

## V4-INV-005 — Deterministic Field Ordering Rules

Component verdict ordering inside an Orchestrator receipt must be canonical and schema-defined.

Required component order for v4 receipt construction:

1. `adn`
2. `dqsn`
3. `guardian_wallet`
4. `qwg`
5. `sentinel_ai`

Evidence families are set-valued and must be serialized as sorted unique lists.

Reason IDs are policy-ordered tuples. Caller-provided reason ID order is not authoritative.

Duplicate component verdicts, duplicate evidence families, or duplicate signature entries fail closed.

## V4-INV-006 — Domain Separation

Component verdict signatures and Orchestrator receipt signatures must use different signed domains.

Component verdict domain tag:

```text
DGB-SHIELD-V4-COMPONENT-VERDICT:shield.verdict.v2:policy.v1
```

Orchestrator receipt domain tag:

```text
DGB-SHIELD-V4-ORCH-RECEIPT:shield.receipt.v2:policy.v1
```

The domain tag is part of the signed bytes.

A signature valid under one domain must fail under every other domain.

## V4-INV-007 — Signed Payload Hash

Every signature in a v4 signature bundle must verify against the same domain-separated `signed_payload_hash`.

The `signed_payload_hash` must be computed from:

1. domain tag
2. canonical signed payload bytes

The signature fields themselves are never part of the payload being signed.

## V4-INV-008 — Signed Freshness

Every signed component verdict and signed Orchestrator receipt must include signed freshness fields:

- `request_id`
- `freshness_nonce`
- `not_before`
- `not_after`

The verifier must reject:

- missing freshness fields
- unsigned freshness fields
- stale receipts
- future receipts
- duplicate `request_id` / `freshness_nonce` pairs inside the freshness window
- changed freshness fields after signing

Freshness rejection is DENY, not warn.

## V4-INV-009 — Key Roles

Shield v4 key roles are separate from Q-ID identity keys.

Required Shield v4 roles:

- `shield_component_adn`
- `shield_component_dqsn`
- `shield_component_guardian_wallet`
- `shield_component_qwg`
- `shield_component_sentinel_ai`
- `shield_orchestrator`

Q-ID keys prove identity / authentication.

Shield keys prove decision evidence.

Orchestrator keys prove final Shield aggregation evidence.

A key authorized for one role must fail closed when used for another role.

## V4-INV-010 — Key Lifecycle

Every signature entry must carry:

- `algorithm`
- `standard_profile`
- `key_id`
- `key_version`

Every key registry entry must carry:

- `role`
- `key_id`
- `key_version`
- `algorithm`
- `not_before`
- `not_after`
- `status`

Valid statuses:

- `active`
- `revoked`

A key must be active and inside its validity window at verification time.

The signed artifact must also have been produced inside the key validity window.

Revoked keys fail closed.

Expired keys fail closed.

Unknown keys fail closed.

Trust-registry rollback that re-activates a revoked key fails closed.

## V4-INV-011 — Versioned Signature Policy

The first Shield v4 signature policy is `policy.v1`.

`policy.v1` requires:

- an approved classical signature path
- an approved ML-DSA signature path

`policy.v1` may include FN-DSA as supplemental evidence.

ML-DSA means ML-DSA, formerly CRYSTALS-Dilithium.

FN-DSA means FN-DSA, based on Falcon.

FN-DSA must never satisfy or override a missing or failed ML-DSA requirement.

For V4.8H, the only supported FN-DSA profile is
`fips206-draft-falcon1024-v1` (Falcon-1024). The profile is part of the
per-signature signed message. Unsupported profiles or profile changes after
signing fail closed.

The embedded `signature_policy` must be covered by the signature.

The verifier-required policy is authoritative. If the embedded policy is weaker than the verifier-required policy, verification fails closed.

## V4-INV-012 — Signature Bundle Binding

A v4 signature bundle must not be malleable.

Rules:

- all required signatures sign the same `signed_payload_hash`
- all required signatures are evaluated
- no first-valid-wins behavior
- signature order is derived from the active signature policy's
  `allowed_algorithms`; no separate order source is authoritative
- `policy.v1` uses exactly `classical-ed25519`, `ml-dsa`, then optional
  `fn-dsa`; omitting `fn-dsa` does not change the required order
- builders emit the canonical policy order without mutating caller input
- verifiers reject any reordered signature array before per-signature key
  selection, role/status/window checks, or cryptographic verification
- duplicate algorithm entries fail closed
- duplicate key entries fail closed
- unknown algorithms fail closed
- unsupported algorithms fail closed
- wrong role fails closed
- wrong key id fails closed
- wrong key version fails closed
- wrong policy fails closed
- wrong or unsupported `standard_profile` fails closed
- cross-receipt signature splicing fails closed

## V4-INV-013 — Algorithm Naming Accuracy

ML-DSA and FN-DSA are separate algorithms.

ML-DSA was formerly CRYSTALS-Dilithium.

FN-DSA is based on Falcon.

Documentation, tests, fixtures, and code must not describe FN-DSA / Falcon as ML-DSA.

If legacy identifiers are supported for compatibility, their mapping must be explicit, tested, and fail closed on ambiguity.

## V4-INV-014 — Metadata Is Never Authority

Metadata is evidence only.

Metadata must not grant:

- approval
- final authority
- signing permission
- broadcast permission
- bypass permission
- trusted status
- execution permission

Forbidden authority keys must be rejected recursively, including inside nested metadata objects.

## V4-INV-015 — AdamantineOS Handoff Discipline

AdamantineOS may consume only the Shield Orchestrator receipt.

AdamantineOS must not consume raw component verdicts directly.

`handoff_allowed` is evidence only. It is not final approval.

A forged, unsigned, or tampered `handoff_allowed` field fails closed.

## V4-INV-016 — External / Wallet Verifier Boundary

The wallet is not the initial Shield v4 cryptographic verification boundary.

The wallet must not treat unverified Shield receipts as verified.

The wallet must not gain execution authority from Shield receipts.

A future external verifier must use a frozen external verification contract and frozen Known-Answer Test vectors before integration.

## V4-INV-017 — Known-Answer Test Vectors

Before v4 is called locked, the repository must contain frozen test-only vectors covering:

- input payload
- canonical bytes
- domain tag
- signed payload hash
- key id
- key version
- algorithm
- signature bundle
- expected verifier result

Vectors must be deterministic and shared across Orchestrator, AdamantineOS, Shield component repositories, and any future external verifier.

Test keys must be marked TEST-ONLY and must never be production keys.

## V4-INV-018 — Verification Work Order

The release-facing audited verifier must reject cheap failures before signed
payload canonicalization, hashing, or cryptographic callbacks.

Across all five component bundles and the one receipt bundle, the required
relative order is:

1. bounded exact-JSON graph snapshot and scalar accounting;
2. exact schema types, field sets, bundle counts, entry shapes, and text limits;
3. contract, schema, policy, canonical algorithm order, role, profile,
   freshness, registry floor, key identity, key status, key window, and artifact
   window checks for all six bundles;
4. canonical signature-bundle and receipt byte limits;
5. independent receipt and component signed-hash construction and comparison;
6. global classical callback wave for all six artifacts;
7. global ML-DSA callback wave for all six artifacts;
8. optional global FN-DSA callback wave;
9. cached envelope validation and final handoff / AdamantineOS policy evaluation.

Any pre-crypto failure produces one failed preflight audit event and zero
backend callbacks. Existing validators must consume cached callback results and
must not repeat backend work.

## V4-INV-019 — Dual-Stack Governance

`v4-required` mode must be verifier-controlled.

Untrusted upstream input must not be able to downgrade from `v4-required` to `v3-allowed`.

Rollback must fail closed unless a future explicit, versioned, tested governance contract allows it.

## V4-INV-020 — Verification Observability

Release integrations requiring durable evidence must use the audited v4
verification boundary defined by `SHIELD_V4_VERIFICATION_AUDIT_V1.md`.

The audit contract is an exact tagged union. It uses domain-separated hashes
of request and key identifiers, immutable canonical record bytes, an atomic
append-only batch, and an exact durable acknowledgement. Successful evidence
must not leave the boundary before the durable acknowledgement passes.

Receipt-controlled verification failures must be recorded without weakening
fail-closed behavior. Audit sink failure is
`ShieldV4AuditSinkError("V4_AUDIT_SINK_FAILURE")` and must withhold any result.

Raw identifiers, secrets, keys, signatures, payloads, metadata, nonces,
exception text, unnecessary personal data, and authority fields are forbidden.
Audit evidence never grants signing, approval, broadcast, or execution
authority. Mutable replay consumption remains at the AdamantineOS execution
boundary.

## V4-INV-021 — Performance / DoS Envelope

The release-facing audited verifier implements the normative envelope in
`SHIELD_V4_PERFORMANCE_DOS_ENVELOPE_V1.md`.

The frozen ceilings are 131072 canonical receipt bytes, 131072 cumulative
UTF-8 scalar and object-key bytes, 8192 UTF-8 bytes per string or encoded field,
32768 canonical bytes per signature bundle, depth 16, 4096 nodes, signed 64-bit
integers, exactly five component bundles and one receipt bundle, two or three
unique canonical signatures per bundle, 18 total backend attempts, 12 combined
ML-DSA/FN-DSA attempts, and 64 loaded trusted-registry entries.

Input that exceeds a size or count envelope fails as `V4_CONTRACT_INVALID`
before cryptographic verification.

## V4-INV-022 — Negative-First Lock

No v4 release is locked until negative tests prove fail-closed behavior for:

- missing signatures
- wrong keys
- wrong roles
- unknown algorithms
- unsupported algorithms
- policy downgrade
- domain mismatch
- context mismatch
- request mismatch
- stale receipt
- replayed receipt
- registry rollback
- revoked keys
- expired keys
- signature splicing
- reordered signature arrays
- optional FN-DSA inserted before or between required signatures
- metadata authority injection
- v3 downgrade where v4 is required

## V4-INV-023 — Complete Six-Bundle Plan

No backend callback may run until all six signature bundles and every referenced
trusted key have passed cheap preflight. Required-only evidence performs exactly
12 callbacks: six classical followed by six ML-DSA. If every bundle carries
optional FN-DSA, it performs exactly 18 callbacks, with six FN-DSA callbacks
last. A required-wave failure stops all later waves.

The shared total and PQC counters increment immediately before an actual
backend callback. Backend exceptions and non-Boolean results fail closed.

## Final Invariant

Cryptography proves Shield evidence.

Cryptography does not grant execution authority.

AdamantineOS remains the final boundary.

## V4.8H-E component summary profile invariant

Every Orchestrator `component_signature_results` entry now carries both:

```text
verified_algorithms
verified_standard_profiles
```

The arrays must align one-for-one. Required algorithms remain `classical-ed25519` and `ml-dsa`; optional `fn-dsa` may be present only with `fips206-draft-falcon1024-v1`. Missing profile summaries, profile omissions, unsupported profiles, duplicate algorithms, or unsupported algorithms are rejected before the final receipt can be accepted as valid evidence.
