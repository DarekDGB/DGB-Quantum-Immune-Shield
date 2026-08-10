# Shield v4 Known-Answer Test Vectors

Author attribution: DarekDGB

## Status

This document records the controlled Shield v4 Known-Answer Test vectors and
identifies the current external-verifier package.

All fixture signatures are TEST-ONLY unless a fixture explicitly states that
it contains captured real-backend material. Deterministic fixtures do not claim
production Ed25519, ML-DSA, or FN-DSA cryptography.

## Current External-Verifier Package

Normative contract:

```text
docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_CONTRACT_V1.md
```

Self-excluding package manifest:

```text
docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_PACKAGE_V1.json
```

Shared full-chain KAT:

```text
tests/fixtures/v4/external_verifier_contract_v1_kat.json
```

Regression lock:

```text
tests/test_v49_external_verification_contract.py
```

The shared KAT contains:

- five complete signed component verdicts;
- one complete signed Orchestrator receipt;
- canonical C -> M -> optional F ordering in all six bundles;
- 18 verifier-controlled TEST-ONLY registry entries;
- exact canonical JSON UTF-8 and hex;
- exact domain-separated payload UTF-8 and hex;
- receipt and signed-payload hashes;
- exact deterministic TEST-ONLY signature inputs;
- exact production real-crypto signature-input bytes for every entry;
- explicit replay, denylist, registry-floor, time, context, and request inputs;
- an evidence-only expected result with `final_approval: false`; and
- no embedded local `verification_summary` fields.

The shared external-verifier receipt hash is:

```text
0bfa04a330270d41db352861971742ebeb901a9f1e51612cdd91b5405cc26378
```

The shared external-verifier signed payload hash is:

```text
9c66e9607bd58f9b41f6e885b49e44f1566bd46b5b734fa8365444d80548f026
```

## Historical V4.3 Receipt KAT

Location:

```text
tests/fixtures/v4/orchestrator_receipt_policy_v1_kat.json
```

File SHA-256:

```text
636773fe7bef34525e48a004b019529c811d2f5f16c1a5f97cf073545715886d
```

Correct frozen receipt hash:

```text
9b46e013b5fdcc70df190219fa19548698f48909ce000ccdb64f9062cf4860b6
```

Correct frozen signed payload hash:

```text
9004b38d7c55f7a2ed7b75b7b129279a64874c050b8c3b944b94e6dd8e80c8ad
```

This historical fixture remains byte-locked as an earlier canonicalization and
receipt-envelope vector. Its deliberately reduced component objects do not form
the current complete external-verifier transport contract. Consumers must use
the V1 external-verifier package for current cross-repository verification.

Previously published stale hash text has been removed. The regression lock
requires the two values above to match the committed historical fixture.

## V4.8H Draft FN-DSA Signed-Message KAT

Location:

```text
tests/fixtures/v4/fn_dsa_signed_message_draft_profile_kat.json
```

File SHA-256:

```text
ab05e603ba6c9711651f3a23ee0f3526e3d8aa781e763974bd002d864d286a59
```

This vector freezes the exact draft FN-DSA/Falcon-1024 real-signature input
bytes, including authenticated `standard_profile`, so implementations cannot
drift from the Orchestrator byte construction.

## Common Contract Values

Orchestrator receipt domain:

```text
DGB-SHIELD-V4-ORCH-RECEIPT:shield.receipt.v2:policy.v1
```

Component verdict domain:

```text
DGB-SHIELD-V4-COMPONENT-VERDICT:shield.verdict.v2:policy.v1
```

Canonicalization profile:

```text
shield-v4-canon.v1
```

Signature policy:

```text
policy.v1
```

Required algorithm paths:

```text
classical-ed25519
ml-dsa
```

Optional evidence path:

```text
fn-dsa
```

Locked optional profile:

```text
standard_profile: fips206-draft-falcon1024-v1
Falcon parameter set: Falcon-1024
```

ML-DSA means ML-DSA, formerly CRYSTALS-Dilithium.

FN-DSA means FN-DSA, based on Falcon. FN-DSA is not ML-DSA and cannot satisfy
the ML-DSA requirement.

The FN-DSA vector is draft-profile evidence only. It must not be reused as a
final FIPS 206 proof without a later final-profile backend, registry keys, and
KAT refresh.

## Deterministic and Live-Crypto Separation

The V1 external-verifier KAT freezes deterministic TEST-ONLY signatures and
exact production signature-input bytes. It does not contain production private
keys and does not prove that a live cryptographic backend is available.

Live ML-DSA-65 and draft FN-DSA/Falcon-1024 proof remains a separate guarded
real-OQS workflow. Coverage success or deterministic KAT success cannot replace
that guarded proof.

## Registry and Summary Boundary

The shared registry is verifier-controlled pinned TEST-ONLY input. A registry
provided by an untrusted receipt never becomes a trust anchor.

`standard_profile` is authenticated in each signature entry and checked against
the verifier allow-list. It is not a registry-entry field.

The shared transport KAT omits receipt and component `verification_summary`
fields. Those summaries are local verifier output. The signed
`component_signature_results` array must be independently reverified and
cross-checked, never trusted by itself.

## Authority Boundary

Passing a KAT proves only that an implementation agrees with the frozen test
vector and contract bytes.

It does not grant transaction-signing authority.

It does not grant broadcast authority.

It does not change DigiByte consensus.

It does not bypass local wallet policy or AdamantineOS.

AdamantineOS remains the final fail-closed policy and execution boundary.
