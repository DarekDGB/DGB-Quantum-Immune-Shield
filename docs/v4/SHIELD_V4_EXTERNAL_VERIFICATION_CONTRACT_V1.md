# Shield v4 External Verification Contract V1

Author attribution: DarekDGB

## 1. Status and Scope

This document freezes the versioned external-verifier contract for Shield v4
Orchestrator evidence. It is intended for wallets, AdamantineOS, independent
auditors, and other verify-only consumers.

The normative shared vector is:

```text
tests/fixtures/v4/external_verifier_contract_v1_kat.json
```

The package manifest is:

```text
docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_PACKAGE_V1.json
```

The manifest deliberately does not hash itself. That rule prevents a cyclic
manifest dependency.

This contract does not add a signing API, broadcast API, transaction API,
consensus rule, approval authority, or execution authority.

## 2. Authority Boundary

Shield v4 produces cryptographically verifiable decision evidence only.

It does not:

- sign transactions;
- broadcast transactions;
- change DigiByte consensus;
- authorize wallet execution;
- override local wallet policy;
- override AdamantineOS policy; or
- turn an ALLOW evidence result into final approval.

AdamantineOS remains the final fail-closed policy and execution boundary. A
wallet verifier may accept Shield evidence for further local checks, but it must
not treat that evidence as execution authority.

The expected positive state in the shared KAT is:

```text
state: VERIFIED_ALLOW_EVIDENCE_CONTINUE_CHECKS
verified: true
accepted_as_evidence: true
final_approval: false
```

## 3. Contract Identifiers

```text
external contract schema: shield.external_verifier_contract.v1
external contract version: 1
receipt schema: shield.receipt.v2
component verdict schema: shield.verdict.v2
signature bundle schema: shield.signature_bundle.v1
key registry schema: shield.key_registry.v1
Shield contract version: 4
canonicalization profile: shield-v4-canon.v1
signature policy: policy.v1
```

An external verifier must reject unsupported versions. It must not silently
downgrade or reinterpret a later version under this contract.

## 4. Algorithm and Profile Policy

The canonical policy order is:

```text
classical-ed25519
ml-dsa
fn-dsa
```

The required strict-AND policy is:

```text
classical-ed25519 + ml-dsa
```

FN-DSA is optional evidence only. If present, it must be last. An invalid
optional FN-DSA entry is fatal. It cannot replace or rescue a failed required
entry.

The exact profiles are:

```text
classical-ed25519 -> rfc8032-ed25519-v1
ml-dsa -> fips204-ml-dsa-65-v1
fn-dsa -> fips206-draft-falcon1024-v1
```

ML-DSA means ML-DSA, formerly CRYSTALS-Dilithium.

FN-DSA means FN-DSA, based on Falcon. This contract freezes draft
FN-DSA/Falcon-1024 evidence. It does not claim final FIPS 206 proof.

Builders emit a new canonical outer list. Verifiers never sort, repair, or
reinterpret received signature order. The only valid received sequences are:

```text
classical-ed25519, ml-dsa
classical-ed25519, ml-dsa, fn-dsa
```

## 5. Canonical JSON

Canonical JSON uses:

- UTF-8;
- NFC-normalized strings and keys;
- lexicographically sorted object keys;
- no insignificant whitespace;
- JSON separators `,` and `:` without following spaces;
- JSON lowercase literals;
- integers only for numeric values;
- no floating-point values;
- no `null`; absent fields are omitted;
- no duplicate key before or after NFC normalization; and
- list order preserved exactly.

The canonical JSON text is equivalent to Python `json.dumps` with:

```text
sort_keys=True
separators=(",", ":")
ensure_ascii=False
allow_nan=False
```

after recursive NFC normalization and type validation.

## 6. Signed Payload Domains

Component verdict domain:

```text
DGB-SHIELD-V4-COMPONENT-VERDICT:shield.verdict.v2:policy.v1
```

Orchestrator receipt domain:

```text
DGB-SHIELD-V4-ORCH-RECEIPT:shield.receipt.v2:policy.v1
```

The exact domain-separated signed payload bytes are:

```text
DGB-SHIELD-V4-SIGNED-PAYLOAD\n<domain_tag>\n<canonical_json_bytes>
```

There is no terminal LF added after the canonical JSON bytes. The
`signed_payload_hash` is lowercase SHA-256 hex over those exact bytes.

The receipt `receipt_hash` is lowercase SHA-256 hex over the canonical unsigned
receipt JSON bytes without the domain prefix.

## 7. Real-Crypto Signature Input

Every external implementation must reproduce the exact real-backend message
bytes for each signature entry:

```text
DGB-SHIELD-V4-REAL-CRYPTO-SIGNATURE-INPUT
<domain_tag>
<signed_payload_hash>
<algorithm>
<standard_profile>
<key_id>
<key_version>
```

The lines are joined with ASCII LF. There is no terminal LF.

The shared KAT freezes both UTF-8 and hex representations of these bytes for
all 18 entries: three algorithms across five component roles and the
Orchestrator role.

## 8. TEST-ONLY Signature Inputs

The shared KAT uses deterministic TEST-ONLY signatures so all consumers can
reproduce the package without private key material.

Component TEST-ONLY input is:

```text
<component-specific TEST-ONLY prefix>
<public test key>
<algorithm>
<standard_profile>
<signed_payload_hash>
```

Its deterministic signature is SHA-256 hex over those UTF-8 bytes.

Orchestrator TEST-ONLY input is:

```text
<domain_tag>|<signed_payload_hash>|<algorithm>|<standard_profile>|<key_id>|<key_version>
```

Its deterministic signature is HMAC-SHA256 hex using the public test material
as the TEST-ONLY HMAC key.

These deterministic signatures are contract test doubles. They are not live
Ed25519, ML-DSA, or FN-DSA signatures. Passing them is not live cryptographic
proof. Live-OQS proof remains a separate guarded workflow boundary.

## 9. External KAT Wrapper

The top-level shared KAT object has exactly these fields:

```text
author_attribution
canonicalization_profile
contract_version
expected_result
inputs
kat_artifacts
receipt
schema_version
signature_policy
verifier_controlled_test_registry
warning
```

The input object has exactly:

```text
expected_context_hash
expected_request_id
minimum_key_registry_version
rejected_receipt_hashes
seen_request_ids
verification_time
```

The expected result object has exactly:

```text
accepted_as_evidence
dominant_reason_ids
final_approval
final_outcome
handoff_allowed
reason_id
state
verified
```

## 10. Receipt Envelope

The transport receipt has exactly these fields:

```text
adamantineos_handoff
canonicalization_profile
component_signature_results
component_verdicts
context_hash
contract_version
dominant_reason_ids
fail_closed
final_outcome
freshness_nonce
key_registry_version
not_after
not_before
receipt_hash
request_id
schema_version
signature_bundle
signature_policy
signed_payload_hash
```

`verification_summary` is intentionally omitted from the shared transport KAT.
It is optional local verifier output and is excluded from the outer signed
payload.

The unsigned receipt payload is the receipt after omitting:

```text
receipt_hash
signature_bundle
signed_payload_hash
verification_summary
```

The five component verdicts are sorted by `component_id`:

```text
adn
dqsn
guardian_wallet
qwg
sentinel_ai
```

The `component_signature_results` array is signed Orchestrator evidence. An
external verifier must independently verify every embedded component bundle
and cross-check the claimed results. It must never trust that array by itself.

## 11. Component Verdict Envelope

Each transport component verdict has exactly these fields:

```text
canonicalization_profile
component_id
context_hash
contract_version
decision
evidence_families
evidence_hash
fail_closed
freshness_nonce
key_registry_version
metadata
not_after
not_before
reason_ids
request_id
schema_version
signature_bundle
signature_policy
signed_payload_hash
```

The optional local `verification_summary` is omitted. If a component verifier
adds it locally, that field is excluded from the component signed payload. If a
summary is embedded before receipt construction, the outer receipt binds the
embedded bytes. External consumers should prefer the transport form without
local summaries.

The unsigned component payload is the component verdict after omitting:

```text
signature_bundle
signed_payload_hash
verification_summary
```

## 12. Component Signature Result

Each component signature result has exactly:

```text
component_id
component_role
signature_policy
verified
verified_algorithms
verified_standard_profiles
```

The algorithm and profile arrays must have equal length and corresponding
positions. Required algorithms must be present. Consumers may normalize those
paired summary values for comparison, but they must not confuse summary-array
order with the raw signature-bundle order contract.

## 13. Signature Bundle and Entry

Each signature bundle has exactly:

```text
policy_version
schema_version
signatures
```

Each signature entry has exactly:

```text
algorithm
domain_tag
key_id
key_version
signature
signed_payload_hash
standard_profile
```

Every entry in a bundle must bind the same expected domain and signed payload
hash. Algorithms and `(key_id, key_version)` identities must be unique inside a
bundle.

## 14. Verifier-Controlled Registry

The KAT registry has exactly:

```text
entries
registry_version
schema_version
```

Every registry entry has exactly:

```text
algorithm
key_id
key_version
not_after
not_before
public_key
role
status
```

`standard_profile` is not a registry-entry field. It is authenticated in the
signature entry and checked against the verifier allow-list.

The KAT registry contains 18 active TEST-ONLY entries: three algorithms for
each of the five component roles and the Orchestrator role.

The registry is explicitly verifier-controlled pinned test input. A registry
inside or beside an untrusted receipt does not become trusted merely because it
arrived with the receipt. Production consumers must obtain trust anchors from
their own controlled configuration.

## 15. KAT Artifact Records

The `kat_artifacts` array contains six records in this order:

```text
adn
dqsn
guardian_wallet
qwg
sentinel_ai
shield_orchestrator
```

Each artifact record has exactly:

```text
artifact_id
canonical_json_hex
canonical_json_utf8
domain_separated_payload_hex
domain_separated_payload_utf8
domain_tag
role
signature_inputs
signed_payload_hash
unsigned_payload
unsigned_payload_sha256
```

Each signature-input record has exactly:

```text
algorithm
deterministic_signature
domain_tag
key_id
key_version
public_key_hex
public_key_utf8
real_crypto_signature_input_hex
real_crypto_signature_input_utf8
signed_payload_hash
standard_profile
test_only_signature_input_hex
test_only_signature_input_utf8
test_only_signature_scheme
```

The UTF-8 strings and hex fields must decode to identical bytes. Recomputed
canonical JSON, domain-separated bytes, unsigned payload hashes, signed payload
hashes, real-crypto input bytes, TEST-ONLY input bytes, and deterministic
signatures must match exactly.

## 16. Required Verification Order

An external verifier must fail closed and complete cheap structural preflight
before any trust lookup or cryptographic call.

At minimum, preflight covers every embedded component bundle and the outer
receipt bundle for:

- exact object and field shape;
- supported schema, contract, canonicalization, and policy versions;
- required component and role set;
- canonical component order where defined;
- canonical signature algorithm order;
- required algorithm presence;
- duplicate algorithm and key identity;
- allowed profile for each algorithm;
- expected domain tag;
- expected signed payload hash;
- context and request binding;
- receipt and component hash binding;
- registry version consistency; and
- prohibited authority fields.

After complete preflight, the verifier applies verifier-controlled trust,
registry floor, status, key validity, artifact freshness, replay, denylist, and
cryptographic checks. A verifier must fail closed on any exception or non-Boolean
backend result.

## 17. Freshness, Replay, and Denylist Inputs

The KAT pins:

- expected context hash;
- expected request id;
- verification time;
- minimum trusted registry version;
- previously seen request ids; and
- rejected receipt hashes.

The positive KAT uses empty replay and denylist inputs. Consumers must supply
their own live state. The KAT does not grant authority to modify that state.

Registry rollback checking compares the verifier-controlled registry version
against the caller-controlled minimum floor. It does not infer historical
revocation state that is not present in the trusted registry.

## 18. Negative Requirements

An implementation is nonconforming if it:

- accepts reversed or interleaved signature order;
- accepts missing required Ed25519 or ML-DSA evidence;
- lets valid FN-DSA rescue invalid required evidence;
- ignores an invalid optional FN-DSA entry;
- trusts `component_signature_results` without re-verification;
- accepts receipt-supplied trust anchors;
- repairs received evidence before verifying it;
- performs trust or cryptographic work before complete bundle preflight;
- accepts stale, replayed, denied, revoked, or out-of-window evidence;
- treats TEST-ONLY signatures as live cryptographic proof; or
- returns final approval from Shield evidence alone.

## 19. Package Manifest Rule

The external package manifest hashes these normative files:

```text
docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_CONTRACT_V1.md
docs/v4/SHIELD_V4_KAT_VECTORS.md
tests/fixtures/v4/external_verifier_contract_v1_kat.json
```

It does not list or hash itself. The regression test verifies the exact
whitelist and every listed SHA-256 value.

## 20. Conformance Result

Passing the deterministic package test proves byte and contract agreement with
this frozen vector. It does not prove that a production cryptographic backend
is available or correctly installed.

Live Ed25519, ML-DSA-65, and draft FN-DSA/Falcon-1024 verification evidence must
remain independently guarded. Cryptography proves Shield evidence. It does not
grant execution authority.
