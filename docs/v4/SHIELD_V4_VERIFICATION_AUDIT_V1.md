# Shield v4 Verification Audit Contract v1

Status: V4.10-C normative contract  
Schema: `shield.verification_audit.v1`  
Verifier: `shield_orchestrator.v4`  
Author attribution: DarekDGB

## Purpose and authority boundary

This contract defines privacy-safe, append-only evidence for Shield v4
verification. Audit output records what the verifier checked. It is not an
approval, signing instruction, execution command, replay grant, policy
override, or source of authority.

The audited Orchestrator entry point is
`verify_v4_receipt_with_audit`. Existing low-level functions remain unchanged
and intentionally produce no durable audit evidence:

```text
verify_component_verdicts
validate_receipt_envelope
verify_signature_bundle
```

Release integrations that require durable verification evidence must use the
audited entry point. Stateful replay consumption remains an AdamantineOS
execution-boundary responsibility. The Orchestrator does not claim an atomic
replay commit.

## Trusted boundary inputs

The audited entry point requires:

```text
receipt
artifact_transport_hash
expected_context_hash
expected_request_id
registry
minimum_registry_version
verification_time
component_verifier
receipt_verifier
audit_sink
```

`artifact_transport_hash` is a caller-supplied SHA-256 of the caller's exact,
bounded original transport. It is never computed by stringifying an arbitrary
Python object. The hash must be 64 lowercase hexadecimal characters.

`expected_context_hash`, `expected_request_id`, the loaded trusted registry,
the registry floor, and verification time are verifier-controlled.
Verification time is exactly `YYYY-MM-DDTHH:MM:SSZ`.

Malformed trusted arguments are programmer errors and can fail before an audit
batch exists. Receipt-controlled preflight and verification failures must be
audited and fail closed.

The wrapper snapshots the untrusted receipt graph behind the preflight
exception barrier and the limits in
`SHIELD_V4_PERFORMANCE_DOS_ENVELOPE_V1.md`. Only exact built-in JSON object,
array, string, Boolean, signed 64-bit integer, and null types enter
verification; subclasses, floats, cycles, excess depth or nodes, oversized
strings, and other objects are rejected as a sanitized contract failure. The
cumulative scalar and object-key byte counter stops before copying or
canonicalizing an over-budget graph.

The outer receipt must match `expected_request_id`. Component request IDs are
not required to equal the outer request ID. Each validated component event
hashes that component's own signed request ID.

Before signed-payload canonicalization, hashing, or component cryptography, the
wrapper validates the exact outer and component field shapes, requires exactly
five unique component bundles and one outer bundle, and completes policy,
profile, role, freshness, registry, key identity, key status, public-key, and
key/artifact-window resolution for all six bundles. A failure at this boundary
remains one failed preflight event using only the trusted transport hash and
causes zero backend callbacks.

After that complete cheap plan, the wrapper enforces canonical bundle and
receipt byte ceilings and independently recomputes the receipt hash, outer
domain-separated signed-payload hash, and every component signed-payload hash.
It never promotes a received hash into an artifact event until that value
matches the independently computed hash. The artifact map is constructed only
after those checks, so an untrusted duplicate identifier cannot overwrite
another component's audit attribution.

## Privacy-safe identifier hashes

Request identifiers are NFC-normalized and hashed as:

```text
SHA256(UTF8("DGB-SHIELD-V4-AUDIT-REQUEST-ID\n") || UTF8(NFC(request_id)))
```

Key identifiers are NFC-normalized and hashed as:

```text
SHA256(UTF8("DGB-SHIELD-V4-AUDIT-KEY-ID\n") || UTF8(NFC(key_id)))
```

Raw request IDs and raw key IDs are forbidden in audit records.

## Exact tagged union

Every event contains exactly these common fields:

```text
schema_version
event_type
verifier_id
verification_timestamp
verification_passed
reason_id
```

`schema_version` is `shield.verification_audit.v1`.
`verifier_id` is `shield_orchestrator.v4`.
`verification_passed` is an exact JSON Boolean.
`verification_passed` is true if and only if `reason_id` is `V4_VERIFY_OK`;
every failure reason requires false.

### `verification_preflight`

The event has the common fields plus exactly:

```text
artifact_type
expected_artifact_schema_version
artifact_transport_hash
expected_request_id_hash
expected_context_hash
required_policy_version
minimum_registry_version
```

The Orchestrator preflight artifact is `orchestrator_receipt`, expected schema
is `shield.receipt.v2`, and required policy is `policy.v1`.

### `signature_verification`

The event has the common fields plus exactly:

```text
artifact_type
artifact_schema_version
artifact_id
artifact_hash
request_id_hash
context_hash
policy_version
registry_version
key_id_hash
key_version
algorithm
standard_profile
```

This variant exists only after artifact and key identity fields are safely
validated. `artifact_hash` is the validated `signed_payload_hash`.

For `component_verdict`, `artifact_id` is exactly one of:

```text
adn
dqsn
guardian_wallet
qwg
sentinel_ai
```

For `orchestrator_receipt`, `artifact_id` is `shield_orchestrator`.

Algorithms and profiles must match the existing Shield v4 policy allowlist.

### `artifact_verification`

The event has the common fields plus exactly:

```text
artifact_type
artifact_schema_version
artifact_id
artifact_hash
request_id_hash
context_hash
policy_version
registry_version
```

This is the terminal variant for a safely established artifact. A batch that
progressed beyond preflight ends in an artifact success or failure. An early
failure without a safely established artifact is represented by a single
failed preflight event; fields are never fabricated and null placeholders are
forbidden.

## Stable reason IDs

Only these reason IDs are allowed:

```text
V4_VERIFY_OK
V4_CONTRACT_INVALID
V4_CONTEXT_MISMATCH
V4_REQUEST_MISMATCH
V4_HASH_MISMATCH
V4_DOWNGRADE_REJECTED
V4_AUTHORITY_BYPASS
V4_POLICY_INVALID
V4_REGISTRY_INVALID
V4_FRESHNESS_INVALID
V4_REPLAY_REJECTED
V4_SIGNATURE_INVALID
V4_BACKEND_UNAVAILABLE
V4_BACKEND_FAILURE
```

Raw exception messages, exception causes, backend diagnostics, and sink
diagnostics must never become audit fields or public verification errors.

## Canonical records and limits

Each event is exact Shield canonical JSON encoded as immutable UTF-8 `bytes`.
The sink receives only a tuple of those bytes. Limits are:

```text
maximum records per batch: 24
maximum bytes per record: 2048
maximum canonical batch bytes: 49152
```

The standard two-algorithm positive lifecycle has 14 records: one successful
preflight, 12 signature events, and one successful receipt terminal. With
optional FN-DSA throughout, the lifecycle has 20 records.

## Batch hash and durable acknowledgement

The batch hash is:

```text
SHA256(
  UTF8("DGB-SHIELD-V4-VERIFICATION-AUDIT-BATCH:shield.verification_audit.v1\n")
  || CanonicalJSON({"records": [decoded canonical events in tuple order]})
)
```

`append_batch` must append the entire non-empty tuple atomically and in order,
or append none. It must make the batch durable before returning this exact
acknowledgement as an exact built-in dictionary (subclasses are rejected):

```text
schema_version = shield.verification_audit.append_ack.v1
batch_sha256 = exact domain-separated batch hash
record_count = exact positive integer count
durably_committed = true
```

The acknowledgement has no additional fields. Its object, string, and integer
values use exact built-in types; subclasses are rejected. Batch hashes are
compared with a constant-time digest comparison. A missing, malformed, false,
mismatched, or exceptional acknowledgement withholds the verification result
and raises only:

```text
ShieldV4AuditSinkError("V4_AUDIT_SINK_FAILURE")
```

The sink interface exposes no update or delete operation. Implementations must
be append-only and should make retry of an already committed batch hash
idempotent without duplicating records.

## Forbidden content

Audit records must not contain:

- raw request IDs or key IDs;
- private keys, seeds, recovery phrases, or private-key references;
- public keys or signature bytes;
- raw payloads, component metadata, nonces, or handoff content;
- backend or sink exception text;
- personal data not required by this contract; or
- any authority, approval, signing, broadcast, execution, or bypass field.

## Fail-closed lifecycle

The wrapper verifies the bounded snapshot, registry floor, expected outer
request binding, exact schemas, all six bundles, and every referenced trusted
key before canonicalization, signed-hash construction, or backend callbacks.
It then verifies canonical byte budgets and independently computed hashes.

Actual backend attempts are recorded in their true global execution order: all
six classical attempts, all six ML-DSA attempts, then optional FN-DSA attempts.
The shared total/PQC work counter increments immediately before each callback.
A callback exception or non-Boolean result is sanitized and fails closed.
Existing component and receipt validators consume cached successful attempts;
they do not repeat backend work.

Events remain buffered until one atomic append. Success is returned only after
an exact durable acknowledgement. Verification rejection is returned only
after its failure batch is durably acknowledged. Audit failure always wins and
remains fail closed.
