# Shield v4 Performance and DoS Envelope v1

Status: V4.10-C normative contract  
Author attribution: DarekDGB

## Purpose and authority boundary

This contract bounds the untrusted work performed by the release-facing
`verify_v4_receipt_with_audit` entry point. It does not grant approval,
transaction signing, broadcast, custody, consensus, or execution authority.
AdamantineOS remains the final execution boundary.

Low-level compatibility functions retain their existing signatures. They are
not the release-facing durable-audit boundary and do not carry this complete
six-bundle request budget by themselves.

The audited API receives an already-parsed Python dictionary and a trusted,
caller-supplied hash of the exact transport. These snapshot and canonical-byte
ceilings are not a raw HTTP body, compressed-message, decompression, or JSON
parser byte limit. The ingress owner must separately cap raw and decompressed
transport bytes and parser resources before constructing the dictionary or
calling this API. The supplied transport hash must be computed from those exact
bounded original bytes.

## Frozen input budgets

The audited verifier enforces these limits before cryptographic callbacks:

```text
canonical receipt bytes                         131072
cumulative UTF-8 scalar and object-key bytes    131072
one UTF-8 string or encoded field                  8192
one canonical signature bundle bytes              32768
container depth                                       16
container nodes                                     4096
signed integer width                                  64 bits
component signature bundles                           5
receipt signature bundles                             1
signatures in each bundle                           2..3
total signature bundles                                6
backend verification callback attempts                18
ML-DSA plus FN-DSA callback attempts                   12
loaded trusted-registry entries                        64
```

The initial snapshot accepts only exact built-in JSON dictionaries, lists,
strings, integers, Booleans, and null. It rejects subclasses, floats, other
objects, cycles, excess depth, excess nodes, and integers outside the signed
64-bit range. Empty generic JSON strings and object keys remain valid at this
generic layer; an artifact schema can reject them later.

The scalar-byte counter includes UTF-8 bytes for every string value and object
key, ASCII bytes for each integer, four bytes for `null` and `true`, and five
bytes for `false`. It stops before copying or canonicalizing an over-budget
graph. Each string and object key is independently limited to 8192 UTF-8 bytes.

Receipt canonical size and each bundle canonical size are separate post-shape
limits. This prevents escape expansion from bypassing the byte envelope.
Oversize and overcount inputs fail as `V4_CONTRACT_INVALID`.

## Frozen validation and callback order

The audited verifier performs one bounded snapshot and then completes every
cheap check for all six bundles before any signed-payload canonicalization,
hash construction, or backend callback. Cheap preflight includes exact field
sets, bundle counts and entry shapes, contract and schema versions, policy,
role, algorithm, standard profile, freshness, registry floor, key identity,
key status, key validity windows, artifact validity windows, and all public-key
lookups.

Only after the complete six-bundle key plan exists may the verifier enforce
canonical bundle and receipt byte limits and compute receipt or component
signed hashes. Any failure before cryptography produces exactly one failed
preflight audit event and zero backend callbacks.

The verifier prepares exactly five component bundles and one outer receipt
bundle. Every bundle has unique canonical entries for required
`classical-ed25519` and `ml-dsa`, with optional `fn-dsa` last. Backend attempts
then run in global waves:

1. classical Ed25519 for all six artifacts;
2. ML-DSA for all six artifacts;
3. optional FN-DSA for each artifact that carries it.

The shared counter increments immediately before each actual callback. A
required-wave failure stops later work. Existing validators consume cached
successful attempts and cannot call the backend twice.

The required-only chain therefore performs exactly 12 backend attempts, six
of them PQC. A chain with FN-DSA in every bundle performs exactly 18 backend
attempts, 12 of them PQC. No accepted chain can exceed either ceiling.

## Pinned benchmark gate

The dedicated workflow runs only on `ubuntu-24.04` with:

```text
CPython           3.11.15
PYTHONHASHSEED    0
TZ                UTC
LC_ALL            C.UTF-8
warmups           20 per case
samples           200 per case
pip               25.2
setuptools        80.9.0
wheel             0.45.1
pytest            8.4.1
pytest-cov        6.2.1
```

The workflow pins checkout and Python-setup actions to reviewed full commit
SHAs and installs the package without dependency or build-isolation resolution.

The required-only audited fixture is frozen at SHA-256:

```text
279f69dce971d5695ff2ac61f3aca5921e9cd936e059405e79ece38824899ce9
```

Nearest-rank p95 limits are:

```text
required-only audited verification     <= 50.0 ms
oversize receipt rejection             <= 20.0 ms
```

`scripts/benchmark_v410c_verification.py` emits exactly one JSON object with
schema `shield-v4-v410c-performance-v1`, repository, fixture hash, environment,
the installed pinned package versions, warmup and sample counts, median and p95
measurements, limits, and status. It returns nonzero when either threshold
fails.

The fixture uses deterministic no-op verification callbacks. Provider crypto
latency is deliberately excluded so this gate measures Orchestrator validation,
planning, audit construction, and rejection overhead. The callback ceilings
bound crypto invocation count. Provider CPU cost and platform variance remain
residual operational risks and require the separate two-node real-OQS gate.

Timing is not part of the standard multi-version unit-test workflow. Only the
pinned performance workflow is comparable release evidence.

## Required release gates

V4.10-C requires all of the following:

- the standard full suite with 100 percent committed coverage;
- the pinned performance and DoS workflow;
- the existing two-node real-OQS ML-DSA and Falcon-1024 proof with zero skips.

Generated caches, coverage files, editable-install metadata, benchmark output,
and native build products are not release payloads.
