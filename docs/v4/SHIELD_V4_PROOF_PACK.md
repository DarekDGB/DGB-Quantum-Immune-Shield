# Shield v4 Orchestrator Proof Pack

Status: controlled `4.0.0` release candidate; not released or tagged
Author attribution: DarekDGB

## Evidence scope

This proof pack records the authenticated V4.10-C implementation baseline used
to prepare the V4.10-D release documents. It does not authorize `v4.0.0` and
does not replace the later V4.10-H, V4.10-I, V4.10-J, V4.10-K, or V4.10-L
evidence and release-decision gates.

Authenticated source:

```text
repository: DGB-Quantum-Shield-Orchestrator
commit: d4d4f7338b4109d4914bf6861b62a8e9e2dfd0f5
git tree: 1d7b87b877bc832b7894f8261929c8c76c0f5d0b
fresh ZIP: DGB-Quantum-Shield-Orchestrator-main(20260822-074745).zip
fresh ZIP SHA-256: 889ed72fc515e51364af3698921083e51408daa537c38b8e897b5584b6d6d100
fresh ZIP bytes: 251793
archive inventory: 121 files, 20 directories, 141 entries
```

The ZIP comment, remote `main`, official Git tree, and reconstructed archive
tree agree. Archive CRC, path, duplicate, casefold/NFC collision, encryption,
symlink, special-file, and generated-artifact checks pass.

Against authenticated V4.10-B commit
`ecc0360b3f77cf7b894717c3f30d93534ced1b35`, V4.10-C is exactly 5 new and
7 replaced files with zero deletions. All 109 unrelated files are
byte-identical. The 12 changed files exactly match:

```text
package: Shield_V4_10_C_ORCHESTRATOR_PERFORMANCE_DOS_17b7825e.zip
package SHA-256: 17b7825e1f2abb904ca6b92e98f5cb5db8213538c3306004df2d7819d465da2b
content manifest SHA-256: afb3ab2da11228578c22abd700f39117d91dc0279644c37f1d3f124eea9b0a9f
```

## Distribution and immutable contract identities

The release-facing distribution candidate is `4.0.0`. The candidate tag name
is `v4.0.0`; no v4 tag exists or is authorized by this document.

The metadata bump does not change these identities:

```text
v3 contract version: 3
v3 verdict schema: shield.verdict.v1
v3 receipt schema: shield.receipt.v1
v3 compatibility package version: 3.2.0
v4 contract version: 4
v4 verdict schema: shield.verdict.v2
v4 receipt schema: shield.receipt.v2
signature bundle schema: shield.signature_bundle.v1
key registry schema: shield.key_registry.v1
canonicalization profile: shield-v4-canon.v1
signature policy: policy.v1
```

## Algorithm and authority matrix

| Path | Status | Profile | Security meaning |
|---|---|---|---|
| `classical-ed25519` | Required | `rfc8032-ed25519-v1` | Required classical evidence |
| `ml-dsa` | Required | `fips204-ml-dsa-65-v1` | Required PQC evidence |
| `fn-dsa` | Optional and last only | `fips206-draft-falcon1024-v1` | Supplemental draft-profile evidence |

Both required paths must verify. Optional FN-DSA may be absent. If present, it
must verify and cannot replace or rescue either required path. The draft
Falcon-1024 profile is not final FIPS 206 proof.

No path grants transaction signing, broadcast, wallet-key custody, DigiByte
consensus authority, final approval, or an AdamantineOS bypass.

## Frozen KAT and package-manifest evidence

These existing normative files remain byte-identical in V4.10-D:

| Evidence | SHA-256 |
|---|---|
| External verification contract | `7119b3ee26d3aad8fb6040d349734dfdeca0251cdce743f47516282374098bea` |
| KAT index | `c39080f077dec9ae599d5cba3a518274446f2efd8975ab14dc3d79bfcf58067a` |
| External full-chain KAT | `308b9aadd993cf07665a125c4294d8e22cbe3f747419e346e104f127093e951f` |
| Self-excluding external package manifest | `44a3b3cf59efb22b90a11ca9a971abd3ec00282f0c00272c98ef7582151b1223` |
| Historical receipt KAT | `636773fe7bef34525e48a004b019529c811d2f5f16c1a5f97cf073545715886d` |
| Draft FN-DSA/Falcon signed-message KAT | `ab05e603ba6c9711651f3a23ee0f3526e3d8aa781e763974bd002d864d286a59` |
| Pinned required-only performance fixture | `279f69dce971d5695ff2ac61f3aca5921e9cd936e059405e79ece38824899ce9` |

The new test matrix, proof pack, and release-status documents are release
evidence around the frozen external-verifier package. They are deliberately
outside that package's exact three-file self-excluding manifest.

## Exact-commit GitHub workflow evidence

GitHub reports every required V4.10-C run completed successfully on
`d4d4f7338b4109d4914bf6861b62a8e9e2dfd0f5`.

| Workflow | Run | Run ID | Event | Completed UTC | Result and exact count boundary |
|---|---:|---:|---|---|---|
| `CI` | [#321](https://github.com/DarekDGB/DGB-Quantum-Shield-Orchestrator/actions/runs/32556674716) | `32556674716` | push | `2026-08-22T06:20:08Z` | Python 3.11 and 3.13 jobs each: 347 passed, 4 approved skips, 0 failed/errors; 2375/2375 statements, 100 percent |
| `Shield Live Integration` | [#135](https://github.com/DarekDGB/DGB-Quantum-Shield-Orchestrator/actions/runs/32556777805) | `32556777805` | workflow dispatch | `2026-08-22T06:22:40Z` | 2 collected and passed; skipped=0, failures=0, errors=0 |
| `Shield v4 Performance and DoS Envelope` | [#12](https://github.com/DarekDGB/DGB-Quantum-Shield-Orchestrator/actions/runs/32556812124) | `32556812124` | workflow dispatch | `2026-08-22T06:23:11Z` | 54 focused tests passed; pinned benchmark status `PASS` |
| `Shield v4 Real OQS ML-DSA and Falcon-1024 Proof` | [#95](https://github.com/DarekDGB/DGB-Quantum-Shield-Orchestrator/actions/runs/32556691297) | `32556691297` | workflow dispatch | `2026-08-22T06:25:46Z` | tests=2, skipped=0, failures=0, errors=0, required=2 |

The CI job IDs are `96991869791` for Python 3.11 and `96991869695` for
Python 3.13. The live, performance, and real-OQS job IDs are respectively
`96992130134`, `96992213987`, and `96991912430`.

The real-OQS JUnit guard requires exactly:

```text
tests/test_v48g_real_oqs_mldsa_backend.py::test_v48g_real_oqs_mldsa65_orchestrator_backend_round_trip_and_negatives
tests/test_v48h_e_real_oqs_falcon_backend.py::test_v48h_e_real_oqs_falcon1024_backend_round_trip_and_negatives
```

The live-integration run requires the two nodes in
`tests/live/test_step11_2_real_component_integration.py`. Successful guard
steps prove that neither workflow silently passed by skipping its required
nodes.

## JUnit and retained-artifact boundary

The successful live and real-OQS jobs generated transient JUnit XML and ran
their exact no-skip guards. GitHub's run-artifact API reports zero retained
artifacts for both runs, so no persisted JUnit archive SHA-256 is claimed.

Final retained report identity remains an explicit V4.10-H/I evidence item.
This disclosure is preferable to inventing a report hash. The committed test
matrix and this proof pack are the controlled equivalent evidence records for
V4.10-D, but they do not misrepresent a stored workflow artifact.

## Independent local reproduction

Exact CPython 3.11.15 and the fresh ZIP bytes produced:

```text
full suite: 347 passed, 4 approved skips
statement coverage: 2375/2375, 100.00 percent
focused V4.10-C suite: 54 passed
combined V4.10-B audit plus V4.10-C envelope: 114 passed
```

The standard four skips are approved only in the default suite: native ML-DSA,
native Falcon-1024, and the two full cross-repository live nodes. Dedicated
workflows executed those boundaries with zero skips.

Pinned benchmark reproduction used Python 3.11.15, `PYTHONHASHSEED=0`, UTC,
`C.UTF-8`, pip 25.2, setuptools 80.9.0, wheel 0.45.1, pytest 8.4.1,
pytest-cov 6.2.1, 20 warmups, and 200 samples:

```text
valid median: 3.807891 ms
valid p95: 4.341373 ms
valid p95 limit: 50.0 ms
oversize median: 0.133543 ms
oversize p95: 0.171975 ms
oversize p95 limit: 20.0 ms
status: PASS
```

The benchmark uses deterministic no-op callbacks and measures verifier
planning, audit, and rejection overhead, not provider cryptographic latency.

## Observability and durable acknowledgement

`tests/test_v410b_verification_audit.py` locks the exact privacy-safe tagged
union, identifier hash domains, canonical immutable record bytes, ordered
batch hash, bounded batch size, sanitized failures, and exact durable
acknowledgement.

Success and verification rejection are both withheld until durable append
acknowledgement. Sink failure always wins and raises only
`ShieldV4AuditSinkError("V4_AUDIT_SINK_FAILURE")`. Audit evidence never grants
authority.

## Performance and DoS evidence

`tests/test_v410c_performance_dos_envelope.py` locks:

- the exact built-in JSON graph boundary;
- UTF-8 scalar, object-key, string, bundle, and receipt byte ceilings;
- depth, node, integer, registry, bundle, and signature limits;
- complete six-bundle preflight before hashes or callbacks;
- six classical, six ML-DSA, and optional FN-DSA global waves;
- 12 required-only and 18 maximum total callbacks;
- 12 maximum combined ML-DSA/FN-DSA callbacks; and
- zero callbacks for every cheap preflight failure.

## Negative matrix

The test matrix maps all 23 v4 invariants to exact nodes. The wider negative
suite rejects missing or duplicate components, wrong roles or keys, unknown or
reordered algorithms, policy downgrade, cross-domain replay, signature splice,
hash/context/request tampering, stale or replayed evidence, registry rollback,
revoked or expired keys, profile mutation, optional rescue, authority
injection, hostile containers, over-budget inputs, backend exceptions, and
audit-sink failure.

## Known residual issues and remaining gates

- liboqs and liboqs-python are fetched from floating default branches in the
  current native workflow.
- Existing standard, live, and native workflows retain mutable major action
  tags; live component checkouts are not immutable.
- Standard CI enforces statement coverage, not branch coverage.
- Not every transient JUnit/report file is uploaded as a retained artifact.
- Native evidence uses test keys and does not prove production custody or HSM
  assurance.
- Provider cryptographic latency is outside the pinned structural benchmark.
- FN-DSA/Falcon-1024 remains a draft profile and is not final FIPS 206 proof.
- V4.10-D requires its own post-commit workflows and fresh-ZIP verification.
- V4.10-E through V4.10-L remain separate controlled gates.

No release tag may be created or moved without explicit DarekDGB approval at
the final release-decision gate.
