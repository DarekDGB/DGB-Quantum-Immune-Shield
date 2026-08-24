# DigiByte Quantum Shield Orchestrator 4.0.0 Candidate

![CI](https://github.com/DarekDGB/DGB-Quantum-Shield-Orchestrator/actions/workflows/ci.yml/badge.svg)
![Coverage 100%](https://img.shields.io/badge/coverage-100%25-brightgreen)
![License](https://img.shields.io/github/license/DarekDGB/DGB-Quantum-Shield-Orchestrator)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Status](https://img.shields.io/badge/status-CONTROLLED--PRE--RELEASE-orange)

Author attribution: **DarekDGB**

Distribution version: `4.0.0`
Candidate tag: `v4.0.0`
Release status: **controlled pre-release; not released and not tagged**

The DigiByte Quantum Shield Orchestrator is the deterministic aggregation,
cryptographic-evidence verification, and signed-receipt boundary for Shield.
It verifies component evidence, produces the one Shield receipt that
AdamantineOS may consume, and fails closed when evidence is invalid,
incomplete, stale, replayed, downgraded, or outside the bounded verification
contract.

## Authority boundary

Shield evidence is not execution authority.

The Orchestrator does not:

- sign or broadcast transactions;
- hold, derive, or access wallet private keys;
- modify DigiByte consensus;
- grant final wallet approval;
- bypass local wallet policy; or
- override AdamantineOS.

AdamantineOS remains the final fail-closed policy and execution boundary. A
Shield `ALLOW` result means only that verified evidence may continue to those
independent checks.

## Current Shield v4 surface

The parallel v4 contract preserves the historical v3 compatibility surface
and adds:

- canonical signed component verdicts and Orchestrator receipts;
- role-separated, versioned verifier-controlled key registries;
- required classical Ed25519 and ML-DSA verification;
- optional FN-DSA/Falcon-1024 draft-profile evidence;
- canonical signature-bundle ordering and no-rescue policy;
- freshness, context, request, registry-floor, replay, and denylist checks;
- an external verification contract with shared Known-Answer Test vectors;
- guarded real-liboqs ML-DSA and Falcon-1024 evidence;
- privacy-safe append-only verification audit records with durable
  acknowledgement; and
- a bounded six-bundle verification plan with callback and input ceilings.

The frozen `policy.v1` order is:

```text
classical-ed25519
ml-dsa
fn-dsa                    optional and last only
```

The required strict-AND paths are `classical-ed25519 + ml-dsa`. Optional
`fn-dsa` may be absent. If present, it must use
`fips206-draft-falcon1024-v1`, must verify, and cannot replace or rescue either
required path. This is draft FN-DSA/Falcon-1024 evidence, not final FIPS 206
proof.

## Verification order and bounded work

The release-facing audited verifier accepts a bounded exact-JSON graph and
completes cheap structural, schema, policy, role, profile, freshness, registry,
and key checks for all five component bundles plus the outer receipt bundle
before cryptographic callbacks.

After complete preflight, callbacks run in global waves:

1. classical Ed25519 for all six artifacts;
2. ML-DSA for all six artifacts; and
3. optional FN-DSA for applicable artifacts.

Required-only evidence performs exactly 12 callbacks. Fully optional evidence
performs at most 18 callbacks. A pre-crypto failure performs zero callbacks and
emits one sanitized failed-preflight audit event.

The durable audit boundary withholds every success or rejection result until
the append-only sink returns the exact acknowledgement for the complete batch.
Audit failure remains fail closed.

## Proof boundaries

Different workflows prove different properties:

- `CI` runs the committed full suite on Python 3.11 and 3.13 with 100 percent
  statement coverage;
- `Shield Live Integration` runs the exact cross-repository integration nodes
  with a no-skip JUnit guard;
- `Shield v4 Performance and DoS Envelope` runs exact Python 3.11.15,
  pinned software, 20 warmups, 200 samples, focused work-budget tests, and
  p95 limits; and
- `Shield v4 Real OQS ML-DSA and Falcon-1024 Proof` runs the exact two native
  liboqs nodes with a no-skip JUnit guard.

Standard CI and deterministic KATs do not by themselves prove that native
liboqs executed. Native test evidence does not prove production key custody,
HSM operation, final FIPS 206 conformance, or release authorization.

## V4 documentation

- Contract invariants:
  `docs/v4/SHIELD_V4_CONTRACT_INVARIANTS.md`
- Canonicalization:
  `docs/v4/SHIELD_V4_CANONICALIZATION_SPEC.md`
- Threat model:
  `docs/v4/SHIELD_V4_THREAT_MODEL.md`
- Test matrix:
  `docs/v4/SHIELD_V4_TEST_MATRIX.md`
- External verification contract:
  `docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_CONTRACT_V1.md`
- External package manifest:
  `docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_PACKAGE_V1.json`
- KAT index:
  `docs/v4/SHIELD_V4_KAT_VECTORS.md`
- Real-crypto backend:
  `docs/v4/SHIELD_V4_REAL_CRYPTO_BACKEND.md`
- Verification audit:
  `docs/v4/SHIELD_V4_VERIFICATION_AUDIT_V1.md`
- Performance and DoS envelope:
  `docs/v4/SHIELD_V4_PERFORMANCE_DOS_ENVELOPE_V1.md`
- Proof pack:
  `docs/v4/SHIELD_V4_PROOF_PACK.md`
- Release status:
  `docs/v4/SHIELD_V4_RELEASE_STATUS_v4.0.0.md`
- PQC scope lock:
  `docs/v4/SHIELD_V4_PQC_SCOPE_LOCK.md`
- Q-ID alignment:
  `docs/v4/SHIELD_V4_QID_CRYPTO_ALIGNMENT.md`

Tests and normative contract documents define truth. A public claim must not
exceed the evidence recorded in the proof pack and release status.

## V3 compatibility and history

The immutable `v3.2.0` tag and its documentation remain historical release
evidence. The v3 contract, verdict, and receipt identities remain unchanged.
The top-level distribution version bump does not reinterpret or rewrite v3
artifacts.

New integrations should use the v4 evidence surface only when their controlled
deployment has satisfied the applicable V4.10 gates. Historical v3 behavior
must not be silently accepted where a verifier requires v4.

## Development

Install the test dependencies and run the committed suite:

```text
python -m pip install -e ".[test]"
pytest
```

The default suite intentionally skips opt-in native-OQS and complete
cross-repository live nodes unless their dedicated environments are enabled.
The guarded workflows must collect the exact required nodes and reject every
skip.

## Release governance

`4.0.0` is the aligned distribution candidate and `v4.0.0` is only the
candidate tag name. No release decision has been authorized, and no v4 tag may
be created or moved until the controlled V4.10 release gates are complete and
DarekDGB explicitly approves the release action.

## License

MIT License. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.

Copyright 2025 DarekDGB
