# Contributing to DGB Quantum Shield Orchestrator

Maintainer: DarekDGB

The repository contains two intentionally separate contract surfaces:

- the frozen Shield v3 compatibility surface; and
- the parallel Shield v4 cryptographic-evidence and receipt surface.

Tests and normative contract documents are authoritative. Contributions must
describe implemented behavior, preserve version boundaries, and remain
fail closed.

## Repository role

The Orchestrator may:

- validate versioned Shield component evidence;
- coordinate deterministic component order;
- verify v4 signature bundles under verifier-controlled trust;
- aggregate evidence into one Shield receipt;
- produce privacy-safe verification audit evidence; and
- enforce bounded verification work.

The Orchestrator must not:

- sign or broadcast transactions;
- hold, derive, or access wallet private keys;
- modify DigiByte consensus;
- move component-specific security policy into this repository;
- treat AI output or metadata as authority;
- grant final approval; or
- override AdamantineOS.

AdamantineOS remains the final fail-closed policy and execution boundary.

## Welcome contributions

### Contract and validation hardening

Changes may tighten exact field shapes, canonicalization, role binding,
freshness, replay, registry, signature-policy, audit, or work-budget checks.
Every behavioral change requires focused positive and negative tests.

### Bridge and compatibility maintenance

Bridge changes must preserve explicit contracts and must not silently alter the
frozen v3 surface. A v3 compatibility repair must not weaken v4-required mode.

### Testing and evidence

Useful test contributions include:

- negative-first contract matrices;
- canonicalization and cross-domain replay cases;
- signature order, duplicate, splice, and no-rescue cases;
- role, registry, revocation, freshness, replay, and denylist cases;
- durable-audit acknowledgement and privacy failures;
- graph, byte, registry, bundle, and callback budget boundaries; and
- guarded live-backend or cross-repository evidence.

### Documentation

Documentation must state what code and tests prove now. Historical v3 material
must remain clearly classified. V4 documents belong under `docs/v4/`; legacy
material belongs under `docs/legacy/`.

Do not publish a final release, production-key, final FIPS 206, transaction
authority, or consensus claim that the evidence does not prove.

## V4 contract requirements

Changes to the v4 evidence surface must preserve:

- exact `shield-v4-canon.v1` canonicalization;
- required `classical-ed25519 + ml-dsa` verification;
- optional `fn-dsa` last only under the allowed draft Falcon-1024 profile;
- no optional rescue of a required failure;
- canonical received signature order;
- role, key, profile, policy, domain, context, request, and freshness binding;
- verifier-controlled registry and rollback floor;
- complete six-bundle cheap preflight before backend work;
- total and PQC callback ceilings;
- privacy-safe append-only audit records;
- exact durable acknowledgement before result release; and
- evidence-only authority boundaries.

If a proposal cannot preserve an invariant, stop and version the contract
explicitly before implementation.

## Required gates

Every pull request must keep standard CI and the committed 100 percent
statement-coverage gate green.

Run additional gates when relevant:

- `Shield Live Integration` for cross-repository behavior;
- `Shield v4 Performance and DoS Envelope` for verifier, work-budget,
  performance asset, or package metadata changes; and
- `Shield v4 Real OQS ML-DSA and Falcon-1024 Proof` for real-backend,
  algorithm, profile, key-registry, or package metadata changes.

Guarded workflows must collect the exact required nodes and reject every skip,
failure, or error. Deterministic tests do not substitute for native-OQS proof.

## Pull request expectations

A change should:

- state intent and exact scope;
- identify changed contracts and authority boundaries;
- include tests for every behavioral claim;
- preserve repository structure and attribution;
- avoid generated caches, coverage data, editable metadata, native build
  products, and secrets; and
- avoid unrelated formatting or release-history drift.

Only DarekDGB may authorize repository changes, releases, or tag movement.

## License

By contributing, you agree that your contribution is licensed under the MIT
License.

Copyright 2025 DarekDGB
