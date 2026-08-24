# Security Policy - DigiByte Quantum Shield Orchestrator

Repository: `DGB-Quantum-Shield-Orchestrator`
Maintainer: DarekDGB
License: MIT

## Supported surfaces

| Surface | Status |
|---|---|
| Distribution `4.0.0` / candidate `v4.0.0` | Controlled pre-release; security-maintained; not released or tagged |
| Shield v3.2.0 compatibility surface | Historical immutable release; compatibility-maintained |
| Older archived behavior | Unsupported unless an issue affects the maintained surfaces |

The v4 distribution version does not change frozen v3 protocol or schema
identities. Historical material remains non-authoritative for the v4 security
surface.

## Security model

The Orchestrator is a deterministic, fail-closed evidence-verification,
aggregation, and signed-receipt boundary.

It does not:

- alter DigiByte consensus;
- sign or broadcast transactions;
- hold, derive, or access wallet private keys;
- grant final wallet approval;
- override local policy; or
- override AdamantineOS.

AdamantineOS remains the final fail-closed policy and execution boundary.
Shield `ALLOW` is verified evidence that may continue to downstream checks,
not execution authority.

## Non-negotiable v4 controls

### Exact contracts and canonicalization

V4 verdict, receipt, signature-bundle, key-registry, canonicalization, and
policy identifiers are versioned and fail closed on mismatch. Signed JSON is
UTF-8, NFC-normalized, type-restricted, and canonically serialized. Duplicate
keys, unsupported fields, ambiguous numbers, and non-canonical evidence are
rejected.

### Required and optional algorithms

`policy.v1` requires both:

```text
classical-ed25519
ml-dsa
```

Optional `fn-dsa` may be present only last and only under
`fips206-draft-falcon1024-v1`. Optional evidence may be absent. Present but
invalid optional evidence is fatal. FN-DSA cannot replace or rescue a missing
or failed required path. The draft Falcon-1024 profile is not final FIPS 206
proof.

### Role, registry, and time binding

Every signature binds algorithm, profile, key ID, key version, role, domain,
and signed payload hash. The verifier controls the trusted registry and minimum
registry floor. Unknown, revoked, expired, wrong-role, out-of-window, replayed,
or downgraded evidence fails closed.

### Durable verification audit

Release-facing integrations that require audit evidence must use the audited
v4 verification boundary. It produces privacy-safe canonical records, hashes
request and key identifiers under separate domains, forbids secrets and raw
identifiers, and appends one ordered batch.

No success or rejection result leaves that boundary until the sink returns the
exact durable acknowledgement. Missing, malformed, false, mismatched, hostile,
or exceptional acknowledgement fails closed as `V4_AUDIT_SINK_FAILURE`.

### Performance and denial-of-service limits

The audited boundary snapshots only bounded exact built-in JSON types. It caps
graph depth, node count, scalar bytes, single strings, bundle bytes, receipt
bytes, registry entries, signature counts, and backend callbacks.

All five component bundles and the outer receipt bundle complete cheap
preflight before signed-payload hashing or backend work. Required callbacks run
in a six-artifact classical wave followed by a six-artifact ML-DSA wave.
Optional FN-DSA runs last. Pre-crypto failures perform zero callbacks.

## Evidence boundaries

Security claims must distinguish:

- standard CI and deterministic test-double coverage;
- shared Known-Answer Test and external-contract conformance;
- complete cross-repository live integration;
- pinned structural performance and rejection cost; and
- guarded native liboqs ML-DSA/Falcon execution.

Standard CI does not prove native OQS execution. Native OQS tests use test
keys and test backends; they do not prove production key custody, HSM
assurance, provider hardening, or final FIPS 206 conformance.

## Required negative behavior

The maintained v4 surface must reject:

- missing or invalid required signatures;
- reordered, duplicated, unknown, or unsupported algorithm entries;
- optional FN-DSA inserted before or between required paths;
- required-path rescue attempts;
- role, key, profile, policy, domain, context, or request mismatch;
- stale, future, replayed, denied, revoked, or registry-rollback evidence;
- signature splicing and hash mismatch;
- metadata or handoff authority injection;
- v3 evidence where trusted policy requires v4;
- hostile JSON containers, subclasses, cycles, overcounts, and oversized
  encoded fields; and
- audit sink failure or diagnostic leakage.

Tests and normative contract documents define truth.

## Known pre-release residuals

- The real-OQS workflow fetches liboqs and liboqs-python from floating default
  branches rather than immutable commits.
- Standard, live-integration, and real-OQS workflows retain mutable major
  action tags in existing workflow definitions.
- Live-integration component checkouts are not pinned to immutable commits.
- Standard CI enforces statement coverage, not branch coverage.
- Current live workflows create transient JUnit reports but do not upload every
  report as a retained artifact.
- The pinned performance gate measures deterministic verifier overhead with
  no-op callbacks and excludes provider cryptographic latency.
- The FN-DSA/Falcon-1024 profile is draft evidence only.

These residuals are disclosed release inputs. They must not be hidden by a
public claim.

## Reporting a vulnerability

Do not disclose a suspected security issue publicly first.

Use a private GitHub security advisory when available, or contact the
maintainer through the GitHub profile `@DarekDGB`.

Include:

- affected commit or tag;
- clear reproduction steps;
- expected and actual behavior;
- security impact; and
- whether the issue affects v3 compatibility, v4 evidence, or both.

## Release governance

Distribution `4.0.0` is a controlled candidate. No `v4.0.0` release tag may be
created or moved before the complete V4.10 release decision and explicit
DarekDGB authorization. Repository metadata and green CI do not themselves
authorize a release.

## Final security rule

Reject any change that weakens deterministic canonicalization, fail-closed
behavior, required signature policy, role separation, durable audit,
work-budget ceilings, or the evidence-only authority boundary.

Copyright 2025 DarekDGB
