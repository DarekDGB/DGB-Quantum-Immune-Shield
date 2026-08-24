# Changelog - DigiByte Quantum Shield Orchestrator

All notable changes to this repository are documented here.

Tests and normative contract documents define truth. Release notes do not
grant authority or replace the controlled release gates.

## 4.0.0 Candidate - Unreleased

Status: controlled pre-release. Candidate tag: `v4.0.0`. Tag created: no.

### Added

- Added the parallel Shield v4 verdict, receipt, signature-bundle, and
  verifier-controlled key-registry surfaces.
- Added the frozen `shield-v4-canon.v1` canonicalization profile and
  domain-separated signed payloads.
- Added required classical Ed25519 and ML-DSA verification under `policy.v1`.
- Added optional-last FN-DSA/Falcon-1024 draft-profile evidence with strict
  no-rescue behavior.
- Added shared external verification contract, deterministic KATs, and the
  self-excluding package manifest.
- Added real-backend interface contracts and guarded native liboqs ML-DSA and
  Falcon-1024 proofs.
- Added privacy-safe append-only verification audit records with an exact
  durable acknowledgement requirement.
- Added bounded six-bundle preflight, canonical byte limits, registry and
  graph limits, callback ceilings, and a pinned performance/DoS workflow.
- Added the v4 test matrix, proof pack, and controlled release-status record.

### Changed

- Aligned the distribution metadata and active public documentation to the
  `4.0.0` candidate.
- Preserved every v3 protocol and schema identity as an independent
  compatibility surface.
- Historicized old present-tense v3.2.0 pending-tag wording without changing
  the immutable tag or its release history.
- Updated contribution and security guidance for the dual v3/v4 repository.

### Security

- Required exact canonical signature order:
  `classical-ed25519`, `ml-dsa`, then optional `fn-dsa`.
- Required both classical and ML-DSA paths; optional FN-DSA cannot replace or
  rescue a failed required path.
- Bound role, profile, payload hash, freshness, request, context, registry
  floor, key status, and validity windows.
- Required cheap complete six-bundle preflight before cryptographic callbacks.
- Required durable audit acknowledgement before any verification result leaves
  the release-facing boundary.
- Preserved no transaction signing, no broadcast, no private-key custody, no
  consensus change, and no final execution authority.

### Release gate

This entry does not announce a release. V4.10 final evidence, adversarial,
hash, attribution, fresh-ZIP, and release-decision gates remain controlling.
Only DarekDGB may authorize creation or movement of the `v4.0.0` tag.

## v3.2.0 - Manifest / Verdict / Receipt Boundary Hardening

The immutable `v3.2.0` tag already exists. The gate below is retained as the
historical pre-tag checklist that governed that release.

### Added

- Added Shield v3.2.0 manifest, registry, and receipt-boundary hardening.
- Added deterministic Shield Orchestrator receipt construction.
- Added canonical receipt validation.
- Added AdamantineOS handoff documentation.
- Added stable evidence-family registry documentation.
- Added v3.2.0 proof-pack and test-matrix documentation.
- Added v3.2.0 Orchestrator receipt lock tests.
- Added explicit component-evidence-only boundary language.

### Changed

- Updated package metadata to `3.2.0` for that historical release.
- Updated the historical README and security policy for the v3.2 receipt
  boundary.
- Clarified that Shield `ALLOW` was not final signing or execution approval.

### Security

- Reinforced fail-closed malformed-verdict and receipt handling.
- Reinforced duplicate component verdict rejection.
- Reinforced stable reason ID and evidence-family validation.
- Reinforced no signing, broadcast, key custody, consensus modification, or
  hidden authority.

### Historical release gate

Before the existing immutable `v3.2.0` tag was created, the controlled process
required:

- the roadmap checklist to be complete;
- tests and 100 percent coverage to pass;
- manifest, reason ID, evidence-family, and receipt documents to align;
- the AdamantineOS handoff boundary to remain intact;
- a final fresh-ZIP audit and Red Team report; and
- no documentation-versus-test mismatch.

## v3.1.0 - Shield Orchestrator Foundation Hardening

### Added

- Foundation hardening for the Shield v3 Orchestrator.
- CI coverage confirmation for the `shield_orchestrator` package.
- Documentation alignment for deterministic and fail-closed orchestration.

### Changed

- Updated package metadata to `3.1.0` for that historical release.
- Clarified Adaptive Core as read-only advisory input with no outcome
  authority.
- Clarified the Orchestrator role as the deterministic integration boundary.

## v3.0.0 - Stable Shield Orchestrator Baseline

- Added the stable Shield v3 Orchestrator baseline.
- Added deterministic component coordination and fail-closed orchestration.
- Added the initial v3 contract documentation.

Copyright 2025 DarekDGB
