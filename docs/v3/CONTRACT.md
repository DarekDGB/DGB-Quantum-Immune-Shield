# Orchestrator v3 — Shield Contract (Normative)

MIT DarekDGB 2025

This document is the authoritative Shield Contract v3 specification
for the DigiByte Quantum Shield Orchestrator.

If anything conflicts with this document, this document wins.

Purpose:
- Deterministic aggregation
- Fail-closed orchestration
- No authority, no signing, no mutation

Contract rules:
- contract_version MUST be 3
- Any violation -> DENY
- Deterministic outputs
- Canonical JSON
- Stable context_hash
- Stable pipeline trace

Outcomes:
- ALLOW
- ESCALATE
- DENY

Failure is never success.

License:
MIT DarekDGB 2025
