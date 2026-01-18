# Orchestrator v3 — Reason IDs

MIT DarekDGB 2025

This document defines the orchestrator-level **ReasonId registry** for v3.

Rules:
- no magic strings in code (single enum/registry)
- stable ids across v3 releases
- fail-closed mapping for every failure class
- deterministic ordering in responses

---

## Core Orchestrator Reasons (v3)

- `INVALID_CONTRACT_VERSION`  
  Request or component response is missing contract_version or is not 3.

- `INVALID_REQUEST`  
  Request schema is missing required fields or contains invalid types.

- `HASHING_FAILED`  
  Canonicalization or context_hash computation failed.

- `COMPONENT_ERROR`  
  Bridge raised an exception or component failed in an unexpected way.

- `COMPONENT_INVALID_RESPONSE`  
  Component response schema invalid or missing required v3 fields.

- `COMPONENT_MISSING`  
  Required component result was not available.

- `DENY_BY_POLICY`  
  Orchestrator policy requires deny (deny-by-default).

- `INTERNAL_ERROR`  
  Unknown internal error. Must be deterministic catch-all.

---

## Ordering Rule

The Orchestrator MUST return reason ids in a stable ordering:
1. version/request validation reasons first
2. component reasons in pipeline order
3. internal catch-all last

---

## License

MIT DarekDGB 2025
