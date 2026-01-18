# Orchestrator v3 — API

MIT DarekDGB 2025

This document defines the **public API surface** of the Orchestrator under v3.

If this file conflicts with CONTRACT.md, **CONTRACT.md wins**.

---

## 1. Public Entrypoint

The Orchestrator MUST expose a single v3 entrypoint.

Recommended Python signature:

```python
def orchestrate(request: OrchestratorV3Request) -> OrchestratorV3Response:
    ...
```

The entrypoint:
- accepts a v3 request envelope
- returns a v3 response envelope
- never raises uncaught exceptions (errors become DENY)

---

## 2. v3 Request Envelope

The request envelope MUST include:

- `contract_version: int` (MUST be 3)
- `wallet_id: str`
- `action: str`
- `nonce: str`
- `ttl_seconds: int`

Optional fields are allowed only if:
- they are explicitly documented
- they are included in canonical hashing rules

---

## 3. v3 Response Envelope

The response envelope MUST include:

- `contract_version: int` (MUST be 3)
- `context_hash: str`
- `outcome: str` (ALLOW / ESCALATE / DENY)
- `reason_ids: list[str]` (stable ordering)
- `trace: list[TraceEntry]` (stable ordering)

---

## 4. Trace Entry Schema

Each trace entry MUST include:

- `stage: str`
- `component: str`
- `status: str` (OK / DENY / ERROR)
- `reason_ids: list[str]`
- `component_context_hash: str | None`

Optional:
- `notes: str | None` (must be deterministic)

---

## 5. Canonicalization / Hashing Notes

The orchestrator MUST provide:
- deterministic canonical JSON for hashing
- deterministic stable ordering for lists

The exact hashing definition is fixed by CONTRACT.md.

---

## License

MIT DarekDGB 2025
