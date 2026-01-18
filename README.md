# DigiByte Quantum Shield Orchestrator (v3)

![CI](https://github.com/DarekDGB/DGB-Quantum-Immune-Shield/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen)
![License](https://img.shields.io/github/license/DarekDGB/DGB-Quantum-Immune-Shield)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

**Shield Contract v3 • Deterministic Orchestration • Fail-Closed Security**

The Orchestrator is the **routing + aggregation layer** that coordinates the DigiByte Quantum Shield’s v3 components (Sentinel AI, DQSN, ADN, QWG, Guardian Wallet) and the **Adaptive Core v3** upgrade oracle.

It produces a **single deterministic v3 envelope** that downstream callers (like Adamantine Wallet OS) can treat as the authoritative shield result.

> Orchestrator v3 coordinates and aggregates.  
> It does **not** sign, broadcast, hold keys, or mutate state.

---

## Core Properties

- **Contract v3 only** (any other version → fail-closed)
- **Deterministic & replayable** (same input → same output → same context_hash)
- **Fail-closed** (no silent defaults, no “best effort”)
- **Strict canonicalization** (stable JSON → stable hashing)
- **No hidden authority** (aggregation only, never escalation-by-magic)
- **Traceable** (component-by-component pipeline trace)

---

## Role in the DigiByte Quantum Shield

Adamantine Wallet OS  
→ Orchestrator v3  
→ Sentinel AI v3  
→ DQSN v3  
→ ADN v3  
→ QWG v3  
→ Guardian Wallet v3  

Signals return back through the Orchestrator as a single v3 envelope.

Adaptive Core v3 receives **read-only reports** from all layers (including Orchestrator) and issues **human-reviewed upgrade recommendations**.

---

## What Orchestrator v3 Produces

A single **v3 response envelope** containing:

- `contract_version = 3`
- deterministic `context_hash`
- final `outcome` (allow / escalate / deny)
- stable `reason_ids` (deny-by-default if uncertain)
- a **pipeline trace**
- canonical JSON suitable for audit and replay

---

## What Orchestrator v3 Does NOT Do

- hold private keys or secrets
- sign or broadcast transactions
- modify wallet or node state
- guess missing fields
- auto-upgrade layers
- bypass EQC / WSQK / Guardian / QWG rules

---

## Documentation (v3)

All authoritative documentation lives under:

```
docs/v3/
```

- INDEX.md
- CONTRACT.md
- ARCHITECTURE.md
- API.md
- REASON_IDS.md

Legacy v2 docs are preserved under:

```
docs/legacy/v2/
```

If code and docs diverge, **CONTRACT.md + tests win**.

---

## Quality & Verification

- CI enforced
- ≥90% test coverage
- deterministic tests only
- negative-first testing
- no silent fallback paths

---

## License

MIT DarekDGB 2025
