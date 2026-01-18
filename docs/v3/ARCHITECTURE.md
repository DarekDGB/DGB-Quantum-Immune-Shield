# Orchestrator v3 — Architecture

MIT DarekDGB 2025

This document describes the **system architecture** and **boundaries**
of the DigiByte Quantum Shield Orchestrator under Shield Contract v3.

It exists to prevent drift and to make review/audit possible.

If this file conflicts with CONTRACT.md, **CONTRACT.md wins**.

---

## 1. Role

The Orchestrator is the **coordination + aggregation** layer that produces
a **single v3 decision envelope** for upstream callers (e.g. Adamantine Wallet OS).

It consumes **read-only** results from Shield v3 components and synthesizes:
- final `outcome` (ALLOW / ESCALATE / DENY)
- stable `reason_ids`
- deterministic `context_hash`
- deterministic pipeline trace

---

## 2. Non-Goals (Hard Boundaries)

The Orchestrator MUST NOT:
- hold or derive private keys
- sign or broadcast transactions
- mutate wallet/node state
- auto-upgrade or hot-patch any component
- hide authority behind flags, env vars, or “admin overrides”
- perform network consensus actions

Orchestrator v3 is **coordination**, not control.

---

## 3. Inputs and Outputs

### 3.1 Input (v3 request)
A v3 request contains only caller-supplied data required for orchestration, such as:
- wallet_id (or caller scope)
- action (SEND / SIGN / CONNECT / etc. as defined by caller)
- context_hash (if provided by upstream) OR raw fields used to compute it
- ttl_seconds / nonce (if used; must be caller-provided)
- contract_version = 3

Orchestrator MUST reject (deny) invalid or incomplete requests per CONTRACT.md.

### 3.2 Output (v3 response)
A single v3 response envelope containing:
- contract_version = 3
- context_hash
- outcome
- reason_ids
- trace (deterministic)

---

## 4. Pipeline Stages (Deterministic Order)

The Orchestrator MUST evaluate stages in the following fixed order:

1. **Input validation**
2. **Sentinel AI v3**
3. **DQSN v3**
4. **ADN v3**
5. **QWG v3**
6. **Guardian Wallet v3**
7. **Final synthesis**

This ordering is part of the contract because it affects determinism and trace.

---

## 5. Bridge Adapters

The Orchestrator uses bridge adapters under:

- `src/shield_orchestrator/bridges/`

Bridges are adapters only. They must:
- call/receive component outputs
- validate schemas
- enforce `contract_version == 3`
- map failure classes to orchestrator reason ids
- never invent data
- never decide final outcomes

**All decision logic lives in v3 orchestration core**, not in bridges.

---

## 6. Deterministic Trace Design

The trace is an audit record of what happened.

Rules:
- stable ordering per pipeline stages
- no secrets
- deterministic notes (no hostnames, env vars, timestamps generated inside)
- consistent structure across outcomes

The trace must allow reviewers to answer:
- which components were consulted
- which ones denied or errored
- why the orchestrator produced the final outcome

---

## 7. Fail-Closed Behavior

Fail-closed applies at every boundary:
- invalid input -> DENY
- bridge exception -> DENY
- missing component response -> DENY
- invalid component schema -> DENY
- contract version mismatch -> DENY

No silent allow.

---

## 8. Minimal Trusted Computing Base (Minimal TCB)

The Orchestrator should remain small:
- avoid large dependencies
- prefer pure-python deterministic primitives
- treat every external component output as untrusted input

---

## 9. Integration with Adaptive Core v3

Adaptive Core v3 receives **read-only reports** from:
- each shield component
- the orchestrator trace and final decision envelope

Adaptive Core v3 is an **upgrade oracle**:
- it does not grant runtime authority
- it produces human-reviewed upgrade recommendations
- upgrades happen via explicit commits, not via orchestrator runtime behavior

---

## License

MIT DarekDGB 2025
