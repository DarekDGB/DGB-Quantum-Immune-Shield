# Contributing to DGB Quantum Immune Shield Orchestrator

The **DigiByte Quantum Immune Shield Orchestrator** is the coordination layer that
connects all defensive components:

- DQSN v2 – network health & entropy
- Sentinel AI v2 – anomaly detection
- ADN v2 – tactical defence engine
- QWG – Quantum Wallet Guard
- Guardian Wallet – user-facing protection
- Adaptive Core v2 – learning & fusion engine

This repository does **not** implement the internals of those layers.  
Instead, it:

- defines **interfaces** between them
- wires them together via **bridges**
- runs **pipelines** that move signals, context, and decisions between layers
- provides a **test harness** for running end-to-end shield flows

Contributions must preserve this role: **orchestration only, never consensus or wallet logic.**

---

## ✅ What Contributions Are Welcome

### ✔️ 1. Bridge & Pipeline Improvements
- new or improved bridges under `src/shield_orchestrator/bridges/`
- better error handling or retries between layers
- richer context propagation between DQSN → Sentinel → ADN → QWG → Guardian → Adaptive Core
- more robust pipeline logic in `pipeline.py` and `context.py`

### ✔️ 2. Test Harness & Scenarios
- additional end-to-end tests in `tests/`
- new scenarios (e.g. reorg, spam, eclipse, hashpower spikes)
- fixtures that simulate layer outputs and expected orchestrated behaviour

### ✔️ 3. Configuration & Observability
- safer configuration patterns in `config.py`
- logging / tracing improvements
- clearer environment and integration settings

### ✔️ 4. Documentation
- clarifications to docs in `docs/`
- better diagrams of data flow
- extended FAQ entries

---

## ❌ What Will NOT Be Accepted

### 🚫 1. Moving Layer Logic Into the Orchestrator
The orchestrator must **not** re-implement:

- Sentinel AI analytics
- DQSN metric computation
- ADN defence playbooks
- QWG behavioural analysis / PQC verification
- Guardian Wallet UX logic
- Adaptive Core learning

Those belong in their own repositories.

### 🚫 2. Consensus or Protocol Changes
This project must **never**:

- alter DigiByte consensus rules
- modify block or mempool validation
- act as a validator or governance layer

It is strictly a **coordination and integration** component.

### 🚫 3. Opaque or Hidden Behaviour
- no black-box decision engines
- no unexplained magic routes
- no hidden configuration that changes security posture without visibility

### 🚫 4. Tight Coupling to a Single Deployment
The orchestrator should remain generic and reusable, not hard-coded to one environment or operator.

---

## 🧱 Design Principles

1. **Separation of Concerns**  
   Each shield layer keeps its own logic. The orchestrator just connects them.

2. **Explicit Interfaces**  
   Bridges are well-defined, typed, and documented.

3. **Consensus Neutral**  
   No consensus changes, ever.

4. **Deterministic Pipelines**  
   Given the same inputs, the same orchestration behaviour must result.

5. **Observability & Auditability**  
   All flows should be loggable and understandable.

6. **Extensibility**  
   New layers or external tools should plug into the orchestration pipeline cleanly.

---

## 🔄 Pull Request Expectations

A good PR should:

- clearly describe what is being changed and why
- reference any relevant document under `docs/`
- include tests for new orchestration paths
- avoid breaking folder structure without strong justification
- preserve the orchestrator’s role as **integration glue**, not a logic sink

The architect (@DarekDGB) reviews **direction & architecture fit**.  
Developers review **implementation details** and CI health.

---

## 📝 License

By contributing, you agree that your contributions are licensed under the MIT License.

© 2025 **DarekDGB**
