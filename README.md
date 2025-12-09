# 🧱 DigiByte Quantum Immune Shield — Orchestrator  
### *5-Layer Defence Coordination • Cross-Layer Signal Routing • Testnet Harness*  
**Architecture by @DarekDGB — MIT Licensed**

---

## 🚀 What Is This Repository?

This repository contains the **orchestrator** for the **DigiByte Quantum Immune Shield**.

It does **not** implement the internals of each defensive layer.  
Instead, it:

- wires together all shield components  
- defines clean interfaces and bridges between them  
- runs **pipelines** that move signals, decisions, and context  
- provides a **test harness** for running end-to-end defence scenarios  

Think of it as the **central nervous system wiring**, not the individual organs.

---

## 🛡️ The Shield Stack (High-Level)

The full Quantum Immune Shield consists of:

- **DQSN v2** — DigiByte Quantum Shield Network (Layer-0 telemetry, entropy, health)  
- **Sentinel AI v2** — network anomaly detection and threat scoring  
- **ADN v2** — Active Defence Network (tactical responses and playbooks)  
- **QWG** — Quantum Wallet Guard (runtime transaction defence, PQC verification)  
- **Guardian Wallet** — user protection & secure UX layer  
- **Adaptive Core v2** — learning, fusion, and adaptive shield sensitivity  

This orchestrator repo is the **hub** that connects all of them.

---

## 🧬 Orchestrator Role

The orchestrator:

- consumes outputs from each shield layer  
- passes relevant context to the next layer  
- coordinates timing and sequencing of actions  
- provides a unified **ShieldContext** object used throughout the pipeline  
- exposes a structure that DigiByte developers can extend, test, and integrate into tooling

It is strictly:

- **external to consensus**  
- **external to node validation rules**  
- **focused on coordination, not authority**

---

## 🧱 Repository Layout

Top-level:

```text
.github/workflows/        # CI pipeline
docs/                     # architecture, security model, interfaces, FAQ
src/shield_orchestrator/  # orchestrator implementation
tests/                    # end-to-end and integration tests
LICENSE
README.md
```

Core orchestrator package:

```text
src/shield_orchestrator/
  bridges/
    base_layer.py
    dqsn_bridge.py
    sentinel_bridge.py
    adn_bridge.py
    qwg_bridge.py
    guardian_wallet_bridge.py
    adaptive_core_bridge.py
  config.py
  context.py
  pipeline.py
  __init__.py
```

---

## 🔗 Bridges — Connecting Each Layer

Bridges are lightweight adapters that translate between **each shield component** and the shared
`ShieldContext`.

Examples:

- `dqsn_bridge.py` — imports DQSN health metrics into the orchestrator context  
- `sentinel_bridge.py` — injects anomaly scores and threat classifications  
- `adn_bridge.py` — retrieves playbook outputs and tactical suggestions  
- `qwg_bridge.py` — brings in wallet-side behavioural and PQC signals  
- `guardian_wallet_bridge.py` — connects user-facing warnings and actions  
- `adaptive_core_bridge.py` — shares learned patterns and sensitivity levels  

All bridges inherit from `base_layer.py`, which defines common behaviour and contracts.

---

## 🔁 Pipeline & Context

At the heart of this repo are two modules:

### `context.py`
Defines the **ShieldContext**, a structured object holding:

- current network health view  
- active threat signals  
- active defence decisions  
- wallet-side alerts  
- user interactions  
- adaptive parameters from Adaptive Core  

ShieldContext is serialisable, traceable, and suitable for logging.

### `pipeline.py`
Defines a high-level orchestration pipeline, such as:

1. Ingest DQSN metrics  
2. Pass into Sentinel AI v2  
3. Forward threat vectors to ADN v2  
4. Route defence outputs to QWG  
5. Present user messages via Guardian Wallet  
6. Feed final outcomes into Adaptive Core for learning  

Developers can run this pipeline in:

- **testnet simulation mode**  
- **integration mode** (with actual components)  
- **future production wiring**

---

## 📚 Documentation

This repo ships detailed documents under `docs/`:

- `Shield_Architecture_v2.md` — overall shield design  
- `Layer_Interfaces_v2.md` — contracts between layers  
- `SECURITY_MODEL_v2.md` — security assumptions & threat model  
- `Shield_Orchestrator_Design_v2.md` — orchestration internals  
- `Shield_Testnet_Bundle_Guide_v2.md` — how to wire everything on a testnet  
- `FAQ.md` — common questions  

For deep technical understanding, start with:

1. `docs/Shield_Architecture_v2.md`  
2. `docs/Shield_Orchestrator_Design_v2.md`  
3. `docs/Layer_Interfaces_v2.md`

---

## 🧪 Tests & CI

The orchestrator includes:

- **GitHub Actions CI** (`.github/workflows/ci.yml`)  
- tests under `tests/`, e.g. `test_full_pipeline_basic.py`  

These validate that:

- bridges can be imported and instantiated  
- the main pipeline runs with mocked shield components  
- context creation and propagation behave as expected  

More end-to-end scenarios can be added to simulate complex attack + defence flows.

---

## 🛡️ Security & Design Principles

1. **Consensus-Neutral**  
   The orchestrator never votes, validates blocks, or touches consensus.

2. **Separation of Concerns**  
   Actual analytics / defence logic remain in their respective repos.

3. **Explicit Interfaces**  
   Bridges use well-documented, versioned contracts between components.

4. **Deterministic Execution**  
   Same inputs → same pipeline outputs (given the same component versions).

5. **Observability**  
   Every step is loggable and traceable via context.

6. **Extensibility**  
   New layers or tools can be added by registering additional bridges or pipeline stages.

---

## 🤝 Contributing

See `CONTRIBUTING.md` for detailed contribution guidelines.

In summary:

- improvements to bridges, pipelines, tests, and docs are welcome  
- do not move shield logic into this repo  
- do not introduce consensus or wallet logic  
- keep orchestration behaviour deterministic and auditable  

---

## 📜 License

MIT License  
© 2025 **DarekDGB**

This architecture is free to use with mandatory attribution.
