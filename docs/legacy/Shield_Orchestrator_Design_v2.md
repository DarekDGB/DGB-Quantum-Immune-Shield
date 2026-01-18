# 🧩 Shield Orchestrator — Design v2

Author: **DarekDGB**  
AI Engineering Assistant: **Angel**  
License: MIT

---

## Purpose

The orchestrator is the “central nervous system” of the DigiByte Quantum Immune Shield.  
It routes packets between layers and manages the order of execution.

---

## Components

### 1. `FullShieldPipeline`
The full execution pipeline for all six layers.

### 2. Bridges
Each bridge file provides a clean interface from the orchestrator to a layer:
- sentinel_bridge.py  
- dqsn_bridge.py  
- adn_bridge.py  
- guardian_wallet_bridge.py  
- qwg_bridge.py  
- adaptive_core_bridge.py  

### 3. Config & Context

- `config.py` stores scoring weights, thresholds.
- `context.py` stores logging, debug and pipeline options.

---

## Packet Types

- SignalPacket  
- NetworkRiskPacket  
- DefenseEvent  
- WalletRiskPacket  
- QuantumRisk  
- ThreatPacket  
- ImmuneResponse  

---

## Execution Model

Each event flows like this:

```
packet = pipeline.process(event)
return packet.final_risk, packet.immune_response
```

