# DigiByte Quantum Shield Orchestrator v3.2.0 Reason IDs

Author attribution: DarekDGB

This historical document defines the frozen v3.2.0 Orchestrator reason-ID
registry. The immutable `v3.2.0` tag already exists at commit
`5290124cd0d4938543f588d48bcd47fe0ba035ca`.

The Orchestrator is the only Shield receipt boundary for AdamantineOS handoff.

Rules:

- reason IDs are stable;
- unknown reason IDs fail closed;
- component reason IDs are checked against the component registry;
- Orchestrator reason IDs are deterministic;
- raw component outputs are evidence only; and
- Shield `ALLOW` is not final AdamantineOS execution authority.

## Orchestrator reason IDs

| Reason ID | Meaning |
|---|---|
| `ORCH_OK_ALL_COMPONENTS_ALLOW` | All required Shield component verdicts allow the handoff to continue. |
| `ORCH_HUMAN_REVIEW_ESCALATE_PRESENT` | One or more component verdicts require escalation or human review. |
| `ORCH_DENY_DOMINATES` | At least one component verdict denies; the final Shield outcome is deny. |
| `ORCH_ERROR_MISSING_REQUIRED_VERDICT` | A required component verdict is missing. |
| `ORCH_ERROR_DUPLICATED_COMPONENT_VERDICT` | More than one verdict was supplied for the same component. |
| `ORCH_ERROR_CONTEXT_HASH_MISMATCH` | Verdict or receipt context does not match the expected context. |
| `ORCH_ERROR_INVALID_COMPONENT_VERDICT` | A component verdict is malformed, unsupported, or inconsistent. |
| `ORCH_ERROR_RECEIPT_TAMPERED` | Receipt hash or canonical content does not validate. |
| `ORCH_ERROR_REPLAY_DETECTED` | Replay protection detected reused or invalid context evidence. |
| `SHIELD_ERROR_AI_AUTHORITY_BYPASS_ATTEMPT` | AI output attempted to act as authority instead of evidence. |
| `SHIELD_ERROR_HUMAN_APPROVAL_CONTEXT_MISMATCH` | Human approval context does not match the exact Shield context. |

## Component reason-ID registry

### Guardian Wallet

- `GW_OK_HEALTHY_ALLOW`
- `GW_ESCALATE_QID_REQUIRED`
- `GW_DENY_POLICY_BLOCKED`
- `GW_ERROR_INVALID_VERDICT`
- `GW_ERROR_CONTEXT_HASH_MISMATCH`

### ADN

- `ADN_OK_COORDINATION_ALLOW`
- `ADN_ESCALATE_POLICY_REVIEW`
- `ADN_DENY_DEFENSE_TRIGGERED`
- `ADN_ERROR_INVALID_VERDICT`
- `ADN_ERROR_CONTEXT_HASH_MISMATCH`

### Sentinel AI

- `SNTL_OK_TELEMETRY_ALLOW`
- `SNTL_ESCALATE_THREAT_REVIEW`
- `SNTL_DENY_THREAT_DETECTED`
- `SNTL_ERROR_AI_OUTPUT_UNTRUSTED`
- `SNTL_ERROR_CONTEXT_HASH_MISMATCH`

### DQSN

- `DQSN_OK_NETWORK_ALLOW`
- `DQSN_ESCALATE_QUANTUM_SIGNAL`
- `DQSN_DENY_NETWORK_RISK`
- `DQSN_ERROR_INVALID_VERDICT`
- `DQSN_ERROR_CONTEXT_HASH_MISMATCH`

### QWG

- `QWG_OK_POSTURE_ALLOW`
- `QWG_ESCALATE_QUANTUM_POSTURE`
- `QWG_DENY_KEY_RISK`
- `QWG_ERROR_INVALID_VERDICT`
- `QWG_ERROR_CONTEXT_HASH_MISMATCH`

## Fail-closed rule

Unknown component reason IDs reject before receipt construction. Unknown
Orchestrator reason IDs reject before AdamantineOS handoff.

The historical tag was permitted only after code, tests, and this registry
agreed. That completed gate is preserved as release history; it is not pending
and does not change the parallel v4 reason and audit contracts.
