from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from .reason_ids import ReasonId
from .version import CONTRACT_VERSION


Outcome = Literal["ALLOW", "ESCALATE", "DENY"]
TraceStatus = Literal["OK", "DENY", "ERROR", "SKIPPED"]


@dataclass(frozen=True)
class TraceEntry:
    stage: str
    component: str
    status: TraceStatus
    reason_ids: tuple[str, ...] = ()
    component_context_hash: str | None = None
    notes: str | None = None


@dataclass(frozen=True)
class OrchestratorV3Request:
    contract_version: int
    wallet_id: str
    action: str
    nonce: str
    ttl_seconds: int

    # Optional opaque payload, but MUST be treated as data (deterministic).
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OrchestratorV3Response:
    contract_version: int
    context_hash: str
    outcome: Outcome
    reason_ids: tuple[str, ...]
    trace: tuple[TraceEntry, ...]

    @staticmethod
    def deny(context_hash: str, reason_ids: tuple[str, ...], trace: tuple[TraceEntry, ...]) -> "OrchestratorV3Response":
        return OrchestratorV3Response(
            contract_version=CONTRACT_VERSION,
            context_hash=context_hash,
            outcome="DENY",
            reason_ids=reason_ids,
            trace=trace,
        )
