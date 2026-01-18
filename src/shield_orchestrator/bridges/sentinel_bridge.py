from __future__ import annotations

from dataclasses import asdict

from .base_layer import BaseLayer
from shield_orchestrator.v3.context_hash import compute_context_hash
from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request, TraceEntry


class SentinelBridge(BaseLayer):
    """
    Sentinel bridge (integration adapter).

    - Keeps legacy BaseLayer.process() behavior for pipeline.py (v2 testnet flow).
    - Adds a v3-facing method that emits a deterministic TraceEntry
      which Orchestrator v3 can aggregate.

    NOTE (Phase 3 in-progress):
    This is a stub adapter that does not yet call an external Sentinel AI v3 service/repo.
    It is intentionally deterministic and fail-closed-ready.
    """

    COMPONENT = "sentinel_ai"
    STAGE = "sentinel_ai"

    def evaluate_v3(self, request: OrchestratorV3Request) -> TraceEntry:
        """
        Evaluate Sentinel AI for a v3 orchestrator request.

        Returns a deterministic TraceEntry. In Phase 3, this will be replaced
        with a real call + strict validation of Sentinel AI v3 output.
        """
        # Deterministic per-component context hash (no hidden inputs).
        component_context_hash = compute_context_hash(
            {
                "component": self.COMPONENT,
                "request": asdict(request),
            }
        )

        return TraceEntry(
            stage=self.STAGE,
            component=self.COMPONENT,
            status="OK",
            reason_ids=(),
            component_context_hash=component_context_hash,
            notes="phase3_bridge_stub",
        )
