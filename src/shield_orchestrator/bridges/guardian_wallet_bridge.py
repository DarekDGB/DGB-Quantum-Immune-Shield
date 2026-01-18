from __future__ import annotations

from dataclasses import asdict

from .base_layer import BaseLayer
from shield_orchestrator.v3.context_hash import compute_context_hash
from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request, TraceEntry


class GuardianWalletBridge(BaseLayer):
    """
    Guardian Wallet bridge (last enforcement gate before QWG).

    - Preserves legacy BaseLayer.process() behavior for pipeline.py.
    - Adds a v3-facing evaluation method emitting a deterministic TraceEntry
      for Orchestrator v3 aggregation.

    NOTE (Phase 3 in-progress):
    This is a deterministic stub. Real Guardian Wallet v3 integration
    will replace internals while keeping this contract stable.
    """

    COMPONENT = "guardian_wallet"
    STAGE = "guardian_wallet"

    def evaluate_v3(self, request: OrchestratorV3Request) -> TraceEntry:
        """
        Evaluate Guardian Wallet for a v3 orchestrator request.

        Returns a deterministic TraceEntry suitable for aggregation.
        """
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
