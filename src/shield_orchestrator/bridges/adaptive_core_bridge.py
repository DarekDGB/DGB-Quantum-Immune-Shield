from __future__ import annotations

from typing import Any, Dict

from .base_layer import ShieldLayer, ShieldEvent, LayerResult
from ..context import ShieldContext


class AdaptiveCoreBridge(ShieldLayer):
    """
    Bridge for Adaptive Core v2.

    In this bundle we simulate a Network Immune Score (NIS) returned
    from previous learning cycles.
    """

    def __init__(self) -> None:
        super().__init__(name="adaptive_core_v2")

    def process(self, event: ShieldEvent, ctx: ShieldContext) -> LayerResult:
        p: Dict[str, Any] = event.payload
        nis = float(p.get("network_immune_score", 0.0))

        # Higher NIS means the immune system is *already* suspicious.
        severity = max(0.0, min(nis, 1.0))
        level = "LOW"
        if severity > 0.75:
            level = "CRITICAL"
        elif severity > 0.55:
            level = "HIGH"
        elif severity > 0.3:
            level = "ELEVATED"

        return LayerResult(
            layer=self.name,
            severity=severity,
            level=level,
            notes="Simulated Adaptive Core network immune score.",
            metadata={"network_immune_score": nis},
        )
