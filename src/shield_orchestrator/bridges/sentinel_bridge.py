from __future__ import annotations

from typing import Any, Dict

from .base_layer import ShieldLayer, ShieldEvent, LayerResult
from ..context import ShieldContext


class SentinelBridge(ShieldLayer):
    """
    Lightweight bridge for Sentinel AI v2.

    In this bundle we don't talk to a real node yet; instead we
    simulate a simple "entropy-based" severity using the payload.
    """

    def __init__(self) -> None:
        super().__init__(name="sentinel_v2")

    def process(self, event: ShieldEvent, ctx: ShieldContext) -> LayerResult:
        payload: Dict[str, Any] = event.payload
        entropy_drop = float(payload.get("entropy_drop", 0.0))

        severity = max(0.0, min(entropy_drop, 1.0))
        level = "LOW"
        if severity > 0.75:
            level = "CRITICAL"
        elif severity > 0.5:
            level = "HIGH"
        elif severity > 0.25:
            level = "ELEVATED"

        return LayerResult(
            layer=self.name,
            severity=severity,
            level=level,
            notes="Simulated Sentinel entropy signal.",
            metadata={"entropy_drop": entropy_drop},
        )
