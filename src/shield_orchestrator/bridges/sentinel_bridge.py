from __future__ import annotations

from typing import Any, Dict

from .base_layer import BaseLayer, LayerResult
from ..context import ShieldContext


class SentinelLayer(BaseLayer):
    """
    Lightweight Sentinel AI v2 bridge.

    It turns entropy / anomaly hints in the event into a 0–1 risk score.
    """

    def __init__(self, weight: float = 1.0) -> None:
        super().__init__("sentinel_ai_v2")
        self.weight = weight

    def process(self, event: Dict[str, Any], context: ShieldContext) -> LayerResult:
        entropy_drop = float(event.get("entropy_drop", 0.0))
        reorg_depth = int(event.get("reorg_depth", 0))

        base_score = max(0.0, min(1.0, entropy_drop + 0.05 * reorg_depth))
        score = max(0.0, min(1.0, base_score * self.weight))

        context.log(f"[Sentinel] entropy_drop={entropy_drop}, reorg_depth={reorg_depth}, "
                    f"score={score:.3f}")

        return LayerResult(
            name=self.name,
            risk_score=score,
            details={
                "entropy_drop": entropy_drop,
                "reorg_depth": reorg_depth,
            },
        )
