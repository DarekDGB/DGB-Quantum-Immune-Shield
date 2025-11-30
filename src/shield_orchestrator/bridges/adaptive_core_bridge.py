# src/shield_orchestrator/bridges/adaptive_core_bridge.py

from __future__ import annotations

from typing import Any, Dict, List

from .base_layer import BaseLayerBridge, LayerResult
from ..context import ShieldContext


class AdaptiveCoreBridge(BaseLayerBridge):
    name = "adaptive_core"

    def process(self, event: Dict[str, Any], context: ShieldContext) -> LayerResult:
        """Very small simulation of immune behaviour.

        - Looks at any *_risk fields on the event
        - Computes an aggregate
        - Slightly boosts the risk if multiple layers are high
        """
        risk_fields: List[float] = []
        for key, value in event.items():
            if key.endswith("_risk"):
                try:
                    risk_fields.append(float(value))
                except (TypeError, ValueError):
                    continue

        if not risk_fields:
            base = float(event.get("immune_risk", 0.35))
        else:
            avg = sum(risk_fields) / len(risk_fields)
            # If many layers are high, immune system responds stronger
            base = min(1.0, avg + 0.10)

        score = max(0.0, min(1.0, base))
        return LayerResult(
            self.name,
            score,
            {"source": "adaptive_core", "raw": base, "observed_layers": len(risk_fields)},
        )
