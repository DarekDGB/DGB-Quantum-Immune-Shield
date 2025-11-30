# src/shield_orchestrator/bridges/adn_bridge.py

from __future__ import annotations

from typing import Any, Dict

from .base_layer import BaseLayerBridge, LayerResult
from ..context import ShieldContext


class ADNBridge(BaseLayerBridge):
    name = "adn"

    def process(self, event: Dict[str, Any], context: ShieldContext) -> LayerResult:
        base = float(event.get("node_risk", 0.20))
        score = max(0.0, min(1.0, base))
        return LayerResult(self.name, score, {"source": "adn", "raw": base})
