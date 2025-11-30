# src/shield_orchestrator/bridges/qwg_bridge.py

from __future__ import annotations

from typing import Any, Dict

from .base_layer import BaseLayerBridge, LayerResult
from ..context import ShieldContext


class QWGBridge(BaseLayerBridge):
    name = "qwg"

    def process(self, event: Dict[str, Any], context: ShieldContext) -> LayerResult:
        # Quantum-style risk – defaults a bit higher when quantum flags appear.
        base = float(event.get("quantum_risk", 0.30))
        if event.get("quantum_flag"):
            base = min(1.0, base + 0.20)

        score = max(0.0, min(1.0, base))
        return LayerResult(
            self.name,
            score,
            {"source": "qwg", "raw": base, "quantum_flag": event.get("quantum_flag")},
        )
