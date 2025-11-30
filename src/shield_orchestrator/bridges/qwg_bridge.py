from __future__ import annotations

from typing import Any, Dict

from .base_layer import BaseLayer, LayerResult
from ..context import ShieldContext


class QWGLayer(BaseLayer):
    """
    Bridge for Quantum Wallet Guard (QWG v2).

    It turns quantum-style signature / key pattern hints into a risk score.
    """

    def __init__(self, weight: float = 1.0) -> None:
        super().__init__("qwg_v2")
        self.weight = weight

    def process(self, event: Dict[str, Any], context: ShieldContext) -> LayerResult:
        quantum_hint = float(event.get("quantum_hint", 0.0))
        key_reuse = bool(event.get("key_reuse_detected", False))

        base_score = quantum_hint
        if key_reuse:
            base_score = max(base_score, 0.8)

        score = max(0.0, min(1.0, base_score * self.weight))

        context.log(f"[QWG] quantum_hint={quantum_hint}, key_reuse={key_reuse}, "
                    f"score={score:.3f}")

        return LayerResult(
            name=self.name,
            risk_score=score,
            details={
                "quantum_hint": quantum_hint,
                "key_reuse_detected": key_reuse,
            },
        )
