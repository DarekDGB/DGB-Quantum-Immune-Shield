from __future__ import annotations

from typing import Any, Dict

from .base_layer import BaseLayer, LayerResult
from ..context import ShieldContext


class ADNLayer(BaseLayer):
    """
    Bridge for Autonomous Defense Node (ADN v2).

    It reacts to escalating risk by modelling local node reflex behaviour.
    """

    def __init__(self, weight: float = 1.0) -> None:
        super().__init__("adn_v2")
        self.weight = weight

    def process(self, event: Dict[str, Any], context: ShieldContext) -> LayerResult:
        local_anomaly = float(event.get("local_anomaly", 0.0))
        lockdown_triggered = bool(event.get("lockdown_triggered", False))

        base_score = local_anomaly
        if lockdown_triggered:
            base_score = max(base_score, 0.9)

        score = max(0.0, min(1.0, base_score * self.weight))

        context.log(f"[ADN] local_anomaly={local_anomaly}, "
                    f"lockdown={lockdown_triggered}, score={score:.3f}")

        return LayerResult(
            name=self.name,
            risk_score=score,
            details={
                "local_anomaly": local_anomaly,
                "lockdown_triggered": lockdown_triggered,
            },
        )
