# src/shield_orchestrator/bridges/base_layer.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from ..context import ShieldContext


@dataclass
class LayerResult:
    """Generic result for any layer in the shield."""

    layer_name: str
    risk_score: float
    meta: Dict[str, Any]


class BaseLayerBridge:
    """Base class for all layer bridges in this repo.

    In this orchestrator skeleton, every bridge is a light-weight adapter
    that receives an event dict and returns a LayerResult.  No external
    DigiByte repos are imported here – everything is self-contained so CI passes.
    """

    name: str = "base"

    def process(self, event: Dict[str, Any], context: ShieldContext) -> LayerResult:
        """Default behaviour: echo the event with neutral risk.

        Concrete subclasses override this to implement their own scoring rules.
        """
        return LayerResult(
            layer_name=self.name,
            risk_score=0.0,
            meta={"echo": True, "event_type": event.get("type", "unknown")},
        )
