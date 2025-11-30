from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class LayerResult:
    """Normalized result for a single shield layer."""
    name: str
    risk_score: float  # 0.0 – 1.0
    details: Dict[str, Any]


class BaseLayer:
    """Common interface for all shield layers."""

    def __init__(self, name: str) -> None:
        self.name = name

    def process(self, event: Dict[str, Any], context: "ShieldContext") -> LayerResult:
        """
        Process a generic event and return a normalized LayerResult.

        Concrete subclasses MUST override this method.
        """
        raise NotImplementedError(f"{self.__class__.__name__}.process() not implemented")
