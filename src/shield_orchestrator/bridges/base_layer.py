from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List

from ..context import ShieldContext


@dataclass
class ShieldEvent:
    """Generic event flowing through the shield."""

    payload: Dict[str, Any]


@dataclass
class LayerResult:
    """
    Result produced by a single layer.

    severity: 0.0–1.0  (local view of risk)
    level: LOW / ELEVATED / HIGH / CRITICAL
    notes: free-form diagnostic info
    """

    layer: str
    severity: float
    level: str
    notes: str
    metadata: Dict[str, Any]


class ShieldLayer(ABC):
    """Abstract base class for all layer bridges."""

    name: str

    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def process(self, event: ShieldEvent, ctx: ShieldContext) -> LayerResult:
        """Process an event and return this layer's risk viewpoint."""
        raise NotImplementedError
