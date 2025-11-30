from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .config import ShieldConfig
from .context import ShieldContext
from .bridges.base_layer import ShieldEvent, LayerResult, ShieldLayer
from .bridges.sentinel_bridge import SentinelBridge
from .bridges.dqsn_bridge import DQSNBridge
from .bridges.adn_bridge import ADNBridge
from .bridges.guardian_wallet_bridge import GuardianWalletBridge
from .bridges.qwg_bridge import QWGBridge
from .bridges.adaptive_core_bridge import AdaptiveCoreBridge


@dataclass
class ShieldOutcome:
    """Final combined result from the full shield pipeline."""

    context: ShieldContext
    trace: List[LayerResult]
    final_risk_level: str
    max_severity: float


class FullShieldPipeline:
    """
    Run an event through all six layers and aggregate risk.

    This orchestrator uses simple, deterministic logic so it can be
    safely executed in tests and on DigiByte testnet later.
    """

    def __init__(self, config: ShieldConfig, layers: List[ShieldLayer]) -> None:
        self.config = config
        self.layers = layers

    @classmethod
    def from_default_config(cls) -> "FullShieldPipeline":
        cfg = ShieldConfig.default()
        layers: List[ShieldLayer] = []

        if cfg.enable_sentinel:
            layers.append(SentinelBridge())
        if cfg.enable_dqsn:
            layers.append(DQSNBridge())
        if cfg.enable_adn:
            layers.append(ADNBridge())
        if cfg.enable_guardian_wallet:
            layers.append(GuardianWalletBridge())
        if cfg.enable_qwg:
            layers.append(QWGBridge())
        if cfg.enable_adaptive_core:
            layers.append(AdaptiveCoreBridge())

        return cls(config=cfg, layers=layers)

    def process_event(
        self,
        payload: Dict[str, Any],
        *,
        ctx: ShieldContext | None = None,
    ) -> ShieldOutcome:
        """
        Run a single event through all enabled layers.

        payload – arbitrary dict with fields understood by the bridges.
        """
        context = ctx or ShieldContext()
        event = ShieldEvent(payload=dict(payload))  # shallow copy

        trace: List[LayerResult] = []

        for layer in self.layers:
            result = layer.process(event, context)
            trace.append(result)

        max_severity = max((r.severity for r in trace), default=0.0)
        final_level = self._severity_to_level(max_severity)

        return ShieldOutcome(
            context=context,
            trace=trace,
            final_risk_level=final_level,
            max_severity=max_severity,
        )

    @staticmethod
    def _severity_to_level(severity: float) -> str:
        if severity > 0.85:
            return "CRITICAL"
        if severity > 0.65:
            return "HIGH"
        if severity > 0.35:
            return "ELEVATED"
        return "LOW"
