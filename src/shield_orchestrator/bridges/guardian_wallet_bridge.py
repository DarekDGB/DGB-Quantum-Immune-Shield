# src/shield_orchestrator/bridges/guardian_wallet_bridge.py

from __future__ import annotations

from typing import Any, Dict

from .base_layer import BaseLayerBridge, LayerResult
from ..context import ShieldContext


class GuardianWalletBridge(BaseLayerBridge):
    name = "guardian_wallet"

    def process(self, event: Dict[str, Any], context: ShieldContext) -> LayerResult:
        # Wallet risk gets slightly higher weight if amount is large.
        base = float(event.get("wallet_risk", 0.25))
        amount = float(event.get("amount_dgb", 0.0))
        if amount > 100_000:
            base = min(1.0, base + 0.15)

        score = max(0.0, min(1.0, base))
        return LayerResult(
            self.name,
            score,
            {"source": "guardian_wallet", "raw": base, "amount_dgb": amount},
        )
