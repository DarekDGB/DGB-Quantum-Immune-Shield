from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ShieldConfig:
    """
    High-level configuration for the Quantum Immune Shield orchestrator.

    For now this is simple and local. In the future it can hold:
    - RPC endpoints
    - node / wallet connection info
    - feature flags per layer
    """

    enable_sentinel: bool = True
    enable_dqsn: bool = True
    enable_adn: bool = True
    enable_guardian_wallet: bool = True
    enable_qwg: bool = True
    enable_adaptive_core: bool = True

    version: str = "v2"

    @classmethod
    def default(cls) -> "ShieldConfig":
        """Return the default config used by FullShieldPipeline.from_default_config()."""
        return cls()
