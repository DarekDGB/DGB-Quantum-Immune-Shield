# src/shield_orchestrator/config.py

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ShieldConfig:
    """Very small config stub for now.

    This keeps room for future options (testnet URLs, logging, etc.).
    """

    name: str = "DigiByte Quantum Immune Shield v2"

    @classmethod
    def default(cls) -> "ShieldConfig":
        return cls()
