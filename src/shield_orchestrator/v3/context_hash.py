from __future__ import annotations

import hashlib
from typing import Any

from .canonical_json import to_canonical_json


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_context_hash(material: Any) -> str:
    """
    Compute deterministic context_hash for Orchestrator v3.

    The hash is derived exclusively from canonical JSON of
    contract-defined material (no hidden inputs).
    """
    canonical = to_canonical_json(material)
    return _sha256_hex(canonical)
