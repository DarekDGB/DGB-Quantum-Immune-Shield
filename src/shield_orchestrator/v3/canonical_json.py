from __future__ import annotations

import json
from typing import Any


def to_canonical_json(obj: Any) -> str:
    """
    Deterministic JSON serialization for hashing/audit.

    - sort_keys=True
    - stable separators (no whitespace)
    - ensure_ascii=False (UTF-8)
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
