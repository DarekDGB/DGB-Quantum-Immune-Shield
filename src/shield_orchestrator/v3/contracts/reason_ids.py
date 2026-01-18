from __future__ import annotations

from enum import Enum


class ReasonId(str, Enum):
    """
    Orchestrator v3 reason identifiers.

    No magic strings are allowed outside this registry.
    Ordering and semantics are contract-locked by docs/v3/REASON_IDS.md.
    """

    INVALID_CONTRACT_VERSION = "INVALID_CONTRACT_VERSION"
    INVALID_REQUEST = "INVALID_REQUEST"
    HASHING_FAILED = "HASHING_FAILED"

    COMPONENT_ERROR = "COMPONENT_ERROR"
    COMPONENT_INVALID_RESPONSE = "COMPONENT_INVALID_RESPONSE"
    COMPONENT_MISSING = "COMPONENT_MISSING"

    DENY_BY_POLICY = "DENY_BY_POLICY"
    INTERNAL_ERROR = "INTERNAL_ERROR"
