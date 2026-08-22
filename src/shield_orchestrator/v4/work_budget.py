from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shield_orchestrator.v4.canonical_json import to_canonical_json
from shield_orchestrator.v4.crypto_algorithms import (
    CLASSICAL_ED25519,
    FN_DSA,
    ML_DSA,
)

MAX_CANONICAL_RECEIPT_BYTES = 131_072
MAX_SNAPSHOT_SCALAR_BYTES = 131_072
MAX_TEXT_FIELD_BYTES = 8_192
MAX_SIGNATURE_BUNDLE_BYTES = 32_768
MAX_CONTAINER_DEPTH = 16
MAX_CONTAINER_NODES = 4_096
MAX_SIGNED_INTEGER_BITS = 64
EXPECTED_COMPONENT_BUNDLE_COUNT = 5
EXPECTED_RECEIPT_BUNDLE_COUNT = 1
MIN_SIGNATURES_PER_BUNDLE = 2
MAX_SIGNATURES_PER_BUNDLE = 3
MAX_SIGNATURE_BUNDLES = 6
MAX_VERIFICATION_CALLS = 18
MAX_PQC_VERIFICATION_CALLS = 12
MAX_TRUSTED_REGISTRY_ENTRIES = 64

_MIN_SIGNED_INTEGER = -(1 << (MAX_SIGNED_INTEGER_BITS - 1))
_MAX_SIGNED_INTEGER = (1 << (MAX_SIGNED_INTEGER_BITS - 1)) - 1
_SUPPORTED_ALGORITHMS = frozenset({CLASSICAL_ED25519, ML_DSA, FN_DSA})
_PQC_ALGORITHMS = frozenset({ML_DSA, FN_DSA})


class ShieldV4WorkBudgetError(ValueError):
    """Raised before crypto when an untrusted work budget is exceeded."""


@dataclass(frozen=True)
class BoundedJsonSnapshot:
    value: Any
    node_count: int
    scalar_bytes: int


@dataclass
class VerificationWorkCounter:
    verification_calls: int = 0
    pqc_verification_calls: int = 0

    def record_callback_attempt(self, algorithm: str) -> None:
        if algorithm not in _SUPPORTED_ALGORITHMS:
            raise ShieldV4WorkBudgetError("unsupported algorithm in verification plan")
        next_total = self.verification_calls + 1
        next_pqc = self.pqc_verification_calls + (algorithm in _PQC_ALGORITHMS)
        if next_total > MAX_VERIFICATION_CALLS:
            raise ShieldV4WorkBudgetError("verification callback budget exceeded")
        if next_pqc > MAX_PQC_VERIFICATION_CALLS:
            raise ShieldV4WorkBudgetError("PQC verification callback budget exceeded")
        self.verification_calls = next_total
        self.pqc_verification_calls = next_pqc


def require_bounded_text(value: Any, *, field: str, allow_empty: bool = False) -> str:
    if type(value) is not str or (not value and not allow_empty):
        raise ShieldV4WorkBudgetError(f"{field} must be exact non-empty string")
    if len(value) > MAX_TEXT_FIELD_BYTES:
        raise ShieldV4WorkBudgetError(f"{field} exceeds text byte budget")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise ShieldV4WorkBudgetError(f"{field} must be valid UTF-8") from None
    if len(encoded) > MAX_TEXT_FIELD_BYTES:
        raise ShieldV4WorkBudgetError(f"{field} exceeds text byte budget")
    return value


def _snapshot_json(value: Any) -> tuple[Any, int, int]:
    active_containers: set[int] = set()
    node_count = 0
    scalar_bytes = 0

    def add_scalar_bytes(byte_count: int) -> None:
        nonlocal scalar_bytes
        scalar_bytes += byte_count
        if scalar_bytes > MAX_SNAPSHOT_SCALAR_BYTES:
            raise ShieldV4WorkBudgetError("receipt scalar byte snapshot exceeds budget")

    def visit(item: Any, *, depth: int) -> Any:
        nonlocal node_count, scalar_bytes
        if depth > MAX_CONTAINER_DEPTH:
            raise ShieldV4WorkBudgetError("receipt container depth exceeds budget")
        node_count += 1
        if node_count > MAX_CONTAINER_NODES:
            raise ShieldV4WorkBudgetError("receipt container node count exceeds budget")

        if item is None:
            add_scalar_bytes(4)
            return item
        if type(item) is bool:
            add_scalar_bytes(4 if item else 5)
            return item
        if type(item) is int:
            if not _MIN_SIGNED_INTEGER <= item <= _MAX_SIGNED_INTEGER:
                raise ShieldV4WorkBudgetError("receipt integer exceeds signed 64-bit budget")
            add_scalar_bytes(len(str(item).encode("ascii")))
            return item
        if type(item) is str:
            text = require_bounded_text(item, field="receipt string", allow_empty=True)
            add_scalar_bytes(len(text.encode("utf-8")))
            return text
        if type(item) not in {list, dict}:
            raise ShieldV4WorkBudgetError("receipt must contain exact JSON value types")

        identity = id(item)
        if identity in active_containers:
            raise ShieldV4WorkBudgetError("receipt JSON graph must be acyclic")
        active_containers.add(identity)
        try:
            if type(item) is list:
                return [visit(child, depth=depth + 1) for child in item]
            snapshot: dict[str, Any] = {}
            for key, child in dict.items(item):
                checked_key = require_bounded_text(
                    key,
                    field="receipt object key",
                    allow_empty=True,
                )
                add_scalar_bytes(len(checked_key.encode("utf-8")))
                snapshot[checked_key] = visit(child, depth=depth + 1)
            return snapshot
        finally:
            active_containers.remove(identity)

    return visit(value, depth=1), node_count, scalar_bytes


def snapshot_bounded_receipt(receipt: Any) -> BoundedJsonSnapshot:
    value, node_count, scalar_bytes = _snapshot_json(receipt)
    if type(value) is not dict:
        raise ShieldV4WorkBudgetError("receipt must be exact dict")
    return BoundedJsonSnapshot(
        value=value,
        node_count=node_count,
        scalar_bytes=scalar_bytes,
    )


def require_canonical_receipt_budget(receipt: dict[str, Any]) -> int:
    canonical_bytes = len(to_canonical_json(receipt).encode("utf-8"))
    if canonical_bytes > MAX_CANONICAL_RECEIPT_BYTES:
        raise ShieldV4WorkBudgetError("canonical receipt exceeds byte budget")
    return canonical_bytes


def require_signature_bundle_budget(bundle: Any) -> dict[str, Any]:
    if type(bundle) is not dict:
        raise ShieldV4WorkBudgetError("signature bundle must be exact dict")
    signatures = bundle.get("signatures")
    if type(signatures) is not list or not (
        MIN_SIGNATURES_PER_BUNDLE <= len(signatures) <= MAX_SIGNATURES_PER_BUNDLE
    ):
        raise ShieldV4WorkBudgetError("signature bundle count exceeds work budget")
    return bundle


def require_canonical_signature_bundle_budget(bundle: dict[str, Any]) -> int:
    canonical_bytes = len(to_canonical_json(bundle).encode("utf-8"))
    if canonical_bytes > MAX_SIGNATURE_BUNDLE_BYTES:
        raise ShieldV4WorkBudgetError("signature bundle exceeds canonical byte budget")
    return canonical_bytes


def require_complete_bundle_count(*, component_count: int, receipt_count: int) -> None:
    if type(component_count) is not int or type(receipt_count) is not int:
        raise ShieldV4WorkBudgetError("signature bundle counts must be exact integers")
    if component_count != EXPECTED_COMPONENT_BUNDLE_COUNT:
        raise ShieldV4WorkBudgetError("complete chain must contain five component bundles")
    if receipt_count != EXPECTED_RECEIPT_BUNDLE_COUNT:
        raise ShieldV4WorkBudgetError("complete chain must contain one receipt bundle")
def require_planned_call_budget(algorithms: tuple[str, ...]) -> None:
    if type(algorithms) is not tuple or any(type(item) is not str for item in algorithms):
        raise ShieldV4WorkBudgetError("verification plan algorithms must be exact tuple")
    if len(algorithms) > MAX_VERIFICATION_CALLS:
        raise ShieldV4WorkBudgetError("verification plan exceeds callback budget")
    if sum(algorithm in _PQC_ALGORITHMS for algorithm in algorithms) > (
        MAX_PQC_VERIFICATION_CALLS
    ):
        raise ShieldV4WorkBudgetError("verification plan exceeds PQC callback budget")
    if any(algorithm not in _SUPPORTED_ALGORITHMS for algorithm in algorithms):
        raise ShieldV4WorkBudgetError("verification plan contains unsupported algorithm")
