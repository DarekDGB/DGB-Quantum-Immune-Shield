#!/usr/bin/env python3
"""Pinned Shield v4 V4.10-C verification and rejection benchmark."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import statistics
import sys
import time
from importlib.metadata import version
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from shield_orchestrator.v4.key_registry import (  # noqa: E402
    KeyRegistryEntry,
    load_key_registry,
)
from shield_orchestrator.v4.verification_audit import (  # noqa: E402
    AUDIT_APPEND_ACK_SCHEMA_VERSION,
    V4_CONTRACT_INVALID,
    ShieldV4VerificationError,
    audit_batch_sha256,
    verify_v4_receipt_with_audit,
)

SCHEMA_VERSION = "shield-v4-v410c-performance-v1"
REPOSITORY = "DGB-Quantum-Shield-Orchestrator"
FIXTURE_PATH = ROOT / "tests/fixtures/v4/full_multi_repo_v4_allow_flow.json"
FIXTURE_SHA256 = "279f69dce971d5695ff2ac61f3aca5921e9cd936e059405e79ece38824899ce9"
WARMUPS = 20
SAMPLES = 200
VALID_P95_LIMIT_MS = 50.0
OVERSIZE_REJECTION_P95_LIMIT_MS = 20.0
PINNED_PACKAGES = (
    "pip",
    "setuptools",
    "wheel",
    "pytest",
    "pytest-cov",
)


class _AcknowledgingSink:
    def append_batch(self, records: tuple[bytes, ...]) -> dict[str, Any]:
        return {
            "schema_version": AUDIT_APPEND_ACK_SCHEMA_VERSION,
            "batch_sha256": audit_batch_sha256(records),
            "record_count": len(records),
            "durably_committed": True,
        }


def _transport_hash(receipt: dict[str, Any]) -> str:
    encoded = json.dumps(
        receipt,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _allow(_entry: dict[str, Any], _key: KeyRegistryEntry) -> bool:
    return True


def _measure(operation: Callable[[], None]) -> list[float]:
    for _ in range(WARMUPS):
        operation()
    samples: list[float] = []
    for _ in range(SAMPLES):
        started = time.perf_counter_ns()
        operation()
        samples.append((time.perf_counter_ns() - started) / 1_000_000)
    return samples


def _p95(samples: list[float]) -> float:
    ordered = sorted(samples)
    return ordered[((95 * len(ordered) + 99) // 100) - 1]


def _summary(samples: list[float], *, limit_ms: float) -> dict[str, float]:
    return {
        "median_ms": round(statistics.median(samples), 6),
        "p95_ms": round(_p95(samples), 6),
        "limit_ms": limit_ms,
    }


def main() -> int:
    fixture_bytes = FIXTURE_PATH.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    if fixture_sha256 != FIXTURE_SHA256:
        raise SystemExit("V4.10-C benchmark fixture hash mismatch")
    fixture = json.loads(fixture_bytes.decode("utf-8"))
    receipt = fixture["receipt"]
    registry = load_key_registry(fixture["trusted_key_registry"])
    transport_hash = _transport_hash(receipt)

    oversize_receipt = copy.deepcopy(receipt)
    oversize_receipt["component_verdicts"][0]["metadata"]["oversize"] = "x" * 8_193
    oversize_transport_hash = _transport_hash(oversize_receipt)

    def valid_operation() -> None:
        verify_v4_receipt_with_audit(
            receipt,
            artifact_transport_hash=transport_hash,
            expected_context_hash=fixture["expected_context_hash"],
            expected_request_id=fixture["expected_request_id"],
            registry=registry,
            minimum_registry_version=1,
            verification_time=fixture["verification_time"],
            component_verifier=_allow,
            receipt_verifier=_allow,
            audit_sink=_AcknowledgingSink(),
        )

    def oversize_rejection_operation() -> None:
        try:
            verify_v4_receipt_with_audit(
                oversize_receipt,
                artifact_transport_hash=oversize_transport_hash,
                expected_context_hash=fixture["expected_context_hash"],
                expected_request_id=fixture["expected_request_id"],
                registry=registry,
                minimum_registry_version=1,
                verification_time=fixture["verification_time"],
                component_verifier=_allow,
                receipt_verifier=_allow,
                audit_sink=_AcknowledgingSink(),
            )
        except ShieldV4VerificationError as error:
            if error.reason_id == V4_CONTRACT_INVALID:
                return
        raise AssertionError("oversize fixture did not fail as V4_CONTRACT_INVALID")

    valid = _summary(_measure(valid_operation), limit_ms=VALID_P95_LIMIT_MS)
    oversize_rejection = _summary(
        _measure(oversize_rejection_operation),
        limit_ms=OVERSIZE_REJECTION_P95_LIMIT_MS,
    )
    passed = (
        valid["p95_ms"] <= valid["limit_ms"]
        and oversize_rejection["p95_ms"] <= oversize_rejection["limit_ms"]
    )
    result = {
        "schema_version": SCHEMA_VERSION,
        "repository": REPOSITORY,
        "fixture_sha256": fixture_sha256,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "pythonhashseed": os.environ.get("PYTHONHASHSEED", ""),
            "tz": os.environ.get("TZ", ""),
            "lc_all": os.environ.get("LC_ALL", ""),
        },
        "packages": {package: version(package) for package in PINNED_PACKAGES},
        "warmups": WARMUPS,
        "samples": SAMPLES,
        "valid": valid,
        "oversize_rejection": oversize_rejection,
        "status": "PASS" if passed else "FAIL",
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
