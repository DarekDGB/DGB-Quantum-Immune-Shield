from __future__ import annotations

import hashlib
import hmac
import json
import unicodedata
from dataclasses import dataclass
from typing import Any, Protocol, TypeAlias

from shield_orchestrator.v4 import (
    CANONICALIZATION_PROFILE,
    KEY_REGISTRY_SCHEMA_VERSION,
    POLICY_VERSION,
    RECEIPT_SCHEMA_VERSION,
    VERDICT_SCHEMA_VERSION,
)
from shield_orchestrator.v4.canonical_json import (
    COMPONENT_VERDICT_DOMAIN,
    ORCHESTRATOR_RECEIPT_DOMAIN,
    signed_payload_hash,
    to_canonical_json,
)
from shield_orchestrator.v4.component_verdicts import (
    COMPONENT_ROLES,
    SUPPORTED_COMPONENTS,
    unsigned_component_payload,
    verify_component_verdicts,
)
from shield_orchestrator.v4.contracts.v4_receipt import (
    OPTIONAL_RECEIPT_FIELDS,
    REQUIRED_RECEIPT_FIELDS,
    UNSIGNED_RECEIPT_EXCLUDED_FIELDS,
    _validate_receipt_payload_semantics,
    build_receipt_hash,
    validate_receipt_envelope,
)
from shield_orchestrator.v4.crypto_algorithms import (
    CLASSICAL_ED25519,
    FN_DSA,
    ML_DSA,
    SIGNATURE_POLICY_V1,
    require_supported_standard_profile,
)
from shield_orchestrator.v4.key_registry import (
    KeyRegistry,
    KeyRegistryEntry,
    enforce_registry_floor,
    load_key_registry,
    parse_utc_timestamp,
)
from shield_orchestrator.v4.signature_bundle import SignatureVerifier, verify_signature_bundle
from shield_orchestrator.v4.work_budget import (
    MAX_SIGNED_INTEGER_BITS,
    MAX_TRUSTED_REGISTRY_ENTRIES,
    ShieldV4WorkBudgetError,
    VerificationWorkCounter,
    require_bounded_text,
    require_canonical_receipt_budget,
    require_canonical_signature_bundle_budget,
    require_complete_bundle_count,
    require_planned_call_budget,
    require_signature_bundle_budget,
    snapshot_bounded_receipt,
)

AUDIT_SCHEMA_VERSION = "shield.verification_audit.v1"
AUDIT_APPEND_ACK_SCHEMA_VERSION = "shield.verification_audit.append_ack.v1"
AUDIT_REQUEST_ID_HASH_DOMAIN = "DGB-SHIELD-V4-AUDIT-REQUEST-ID\n"
AUDIT_KEY_ID_HASH_DOMAIN = "DGB-SHIELD-V4-AUDIT-KEY-ID\n"
AUDIT_BATCH_HASH_DOMAIN = (
    "DGB-SHIELD-V4-VERIFICATION-AUDIT-BATCH:shield.verification_audit.v1\n"
)
AUDIT_VERIFIER_ID = "shield_orchestrator.v4"
ORCHESTRATOR_ARTIFACT_ID = "shield_orchestrator"

VERIFICATION_PREFLIGHT_EVENT = "verification_preflight"
SIGNATURE_VERIFICATION_EVENT = "signature_verification"
ARTIFACT_VERIFICATION_EVENT = "artifact_verification"

V4_VERIFY_OK = "V4_VERIFY_OK"
V4_CONTRACT_INVALID = "V4_CONTRACT_INVALID"
V4_CONTEXT_MISMATCH = "V4_CONTEXT_MISMATCH"
V4_REQUEST_MISMATCH = "V4_REQUEST_MISMATCH"
V4_HASH_MISMATCH = "V4_HASH_MISMATCH"
V4_DOWNGRADE_REJECTED = "V4_DOWNGRADE_REJECTED"
V4_AUTHORITY_BYPASS = "V4_AUTHORITY_BYPASS"
V4_POLICY_INVALID = "V4_POLICY_INVALID"
V4_REGISTRY_INVALID = "V4_REGISTRY_INVALID"
V4_FRESHNESS_INVALID = "V4_FRESHNESS_INVALID"
V4_REPLAY_REJECTED = "V4_REPLAY_REJECTED"
V4_SIGNATURE_INVALID = "V4_SIGNATURE_INVALID"
V4_BACKEND_UNAVAILABLE = "V4_BACKEND_UNAVAILABLE"
V4_BACKEND_FAILURE = "V4_BACKEND_FAILURE"

AUDIT_REASON_IDS = frozenset(
    {
        V4_VERIFY_OK,
        V4_CONTRACT_INVALID,
        V4_CONTEXT_MISMATCH,
        V4_REQUEST_MISMATCH,
        V4_HASH_MISMATCH,
        V4_DOWNGRADE_REJECTED,
        V4_AUTHORITY_BYPASS,
        V4_POLICY_INVALID,
        V4_REGISTRY_INVALID,
        V4_FRESHNESS_INVALID,
        V4_REPLAY_REJECTED,
        V4_SIGNATURE_INVALID,
        V4_BACKEND_UNAVAILABLE,
        V4_BACKEND_FAILURE,
    }
)

COMMON_FIELDS = frozenset(
    {
        "schema_version",
        "event_type",
        "verifier_id",
        "verification_timestamp",
        "verification_passed",
        "reason_id",
    }
)
PREFLIGHT_FIELDS = COMMON_FIELDS | {
    "artifact_type",
    "expected_artifact_schema_version",
    "artifact_transport_hash",
    "expected_request_id_hash",
    "expected_context_hash",
    "required_policy_version",
    "minimum_registry_version",
}
SIGNATURE_FIELDS = COMMON_FIELDS | {
    "artifact_type",
    "artifact_schema_version",
    "artifact_id",
    "artifact_hash",
    "request_id_hash",
    "context_hash",
    "policy_version",
    "registry_version",
    "key_id_hash",
    "key_version",
    "algorithm",
    "standard_profile",
}
ARTIFACT_FIELDS = COMMON_FIELDS | {
    "artifact_type",
    "artifact_schema_version",
    "artifact_id",
    "artifact_hash",
    "request_id_hash",
    "context_hash",
    "policy_version",
    "registry_version",
}

MAX_AUDIT_RECORDS = 24
MAX_AUDIT_RECORD_BYTES = 2_048
MAX_AUDIT_BATCH_BYTES = 49_152

AuditEvent: TypeAlias = dict[str, Any]
AuditAppendAck: TypeAlias = dict[str, Any]
AuditRecordBytes: TypeAlias = bytes


class VerificationAuditSink(Protocol):
    """Durable append-only sink for one bounded, atomic event batch."""

    def append_batch(self, records: tuple[AuditRecordBytes, ...]) -> AuditAppendAck:
        """Append all immutable canonical records or none, then acknowledge durability."""
        ...


class ShieldV4VerificationError(ValueError):
    """Sanitized fail-closed result from the audited verification boundary."""

    def __init__(self, reason_id: str) -> None:
        self.reason_id = reason_id
        super().__init__(reason_id)


class ShieldV4AuditSinkError(RuntimeError):
    """Durable audit evidence was not acknowledged exactly."""


def _require_exact_timestamp(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 20:
        raise ValueError("verification_time must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        from datetime import datetime

        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError("verification_time must be YYYY-MM-DDTHH:MM:SSZ") from error
    return value


def _require_hash(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise ValueError(f"{field} must be 64-character lowercase sha256 hex")
    try:
        int(value, 16)
    except ValueError as error:
        raise ValueError(f"{field} must be 64-character lowercase sha256 hex") from error
    return value


def _hash_identifier(*, domain: str, value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be non-empty string")
    normalized = unicodedata.normalize("NFC", value)
    return hashlib.sha256(domain.encode("ascii") + normalized.encode("utf-8")).hexdigest()


def audit_request_id_hash(request_id: str) -> str:
    return _hash_identifier(
        domain=AUDIT_REQUEST_ID_HASH_DOMAIN,
        value=request_id,
        field="request_id",
    )


def audit_key_id_hash(key_id: str) -> str:
    return _hash_identifier(domain=AUDIT_KEY_ID_HASH_DOMAIN, value=key_id, field="key_id")


def _require_common(event: AuditEvent, *, event_type: str) -> None:
    if event.get("schema_version") != AUDIT_SCHEMA_VERSION:
        raise ValueError("audit event schema mismatch")
    if event.get("verifier_id") != AUDIT_VERIFIER_ID:
        raise ValueError("audit verifier mismatch")
    _require_exact_timestamp(event.get("verification_timestamp"))
    if not isinstance(event.get("verification_passed"), bool):
        raise ValueError("verification_passed must be exact bool")
    if event.get("reason_id") not in AUDIT_REASON_IDS:
        raise ValueError("unsupported audit reason_id")
    if (event["reason_id"] == V4_VERIFY_OK) is not event["verification_passed"]:
        raise ValueError("audit result and reason_id must agree")


def _require_artifact_type(value: Any) -> str:
    if value not in {"component_verdict", "orchestrator_receipt"}:
        raise ValueError("unsupported audit artifact_type")
    return value


def _require_positive_int(value: Any, *, field: str) -> int:
    maximum = (1 << (MAX_SIGNED_INTEGER_BITS - 1)) - 1
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError(f"{field} must be positive signed 64-bit integer")
    return value


def _validate_event(event: AuditEvent) -> None:
    if not isinstance(event, dict):
        raise ValueError("audit event must be dict")
    event_type = event.get("event_type")
    if event_type == VERIFICATION_PREFLIGHT_EVENT:
        if set(event) != PREFLIGHT_FIELDS:
            raise ValueError("preflight event fields must match exact schema")
        _require_common(event, event_type=VERIFICATION_PREFLIGHT_EVENT)
        if event["artifact_type"] != "orchestrator_receipt":
            raise ValueError("preflight artifact_type must be orchestrator_receipt")
        if event["expected_artifact_schema_version"] != RECEIPT_SCHEMA_VERSION:
            raise ValueError("preflight expected schema mismatch")
        _require_hash(event["artifact_transport_hash"], field="artifact_transport_hash")
        _require_hash(event["expected_request_id_hash"], field="expected_request_id_hash")
        _require_hash(event["expected_context_hash"], field="expected_context_hash")
        if event["required_policy_version"] != POLICY_VERSION:
            raise ValueError("preflight policy mismatch")
        _require_positive_int(event["minimum_registry_version"], field="minimum_registry_version")
        return
    if event_type == SIGNATURE_VERIFICATION_EVENT:
        if set(event) != SIGNATURE_FIELDS:
            raise ValueError("signature event fields must match exact schema")
        _require_common(event, event_type=SIGNATURE_VERIFICATION_EVENT)
        _validate_artifact_fields(event, signature=True)
        return
    if event_type == ARTIFACT_VERIFICATION_EVENT:
        if set(event) != ARTIFACT_FIELDS:
            raise ValueError("artifact event fields must match exact schema")
        _require_common(event, event_type=ARTIFACT_VERIFICATION_EVENT)
        _validate_artifact_fields(event, signature=False)
        return
    raise ValueError("unsupported audit event_type")


def _validate_artifact_fields(event: AuditEvent, *, signature: bool) -> None:
    artifact_type = _require_artifact_type(event["artifact_type"])
    expected_schema = (
        VERDICT_SCHEMA_VERSION if artifact_type == "component_verdict" else RECEIPT_SCHEMA_VERSION
    )
    if event["artifact_schema_version"] != expected_schema:
        raise ValueError("audit artifact schema mismatch")
    if not isinstance(event["artifact_id"], str) or not event["artifact_id"]:
        raise ValueError("audit artifact_id must be non-empty string")
    if artifact_type == "component_verdict" and event["artifact_id"] not in COMPONENT_ROLES:
        raise ValueError("component audit artifact_id mismatch")
    if (
        artifact_type == "orchestrator_receipt"
        and event["artifact_id"] != ORCHESTRATOR_ARTIFACT_ID
    ):
        raise ValueError("receipt audit artifact_id mismatch")
    _require_hash(event["artifact_hash"], field="artifact_hash")
    _require_hash(event["request_id_hash"], field="request_id_hash")
    _require_hash(event["context_hash"], field="context_hash")
    if event["policy_version"] != POLICY_VERSION:
        raise ValueError("audit policy mismatch")
    _require_positive_int(event["registry_version"], field="registry_version")
    if signature:
        _require_hash(event["key_id_hash"], field="key_id_hash")
        _require_positive_int(event["key_version"], field="key_version")
        require_supported_standard_profile(
            algorithm=event["algorithm"],
            standard_profile=event["standard_profile"],
        )


def serialize_audit_event(event: AuditEvent) -> AuditRecordBytes:
    _validate_event(event)
    encoded = to_canonical_json(event).encode("utf-8")
    if len(encoded) > MAX_AUDIT_RECORD_BYTES:
        raise ValueError("audit record exceeds byte limit")
    return encoded


def _parse_record(record: AuditRecordBytes) -> AuditEvent:
    if not isinstance(record, bytes):
        raise ValueError("audit record must be immutable bytes")
    if not record or len(record) > MAX_AUDIT_RECORD_BYTES:
        raise ValueError("audit record byte length is invalid")
    try:
        decoded = record.decode("utf-8", errors="strict")
        event = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("audit record must be canonical UTF-8 JSON") from error
    _validate_event(event)
    if serialize_audit_event(event) != record:
        raise ValueError("audit record must use exact canonical bytes")
    return event


def audit_batch_sha256(records: tuple[AuditRecordBytes, ...]) -> str:
    if not isinstance(records, tuple) or not records or len(records) > MAX_AUDIT_RECORDS:
        raise ValueError("audit batch record count is invalid")
    parsed = [_parse_record(record) for record in records]
    canonical = to_canonical_json({"records": parsed}).encode("utf-8")
    if len(canonical) > MAX_AUDIT_BATCH_BYTES:
        raise ValueError("audit batch exceeds byte limit")
    return hashlib.sha256(AUDIT_BATCH_HASH_DOMAIN.encode("ascii") + canonical).hexdigest()


def _common_event(
    *, event_type: str, verification_timestamp: str, verification_passed: bool, reason_id: str
) -> AuditEvent:
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "event_type": event_type,
        "verifier_id": AUDIT_VERIFIER_ID,
        "verification_timestamp": verification_timestamp,
        "verification_passed": verification_passed,
        "reason_id": reason_id,
    }


def _preflight_event(
    *,
    artifact_transport_hash: str,
    expected_request_id_hash: str,
    expected_context_hash: str,
    minimum_registry_version: int,
    verification_timestamp: str,
    verification_passed: bool,
    reason_id: str,
) -> AuditEvent:
    return {
        **_common_event(
            event_type=VERIFICATION_PREFLIGHT_EVENT,
            verification_timestamp=verification_timestamp,
            verification_passed=verification_passed,
            reason_id=reason_id,
        ),
        "artifact_type": "orchestrator_receipt",
        "expected_artifact_schema_version": RECEIPT_SCHEMA_VERSION,
        "artifact_transport_hash": artifact_transport_hash,
        "expected_request_id_hash": expected_request_id_hash,
        "expected_context_hash": expected_context_hash,
        "required_policy_version": POLICY_VERSION,
        "minimum_registry_version": minimum_registry_version,
    }


def _artifact_fields(
    *,
    artifact_type: str,
    artifact_id: str,
    artifact_hash: str,
    request_id: str,
    context_hash: str,
    registry_version: int,
) -> AuditEvent:
    return {
        "artifact_type": artifact_type,
        "artifact_schema_version": (
            VERDICT_SCHEMA_VERSION
            if artifact_type == "component_verdict"
            else RECEIPT_SCHEMA_VERSION
        ),
        "artifact_id": artifact_id,
        "artifact_hash": artifact_hash,
        "request_id_hash": audit_request_id_hash(request_id),
        "context_hash": context_hash,
        "policy_version": POLICY_VERSION,
        "registry_version": registry_version,
    }


def _signature_event(
    *,
    artifact: AuditEvent,
    entry: dict[str, Any],
    key: KeyRegistryEntry,
    verification_timestamp: str,
    verification_passed: bool,
    reason_id: str,
) -> AuditEvent:
    return {
        **_common_event(
            event_type=SIGNATURE_VERIFICATION_EVENT,
            verification_timestamp=verification_timestamp,
            verification_passed=verification_passed,
            reason_id=reason_id,
        ),
        **artifact,
        "key_id_hash": audit_key_id_hash(key.key_id),
        "key_version": key.key_version,
        "algorithm": key.algorithm,
        "standard_profile": entry["standard_profile"],
    }


def _artifact_event(
    *,
    artifact: AuditEvent,
    verification_timestamp: str,
    verification_passed: bool,
    reason_id: str,
) -> AuditEvent:
    return {
        **_common_event(
            event_type=ARTIFACT_VERIFICATION_EVENT,
            verification_timestamp=verification_timestamp,
            verification_passed=verification_passed,
            reason_id=reason_id,
        ),
        **artifact,
    }


def _classify_error(error: Exception, *, fallback: str) -> str:
    try:
        message = str(error).lower()
    except Exception:
        return fallback
    if "context" in message:
        return V4_CONTEXT_MISMATCH
    if "request" in message:
        return V4_REQUEST_MISMATCH
    if "hash" in message:
        return V4_HASH_MISMATCH
    if "authority" in message or "handoff_allowed" in message:
        return V4_AUTHORITY_BYPASS
    if "contract" in message or "schema" in message or "field" in message:
        return V4_CONTRACT_INVALID
    if "policy" in message or "algorithm" in message or "profile" in message:
        return V4_POLICY_INVALID
    if "registry" in message or "key" in message or "role" in message:
        return V4_REGISTRY_INVALID
    if "freshness" in message or "time" in message or "validity" in message:
        return V4_FRESHNESS_INVALID
    if "signature" in message:
        return V4_SIGNATURE_INVALID
    return fallback


def _preflight_reason(error: Exception) -> str:
    if isinstance(error, ShieldV4VerificationError):
        return error.reason_id
    if isinstance(error, ShieldV4WorkBudgetError):
        return V4_CONTRACT_INVALID
    return _classify_error(error, fallback=V4_CONTRACT_INVALID)


def _component_id_for_key(key: KeyRegistryEntry) -> str:
    for component_id, role in COMPONENT_ROLES.items():
        if key.role == role:
            return component_id
    raise ValueError("unsupported component key role")


@dataclass(frozen=True)
class _PrehashedVerification:
    artifact_id: str
    entry: dict[str, Any]
    key: KeyRegistryEntry
    verifier: SignatureVerifier
    verifier_kind: str


@dataclass(frozen=True)
class _PlannedVerification:
    artifact_id: str
    artifact: AuditEvent
    entry: dict[str, Any]
    key: KeyRegistryEntry
    verifier: SignatureVerifier
    verifier_kind: str


def _require_signed_positive_int(value: Any, *, field: str) -> int:
    return _require_positive_int(value, field=field)


def _require_loaded_registry_budget(registry: KeyRegistry) -> KeyRegistry:
    if type(registry.entries) is not tuple or not registry.entries:
        raise ValueError("loaded registry entries must be non-empty exact tuple")
    if len(registry.entries) > MAX_TRUSTED_REGISTRY_ENTRIES:
        raise ShieldV4WorkBudgetError("loaded registry exceeds trusted entry budget")
    schema_version = require_bounded_text(
        registry.schema_version,
        field="registry schema_version",
    )
    registry_version = _require_signed_positive_int(
        registry.registry_version,
        field="registry_version",
    )
    if schema_version != KEY_REGISTRY_SCHEMA_VERSION:
        raise ValueError("key registry schema mismatch")
    raw_entries: list[dict[str, Any]] = []
    for entry in registry.entries:
        if type(entry) is not KeyRegistryEntry:
            raise ValueError("loaded registry entry must be exact KeyRegistryEntry")
        raw_entries.append(
            {
                "role": require_bounded_text(entry.role, field="registry role"),
                "key_id": require_bounded_text(entry.key_id, field="registry key_id"),
                "key_version": _require_signed_positive_int(
                    entry.key_version,
                    field="registry key_version",
                ),
                "algorithm": require_bounded_text(
                    entry.algorithm,
                    field="registry algorithm",
                ),
                "not_before": require_bounded_text(
                    entry.not_before,
                    field="registry not_before",
                ),
                "not_after": require_bounded_text(
                    entry.not_after,
                    field="registry not_after",
                ),
                "status": require_bounded_text(entry.status, field="registry status"),
                "public_key": require_bounded_text(
                    entry.public_key,
                    field="registry public_key",
                ),
            }
        )
    return load_key_registry(
        {
            "schema_version": schema_version,
            "registry_version": registry_version,
            "entries": raw_entries,
        }
    )


def _require_complete_bundle_budgets(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    components = receipt.get("component_verdicts")
    if type(components) is not list:
        raise ValueError("component_verdicts must be exact list")
    require_complete_bundle_count(component_count=len(components), receipt_count=1)
    seen: set[str] = set()
    for component in components:
        if type(component) is not dict:
            raise ValueError("component verdict must be exact dict")
        component_id = require_bounded_text(
            component.get("component_id"),
            field="component_id",
        )
        if component_id not in SUPPORTED_COMPONENTS or component_id in seen:
            raise ValueError("component verdict identity set is invalid")
        seen.add(component_id)
        require_signature_bundle_budget(component.get("signature_bundle"))
    require_signature_bundle_budget(receipt.get("signature_bundle"))
    return components


def _require_artifact_freshness_window(
    *, not_before: Any, not_after: Any, verification_time: str
) -> None:
    start = parse_utc_timestamp(not_before, field="artifact_not_before")
    end = parse_utc_timestamp(not_after, field="artifact_not_after")
    checked_time = parse_utc_timestamp(verification_time, field="verification_time")
    if start >= end:
        raise ValueError("artifact freshness window is invalid")
    if not start <= checked_time <= end:
        raise ValueError("artifact is not valid at verification time")


def _prepare_signature_bundle_keys(
    *,
    bundle: dict[str, Any],
    artifact_id: str,
    expected_domain_tag: str,
    required_role: str,
    registry: KeyRegistry,
    verification_time: str,
    artifact_not_before: str,
    artifact_not_after: str,
    verifier: SignatureVerifier,
    verifier_kind: str,
    prepared: list[_PrehashedVerification],
) -> None:
    signatures = bundle["signatures"]
    for entry in signatures:
        if type(entry) is not dict:
            raise ValueError("signature entry must be exact dict")
        raw_signature = entry.get("signature")
        if type(raw_signature) is not str:
            raise ValueError("signature must be non-empty string")
        require_bounded_text(
            raw_signature,
            field="signature",
            allow_empty=True,
        )
        if not raw_signature.strip():
            raise ValueError("signature must be non-empty string")
    first_entry = signatures[0]
    provisional_hash = _require_hash(
        first_entry.get("signed_payload_hash"),
        field="signed_payload_hash",
    )

    def prepare(entry: dict[str, Any], key: KeyRegistryEntry) -> bool:
        prepared.append(
            _PrehashedVerification(
                artifact_id=artifact_id,
                entry=entry,
                key=key,
                verifier=verifier,
                verifier_kind=verifier_kind,
            )
        )
        return True

    verify_signature_bundle(
        bundle,
        expected_signed_payload_hash=provisional_hash,
        expected_domain_tag=expected_domain_tag,
        required_role=required_role,
        registry=registry,
        verification_time=verification_time,
        artifact_not_before=artifact_not_before,
        artifact_not_after=artifact_not_after,
        verifier=prepare,
    )


def _cache_token(
    *, entry: dict[str, Any], key: KeyRegistryEntry, verifier_kind: str
) -> tuple[Any, ...]:
    return (
        verifier_kind,
        id(entry),
        key.role,
        key.key_id,
        key.key_version,
        key.algorithm,
    )


def _make_cached_verifier(
    *, verifier_kind: str, remaining: set[tuple[Any, ...]]
) -> SignatureVerifier:
    def cached(entry: dict[str, Any], key: KeyRegistryEntry) -> bool:
        token = _cache_token(entry=entry, key=key, verifier_kind=verifier_kind)
        if token not in remaining:
            return False
        remaining.remove(token)
        return True

    return cached


def _validate_complete_plan(plans: list[_PlannedVerification]) -> None:
    artifacts = {plan.artifact_id for plan in plans}
    expected_artifacts = set(SUPPORTED_COMPONENTS) | {ORCHESTRATOR_ARTIFACT_ID}
    if artifacts != expected_artifacts:
        raise ValueError("verification plan must cover all six bundles")
    for artifact_id in expected_artifacts:
        count = sum(plan.artifact_id == artifact_id for plan in plans)
        if not 2 <= count <= 3:
            raise ValueError("verification plan bundle signature count is invalid")
    require_planned_call_budget(tuple(plan.key.algorithm for plan in plans))
    tokens = {
        _cache_token(
            entry=plan.entry,
            key=plan.key,
            verifier_kind=plan.verifier_kind,
        )
        for plan in plans
    }
    if len(tokens) != len(plans):
        raise ValueError("verification plan contains duplicate callback")


def _validate_prehashed_plan(plans: list[_PrehashedVerification]) -> None:
    artifacts = {plan.artifact_id for plan in plans}
    expected_artifacts = set(SUPPORTED_COMPONENTS) | {ORCHESTRATOR_ARTIFACT_ID}
    if artifacts != expected_artifacts:
        raise ValueError("prehash plan must cover all six bundles")
    for artifact_id in expected_artifacts:
        count = sum(plan.artifact_id == artifact_id for plan in plans)
        if not 2 <= count <= 3:
            raise ValueError("prehash plan bundle signature count is invalid")
    require_planned_call_budget(tuple(plan.key.algorithm for plan in plans))
    tokens = {
        _cache_token(
            entry=plan.entry,
            key=plan.key,
            verifier_kind=plan.verifier_kind,
        )
        for plan in plans
    }
    if len(tokens) != len(plans):
        raise ValueError("prehash plan contains duplicate callback")


def _expected_component_signature_results(
    plans: list[_PrehashedVerification],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for component_id in SUPPORTED_COMPONENTS:
        component_plans = [
            plan for plan in plans if plan.artifact_id == component_id
        ]
        results.append(
            {
                "component_id": component_id,
                "component_role": COMPONENT_ROLES[component_id],
                "verified": True,
                "verified_algorithms": [
                    plan.key.algorithm for plan in component_plans
                ],
                "verified_standard_profiles": [
                    plan.entry["standard_profile"] for plan in component_plans
                ],
                "signature_policy": POLICY_VERSION,
            }
        )
    return results


def _run_planned_callbacks(
    *,
    plans: list[_PlannedVerification],
    events: list[AuditEvent],
    verification_timestamp: str,
) -> tuple[_PlannedVerification, str] | None:
    artifact_order = {
        artifact_id: rank
        for rank, artifact_id in enumerate(
            (*SUPPORTED_COMPONENTS, ORCHESTRATOR_ARTIFACT_ID)
        )
    }
    algorithm_order = {
        CLASSICAL_ED25519: 0,
        ML_DSA: 1,
        FN_DSA: 2,
    }
    ordered = sorted(
        plans,
        key=lambda plan: (
            algorithm_order[plan.key.algorithm],
            artifact_order[plan.artifact_id],
        ),
    )
    counter = VerificationWorkCounter()
    for plan in ordered:
        callback_entry = dict(plan.entry)
        callback_key = KeyRegistryEntry(
            role=plan.key.role,
            key_id=plan.key.key_id,
            key_version=plan.key.key_version,
            algorithm=plan.key.algorithm,
            not_before=plan.key.not_before,
            not_after=plan.key.not_after,
            status=plan.key.status,
            public_key=plan.key.public_key,
        )
        counter.record_callback_attempt(plan.key.algorithm)
        try:
            result = plan.verifier(callback_entry, callback_key)
        except Exception:
            result = False
            reason_id = V4_BACKEND_FAILURE
        else:
            if type(result) is not bool:
                result = False
                reason_id = V4_BACKEND_FAILURE
            else:
                reason_id = V4_VERIFY_OK if result else V4_SIGNATURE_INVALID
        events.append(
            _signature_event(
                artifact=plan.artifact,
                entry=plan.entry,
                key=plan.key,
                verification_timestamp=verification_timestamp,
                verification_passed=result,
                reason_id=reason_id,
            )
        )
        if not result:
            return plan, reason_id
    return None


def _commit_records(
    *, audit_sink: VerificationAuditSink, events: list[AuditEvent]
) -> bool:
    try:
        records = tuple(serialize_audit_event(event) for event in events)
        expected_hash = audit_batch_sha256(records)
        acknowledgement = audit_sink.append_batch(records)
        if type(acknowledgement) is not dict:
            return False
        if set(acknowledgement) != {
            "schema_version",
            "batch_sha256",
            "record_count",
            "durably_committed",
        }:
            return False
        return (
            type(acknowledgement["schema_version"]) is str
            and acknowledgement["schema_version"] == AUDIT_APPEND_ACK_SCHEMA_VERSION
            and type(acknowledgement["batch_sha256"]) is str
            and hmac.compare_digest(acknowledgement["batch_sha256"], expected_hash)
            and type(acknowledgement["record_count"]) is int
            and acknowledgement["record_count"] == len(records)
            and acknowledgement["durably_committed"] is True
        )
    except Exception:
        return False


def _raise_sink_failure() -> None:
    raise ShieldV4AuditSinkError("V4_AUDIT_SINK_FAILURE") from None


def _commit_rejection(
    *, audit_sink: VerificationAuditSink, events: list[AuditEvent], reason_id: str
) -> None:
    if not _commit_records(audit_sink=audit_sink, events=events):
        _raise_sink_failure()
    raise ShieldV4VerificationError(reason_id) from None


def verify_v4_receipt_with_audit(
    receipt: dict[str, Any],
    *,
    artifact_transport_hash: str,
    expected_context_hash: str,
    expected_request_id: str,
    registry: KeyRegistry,
    minimum_registry_version: int,
    verification_time: str,
    component_verifier: SignatureVerifier,
    receipt_verifier: SignatureVerifier,
    audit_sink: VerificationAuditSink,
) -> dict[str, Any]:
    """Verify one bounded six-bundle chain and return after durable audit ACK."""
    transport_hash = _require_hash(artifact_transport_hash, field="artifact_transport_hash")
    context_hash = _require_hash(expected_context_hash, field="expected_context_hash")
    timestamp = _require_exact_timestamp(verification_time)
    bounded_request_id = require_bounded_text(
        expected_request_id,
        field="expected_request_id",
    )
    request_hash = audit_request_id_hash(bounded_request_id)
    if type(registry) is not KeyRegistry:
        raise ValueError("registry must be loaded KeyRegistry")
    _require_positive_int(minimum_registry_version, field="minimum_registry_version")

    events = [
        _preflight_event(
            artifact_transport_hash=transport_hash,
            expected_request_id_hash=request_hash,
            expected_context_hash=context_hash,
            minimum_registry_version=minimum_registry_version,
            verification_timestamp=timestamp,
            verification_passed=True,
            reason_id=V4_VERIFY_OK,
        )
    ]

    try:
        receipt = snapshot_bounded_receipt(receipt).value
        if set(receipt) - OPTIONAL_RECEIPT_FIELDS != REQUIRED_RECEIPT_FIELDS:
            raise ValueError("receipt fields must match required schema")
        component_values = _require_complete_bundle_budgets(receipt)
        checked_registry = _require_loaded_registry_budget(registry)
        enforce_registry_floor(
            registry=checked_registry,
            minimum_registry_version=minimum_registry_version,
        )
    except Exception as error:
        reason_id = _preflight_reason(error)
        events[0]["verification_passed"] = False
        events[0]["reason_id"] = reason_id
        _commit_rejection(audit_sink=audit_sink, events=events, reason_id=reason_id)

    if receipt.get("request_id") != bounded_request_id:
        events[0]["verification_passed"] = False
        events[0]["reason_id"] = V4_REQUEST_MISMATCH
        _commit_rejection(
            audit_sink=audit_sink, events=events, reason_id=V4_REQUEST_MISMATCH
        )
    receipt_schema = receipt.get("schema_version")
    if receipt_schema != RECEIPT_SCHEMA_VERSION:
        reason_id = (
            V4_DOWNGRADE_REJECTED
            if isinstance(receipt_schema, str) and receipt_schema.startswith("shield.receipt.v")
            else V4_CONTRACT_INVALID
        )
        events[0]["verification_passed"] = False
        events[0]["reason_id"] = reason_id
        _commit_rejection(audit_sink=audit_sink, events=events, reason_id=reason_id)
    if receipt.get("context_hash") != context_hash:
        events[0]["verification_passed"] = False
        events[0]["reason_id"] = V4_CONTEXT_MISMATCH
        _commit_rejection(
            audit_sink=audit_sink, events=events, reason_id=V4_CONTEXT_MISMATCH
        )
    if receipt.get("signature_policy") != POLICY_VERSION:
        events[0]["verification_passed"] = False
        events[0]["reason_id"] = V4_POLICY_INVALID
        _commit_rejection(
            audit_sink=audit_sink, events=events, reason_id=V4_POLICY_INVALID
        )

    try:
        if receipt.get("contract_version") != 4:
            raise ValueError("receipt contract version mismatch")
        if receipt.get("canonicalization_profile") != CANONICALIZATION_PROFILE:
            raise ValueError("receipt canonicalization profile mismatch")
        if receipt.get("fail_closed") is not True:
            raise ValueError("receipt fail_closed must be true")
        if receipt.get("key_registry_version") != checked_registry.registry_version:
            raise ValueError("receipt key registry version mismatch")

        component_payloads: dict[str, dict[str, Any]] = {}
        prehashed: list[_PrehashedVerification] = []
        for component in component_values:
            payload = unsigned_component_payload(component)
            component_id = payload["component_id"]
            if payload["context_hash"] != context_hash:
                raise ValueError("component context_hash mismatch")
            if payload["key_registry_version"] != checked_registry.registry_version:
                raise ValueError("component key registry version mismatch")
            component_payloads[component_id] = payload
            _require_artifact_freshness_window(
                not_before=payload["not_before"],
                not_after=payload["not_after"],
                verification_time=timestamp,
            )
            _prepare_signature_bundle_keys(
                bundle=component["signature_bundle"],
                artifact_id=component_id,
                expected_domain_tag=COMPONENT_VERDICT_DOMAIN,
                required_role=COMPONENT_ROLES[component_id],
                registry=checked_registry,
                verification_time=timestamp,
                artifact_not_before=payload["not_before"],
                artifact_not_after=payload["not_after"],
                verifier=component_verifier,
                verifier_kind="component",
                prepared=prehashed,
            )
        _require_artifact_freshness_window(
            not_before=receipt["not_before"],
            not_after=receipt["not_after"],
            verification_time=timestamp,
        )
        _prepare_signature_bundle_keys(
            bundle=receipt["signature_bundle"],
            artifact_id=ORCHESTRATOR_ARTIFACT_ID,
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role="shield_orchestrator",
            registry=checked_registry,
            verification_time=timestamp,
            artifact_not_before=receipt["not_before"],
            artifact_not_after=receipt["not_after"],
            verifier=receipt_verifier,
            verifier_kind="receipt",
            prepared=prehashed,
        )
        _validate_prehashed_plan(prehashed)

        unsigned_receipt = {
            key: receipt[key]
            for key in receipt
            if key not in UNSIGNED_RECEIPT_EXCLUDED_FIELDS
        }
        _validate_receipt_payload_semantics(
            unsigned_receipt,
            expected_context_hash=context_hash,
        )
        if receipt.get("component_signature_results") != (
            _expected_component_signature_results(prehashed)
        ):
            raise ValueError(
                "component results do not match prepared verification plan"
            )

        for component in component_values:
            require_canonical_signature_bundle_budget(component["signature_bundle"])
        require_canonical_signature_bundle_budget(receipt["signature_bundle"])
        require_canonical_receipt_budget(receipt)

        expected_receipt_hash = build_receipt_hash(unsigned_receipt)
        if _require_hash(receipt.get("receipt_hash"), field="receipt_hash") != expected_receipt_hash:
            raise ValueError("receipt hash mismatch")
        expected_signed_hash = signed_payload_hash(
            domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            payload=unsigned_receipt,
        )
        if (
            _require_hash(receipt.get("signed_payload_hash"), field="signed_payload_hash")
            != expected_signed_hash
        ):
            raise ValueError("signed payload hash mismatch")

        artifacts: dict[str, AuditEvent] = {}
        for component in component_values:
            component_id = component["component_id"]
            payload = component_payloads[component_id]
            expected_component_hash = signed_payload_hash(
                domain_tag=COMPONENT_VERDICT_DOMAIN,
                payload=payload,
            )
            if (
                _require_hash(
                    component.get("signed_payload_hash"), field="signed_payload_hash"
                )
                != expected_component_hash
            ):
                raise ValueError("component signed payload hash mismatch")
            artifacts[component_id] = _artifact_fields(
                artifact_type="component_verdict",
                artifact_id=component_id,
                artifact_hash=expected_component_hash,
                request_id=payload["request_id"],
                context_hash=context_hash,
                registry_version=checked_registry.registry_version,
            )
    except Exception as error:
        reason_id = _preflight_reason(error)
        events[0]["verification_passed"] = False
        events[0]["reason_id"] = reason_id
        _commit_rejection(audit_sink=audit_sink, events=events, reason_id=reason_id)

    receipt_artifact = _artifact_fields(
        artifact_type="orchestrator_receipt",
        artifact_id=ORCHESTRATOR_ARTIFACT_ID,
        artifact_hash=expected_signed_hash,
        request_id=receipt["request_id"],
        context_hash=context_hash,
        registry_version=checked_registry.registry_version,
    )
    artifacts[ORCHESTRATOR_ARTIFACT_ID] = receipt_artifact

    plans = [
        _PlannedVerification(
            artifact_id=prepared.artifact_id,
            artifact=artifacts[prepared.artifact_id],
            entry=prepared.entry,
            key=prepared.key,
            verifier=prepared.verifier,
            verifier_kind=prepared.verifier_kind,
        )
        for prepared in prehashed
    ]
    try:
        _validate_complete_plan(plans)
        preflight_remaining = {
            _cache_token(
                entry=plan.entry,
                key=plan.key,
                verifier_kind=plan.verifier_kind,
            )
            for plan in plans
        }
        verify_component_verdicts(
            component_values,
            expected_context_hash=context_hash,
            registry=checked_registry,
            verification_time=timestamp,
            verifier=_make_cached_verifier(
                verifier_kind="component",
                remaining=preflight_remaining,
            ),
        )
        validate_receipt_envelope(
            receipt,
            expected_context_hash=context_hash,
            registry=checked_registry,
            verification_time=timestamp,
            verifier=_make_cached_verifier(
                verifier_kind="receipt",
                remaining=preflight_remaining,
            ),
        )
        if preflight_remaining:
            raise ValueError("preflight verification cache was not consumed exactly")
    except Exception as error:
        reason_id = _preflight_reason(error)
        events[0]["verification_passed"] = False
        events[0]["reason_id"] = reason_id
        events[:] = [events[0]]
        _commit_rejection(audit_sink=audit_sink, events=events, reason_id=reason_id)

    failed = _run_planned_callbacks(
        plans=plans,
        events=events,
        verification_timestamp=timestamp,
    )
    if failed is not None:
        failed_plan, reason_id = failed
        events.append(
            _artifact_event(
                artifact=failed_plan.artifact,
                verification_timestamp=timestamp,
                verification_passed=False,
                reason_id=reason_id,
            )
        )
        _commit_rejection(audit_sink=audit_sink, events=events, reason_id=reason_id)

    remaining = {
        _cache_token(
            entry=plan.entry,
            key=plan.key,
            verifier_kind=plan.verifier_kind,
        )
        for plan in plans
    }
    component_cache = _make_cached_verifier(
        verifier_kind="component",
        remaining=remaining,
    )
    receipt_cache = _make_cached_verifier(
        verifier_kind="receipt",
        remaining=remaining,
    )
    try:
        _, component_summaries = verify_component_verdicts(
            component_values,
            expected_context_hash=context_hash,
            registry=checked_registry,
            verification_time=timestamp,
            verifier=component_cache,
        )
        if component_summaries != receipt.get("component_signature_results"):
            raise ValueError("component signature results contract mismatch")
        checked_receipt = validate_receipt_envelope(
            receipt,
            expected_context_hash=context_hash,
            registry=checked_registry,
            verification_time=timestamp,
            verifier=receipt_cache,
        )
        if remaining:
            raise ValueError("verification cache was not consumed exactly")
    except Exception as error:
        reason_id = _classify_error(error, fallback=V4_CONTRACT_INVALID)
        events.append(
            _artifact_event(
                artifact=receipt_artifact,
                verification_timestamp=timestamp,
                verification_passed=False,
                reason_id=reason_id,
            )
        )
        _commit_rejection(audit_sink=audit_sink, events=events, reason_id=reason_id)

    events.append(
        _artifact_event(
            artifact=receipt_artifact,
            verification_timestamp=timestamp,
            verification_passed=True,
            reason_id=V4_VERIFY_OK,
        )
    )
    if not _commit_records(audit_sink=audit_sink, events=events):
        _raise_sink_failure()
    return checked_receipt
