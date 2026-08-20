from __future__ import annotations

import hashlib
import hmac
import json
import unicodedata
from collections.abc import Callable
from typing import Any, Protocol, TypeAlias

from shield_orchestrator.v4 import POLICY_VERSION, RECEIPT_SCHEMA_VERSION, VERDICT_SCHEMA_VERSION
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
    build_receipt_hash,
    validate_receipt_envelope,
)
from shield_orchestrator.v4.crypto_algorithms import require_supported_standard_profile
from shield_orchestrator.v4.key_registry import (
    KeyRegistry,
    KeyRegistryEntry,
    enforce_registry_floor,
)
from shield_orchestrator.v4.signature_bundle import SignatureVerifier

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


def _snapshot_untrusted_json(value: Any) -> Any:
    """Copy an untrusted JSON graph without invoking subclass behavior."""
    if value is None or type(value) in {str, bool, int}:
        return value
    if type(value) is list:
        return [_snapshot_untrusted_json(item) for item in value]
    if type(value) is dict:
        snapshot: dict[str, Any] = {}
        for key in value:
            if type(key) is not str:
                raise ValueError("receipt object keys must be exact strings")
            snapshot[key] = _snapshot_untrusted_json(value[key])
        return snapshot
    raise ValueError("receipt must contain exact JSON value types")


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
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be positive integer")
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
    if "contract" in message or "schema" in message or "field" in message:
        return V4_CONTRACT_INVALID
    if "authority" in message or "handoff_allowed" in message:
        return V4_AUTHORITY_BYPASS
    if "policy" in message or "algorithm" in message or "profile" in message:
        return V4_POLICY_INVALID
    if "registry" in message or "key" in message or "role" in message:
        return V4_REGISTRY_INVALID
    if "freshness" in message or "time" in message or "validity" in message:
        return V4_FRESHNESS_INVALID
    if "signature" in message:
        return V4_SIGNATURE_INVALID
    return fallback


def _component_id_for_key(key: KeyRegistryEntry) -> str:
    for component_id, role in COMPONENT_ROLES.items():
        if key.role == role:
            return component_id
    raise ValueError("unsupported component key role")


def _make_audited_verifier(
    *,
    verifier: SignatureVerifier,
    records: list[AuditEvent],
    artifacts: dict[str, AuditEvent],
    artifact_id_for_key: Callable[[KeyRegistryEntry], str],
    verification_timestamp: str,
    failures: list[tuple[AuditEvent, str]],
) -> SignatureVerifier:
    def audited(entry: dict[str, Any], key: KeyRegistryEntry) -> bool:
        artifact_id = artifact_id_for_key(key)
        artifact = artifacts[artifact_id]
        try:
            result = verifier(entry, key)
        except Exception:
            result = False
            reason_id = V4_BACKEND_FAILURE
        else:
            reason_id = V4_VERIFY_OK if result is True else V4_SIGNATURE_INVALID
            if not isinstance(result, bool):
                result = False
                reason_id = V4_BACKEND_FAILURE
        records.append(
            _signature_event(
                artifact=artifact,
                entry=entry,
                key=key,
                verification_timestamp=verification_timestamp,
                verification_passed=result,
                reason_id=reason_id,
            )
        )
        if not result:
            failures.append((artifact, reason_id))
        return result

    return audited


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
    """Verify components and receipt; return only after exact durable audit ACK."""
    transport_hash = _require_hash(artifact_transport_hash, field="artifact_transport_hash")
    context_hash = _require_hash(expected_context_hash, field="expected_context_hash")
    timestamp = _require_exact_timestamp(verification_time)
    request_hash = audit_request_id_hash(expected_request_id)
    if not isinstance(registry, KeyRegistry):
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
        enforce_registry_floor(
            registry=registry, minimum_registry_version=minimum_registry_version
        )
    except Exception:
        events[0]["verification_passed"] = False
        events[0]["reason_id"] = V4_REGISTRY_INVALID
        _commit_rejection(
            audit_sink=audit_sink, events=events, reason_id=V4_REGISTRY_INVALID
        )

    try:
        plain_receipt = _snapshot_untrusted_json(receipt)
        if type(plain_receipt) is not dict:
            raise ValueError("receipt must be dict")
        receipt = plain_receipt
    except Exception:
        events[0]["verification_passed"] = False
        events[0]["reason_id"] = V4_CONTRACT_INVALID
        _commit_rejection(
            audit_sink=audit_sink, events=events, reason_id=V4_CONTRACT_INVALID
        )

    if receipt.get("request_id") != expected_request_id:
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
        if set(receipt) - OPTIONAL_RECEIPT_FIELDS != REQUIRED_RECEIPT_FIELDS:
            raise ValueError("receipt fields must match required schema")
        unsigned_receipt = {
            key: receipt[key]
            for key in receipt
            if key not in UNSIGNED_RECEIPT_EXCLUDED_FIELDS
        }
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
    except Exception as error:
        reason_id = _classify_error(error, fallback=V4_CONTRACT_INVALID)
        events[0]["verification_passed"] = False
        events[0]["reason_id"] = reason_id
        _commit_rejection(audit_sink=audit_sink, events=events, reason_id=reason_id)

    component_values = receipt.get("component_verdicts")
    artifacts: dict[str, AuditEvent] = {}
    try:
        if type(component_values) is not list or len(component_values) != len(
            SUPPORTED_COMPONENTS
        ):
            raise ValueError("component_verdicts must contain every required component")
        seen_component_ids: set[str] = set()
        for component in component_values:
            if type(component) is not dict:
                raise ValueError("component verdict must be dict")
            payload = unsigned_component_payload(component)
            component_id = payload["component_id"]
            if component_id in seen_component_ids:
                raise ValueError("duplicate component verdict")
            seen_component_ids.add(component_id)
            if payload["context_hash"] != context_hash:
                raise ValueError("component context_hash mismatch")
            if payload["key_registry_version"] != registry.registry_version:
                raise ValueError("component key registry version mismatch")
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
                registry_version=registry.registry_version,
            )
    except Exception as error:
        reason_id = _classify_error(error, fallback=V4_CONTRACT_INVALID)
        events[0]["verification_passed"] = False
        events[0]["reason_id"] = reason_id
        _commit_rejection(audit_sink=audit_sink, events=events, reason_id=reason_id)

    receipt_artifact = _artifact_fields(
        artifact_type="orchestrator_receipt",
        artifact_id=ORCHESTRATOR_ARTIFACT_ID,
        artifact_hash=expected_signed_hash,
        request_id=receipt["request_id"],
        context_hash=context_hash,
        registry_version=registry.registry_version,
    )
    artifacts[ORCHESTRATOR_ARTIFACT_ID] = receipt_artifact

    component_failures: list[tuple[AuditEvent, str]] = []
    receipt_failures: list[tuple[AuditEvent, str]] = []
    component_auditor = _make_audited_verifier(
        verifier=component_verifier,
        records=events,
        artifacts=artifacts,
        artifact_id_for_key=_component_id_for_key,
        verification_timestamp=timestamp,
        failures=component_failures,
    )
    receipt_auditor = _make_audited_verifier(
        verifier=receipt_verifier,
        records=events,
        artifacts=artifacts,
        artifact_id_for_key=lambda _key: ORCHESTRATOR_ARTIFACT_ID,
        verification_timestamp=timestamp,
        failures=receipt_failures,
    )

    try:
        _, component_summaries = verify_component_verdicts(
            component_values,
            expected_context_hash=context_hash,
            registry=registry,
            verification_time=timestamp,
            verifier=component_auditor,
        )
    except Exception as error:
        reason_id = _classify_error(error, fallback=V4_CONTRACT_INVALID)
        if component_failures:
            terminal_artifact, reason_id = component_failures[-1]
            events.append(
                _artifact_event(
                    artifact=terminal_artifact,
                    verification_timestamp=timestamp,
                    verification_passed=False,
                    reason_id=reason_id,
                )
            )
        elif len(events) > 1:
            events.append(
                _artifact_event(
                    artifact=receipt_artifact,
                    verification_timestamp=timestamp,
                    verification_passed=False,
                    reason_id=reason_id,
                )
            )
        else:
            events[0]["verification_passed"] = False
            events[0]["reason_id"] = reason_id
            events[:] = [events[0]]
        _commit_rejection(audit_sink=audit_sink, events=events, reason_id=reason_id)

    if component_summaries != receipt.get("component_signature_results"):
        reason_id = V4_CONTRACT_INVALID
        events.append(
            _artifact_event(
                artifact=receipt_artifact,
                verification_timestamp=timestamp,
                verification_passed=False,
                reason_id=reason_id,
            )
        )
        _commit_rejection(audit_sink=audit_sink, events=events, reason_id=reason_id)

    try:
        checked_receipt = validate_receipt_envelope(
            receipt,
            expected_context_hash=context_hash,
            registry=registry,
            verification_time=timestamp,
            verifier=receipt_auditor,
        )
    except Exception as error:
        reason_id = _classify_error(error, fallback=V4_CONTRACT_INVALID)
        if receipt_failures:
            terminal_artifact, reason_id = receipt_failures[-1]
            events.append(
                _artifact_event(
                    artifact=terminal_artifact,
                    verification_timestamp=timestamp,
                    verification_passed=False,
                    reason_id=reason_id,
                )
            )
        else:
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
