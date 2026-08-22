from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import shield_orchestrator.v4.verification_audit as audit

from shield_orchestrator.v4.canonical_json import (
    ORCHESTRATOR_RECEIPT_DOMAIN,
    signed_payload_hash,
    to_canonical_json,
)
from shield_orchestrator.v4.component_verdicts import verify_test_only_component_signature
from shield_orchestrator.v4.contracts.v4_receipt import (
    UNSIGNED_RECEIPT_EXCLUDED_FIELDS,
    build_receipt_hash,
)
from shield_orchestrator.v4.key_registry import load_key_registry
from shield_orchestrator.v4.orchestrate import verify_test_only_orchestrator_signature
from shield_orchestrator.v4.verification_audit import (
    ARTIFACT_FIELDS,
    ARTIFACT_VERIFICATION_EVENT,
    AUDIT_APPEND_ACK_SCHEMA_VERSION,
    AUDIT_BATCH_HASH_DOMAIN,
    AUDIT_KEY_ID_HASH_DOMAIN,
    AUDIT_REQUEST_ID_HASH_DOMAIN,
    AUDIT_SCHEMA_VERSION,
    AUDIT_VERIFIER_ID,
    MAX_AUDIT_BATCH_BYTES,
    MAX_AUDIT_RECORD_BYTES,
    MAX_AUDIT_RECORDS,
    PREFLIGHT_FIELDS,
    SIGNATURE_FIELDS,
    SIGNATURE_VERIFICATION_EVENT,
    V4_BACKEND_FAILURE,
    V4_CONTRACT_INVALID,
    V4_CONTEXT_MISMATCH,
    V4_HASH_MISMATCH,
    V4_REGISTRY_INVALID,
    V4_REQUEST_MISMATCH,
    V4_SIGNATURE_INVALID,
    V4_VERIFY_OK,
    VERIFICATION_PREFLIGHT_EVENT,
    ShieldV4AuditSinkError,
    ShieldV4VerificationError,
    audit_batch_sha256,
    audit_key_id_hash,
    audit_request_id_hash,
    serialize_audit_event,
    verify_v4_receipt_with_audit,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/v4/full_multi_repo_v4_allow_flow.json"


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _transport_hash(receipt: dict[str, Any]) -> str:
    bounded_transport = json.dumps(
        receipt,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(bounded_transport).hexdigest()


def _refresh_outer_hashes(receipt: dict[str, Any]) -> None:
    unsigned = {
        key: receipt[key]
        for key in receipt
        if key not in UNSIGNED_RECEIPT_EXCLUDED_FIELDS
    }
    receipt["receipt_hash"] = build_receipt_hash(unsigned)
    receipt["signed_payload_hash"] = signed_payload_hash(
        domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        payload=unsigned,
    )


def _decode(records: tuple[bytes, ...]) -> list[dict[str, Any]]:
    return [json.loads(record.decode("utf-8")) for record in records]


class RecordingSink:
    def __init__(self) -> None:
        self.batches: list[tuple[bytes, ...]] = []

    def append_batch(self, records: tuple[bytes, ...]) -> dict[str, Any]:
        assert isinstance(records, tuple)
        assert all(type(record) is bytes for record in records)
        self.batches.append(records)
        return {
            "schema_version": AUDIT_APPEND_ACK_SCHEMA_VERSION,
            "batch_sha256": audit_batch_sha256(records),
            "record_count": len(records),
            "durably_committed": True,
        }


class BadSink:
    def __init__(self, acknowledgement: Any = None, *, raises: bool = False) -> None:
        self.acknowledgement = acknowledgement
        self.raises = raises

    def append_batch(self, _records: tuple[bytes, ...]) -> Any:
        if self.raises:
            raise RuntimeError("SECRET-SINK-DIAGNOSTIC")
        return self.acknowledgement


def _verify(
    *,
    receipt: dict[str, Any] | None = None,
    artifact_transport_hash: str | None = None,
    expected_request_id: str | None = None,
    minimum_registry_version: int = 1,
    component_verifier=verify_test_only_component_signature,
    receipt_verifier=verify_test_only_orchestrator_signature,
    sink: Any | None = None,
) -> tuple[dict[str, Any], RecordingSink]:
    fixture = _fixture()
    checked_receipt = fixture["receipt"] if receipt is None else receipt
    checked_sink = RecordingSink() if sink is None else sink
    result = verify_v4_receipt_with_audit(
        checked_receipt,
        artifact_transport_hash=(
            _transport_hash(checked_receipt)
            if artifact_transport_hash is None
            else artifact_transport_hash
        ),
        expected_context_hash=fixture["expected_context_hash"],
        expected_request_id=(
            fixture["expected_request_id"]
            if expected_request_id is None
            else expected_request_id
        ),
        registry=load_key_registry(fixture["trusted_key_registry"]),
        minimum_registry_version=minimum_registry_version,
        verification_time=fixture["verification_time"],
        component_verifier=component_verifier,
        receipt_verifier=receipt_verifier,
        audit_sink=checked_sink,
    )
    return result, checked_sink


def test_v410b_success_emits_exact_private_bounded_tagged_union_and_ack() -> None:
    result, sink = _verify()
    assert result["final_outcome"] == "ALLOW"
    assert len(sink.batches) == 1
    records = sink.batches[0]
    assert len(records) == 14
    assert len(records) <= MAX_AUDIT_RECORDS
    assert all(len(record) <= MAX_AUDIT_RECORD_BYTES for record in records)

    events = _decode(records)
    assert set(events[0]) == PREFLIGHT_FIELDS
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[0]["verification_passed"] is True
    assert events[0]["reason_id"] == V4_VERIFY_OK
    assert events[0]["verifier_id"] == AUDIT_VERIFIER_ID
    assert all(set(event) == SIGNATURE_FIELDS for event in events[1:-1])
    assert all(event["event_type"] == SIGNATURE_VERIFICATION_EVENT for event in events[1:-1])
    assert set(events[-1]) == ARTIFACT_FIELDS
    assert events[-1]["event_type"] == ARTIFACT_VERIFICATION_EVENT
    assert events[-1]["verification_passed"] is True
    assert events[-1]["reason_id"] == V4_VERIFY_OK
    assert all(event["schema_version"] == AUDIT_SCHEMA_VERSION for event in events)

    serialized_batch = to_canonical_json({"records": events}).encode("utf-8")
    expected_batch = hashlib.sha256(
        AUDIT_BATCH_HASH_DOMAIN.encode("ascii") + serialized_batch
    ).hexdigest()
    assert audit_batch_sha256(records) == expected_batch
    assert len(serialized_batch) <= MAX_AUDIT_BATCH_BYTES

    transport_text = b"\n".join(records).decode("utf-8")
    fixture = _fixture()
    assert fixture["expected_request_id"] not in transport_text
    assert "test-shield_component" not in transport_text
    assert '"signature"' not in transport_text
    assert '"public_key"' not in transport_text
    assert '"metadata"' not in transport_text
    assert '"freshness_nonce"' not in transport_text
    assert '"authority"' not in transport_text


def test_v410b_hash_domains_use_nfc_and_component_events_use_own_request() -> None:
    assert AUDIT_REQUEST_ID_HASH_DOMAIN == "DGB-SHIELD-V4-AUDIT-REQUEST-ID\n"
    assert AUDIT_KEY_ID_HASH_DOMAIN == "DGB-SHIELD-V4-AUDIT-KEY-ID\n"
    assert audit_request_id_hash("Cafe\u0301") == audit_request_id_hash("Caf\u00e9")
    assert audit_key_id_hash("Cle\u0301") == audit_key_id_hash("Cl\u00e9")

    receipt = copy.deepcopy(_fixture()["receipt"])
    component = receipt["component_verdicts"][0]
    component["request_id"] = "component-specific-request"

    # Re-sign only the modified component, then rebuild the outer receipt around it.
    from shield_orchestrator.v4.canonical_json import COMPONENT_VERDICT_DOMAIN, signed_payload_hash
    from shield_orchestrator.v4.component_verdicts import (
        build_test_component_signature_entry,
        unsigned_component_payload,
    )
    from shield_orchestrator.v4.contracts.v4_receipt import (
        build_signed_receipt_envelope,
        build_unsigned_receipt_payload,
    )
    from shield_orchestrator.v4.orchestrate import build_test_only_orchestrator_signature_entry
    from shield_orchestrator.v4.signature_bundle import build_signature_bundle

    payload = unsigned_component_payload(component)
    component_hash = signed_payload_hash(domain_tag=COMPONENT_VERDICT_DOMAIN, payload=payload)
    component.update(
        {
            "signed_payload_hash": component_hash,
            "signature_bundle": build_signature_bundle(
                policy_version="policy.v1",
                signatures=[
                    build_test_component_signature_entry(
                        component_id=component["component_id"],
                        algorithm=algorithm,
                        signed_hash=component_hash,
                    )
                    for algorithm in ("classical-ed25519", "ml-dsa")
                ],
            ),
        }
    )
    fixture = _fixture()
    registry = load_key_registry(fixture["trusted_key_registry"])
    from shield_orchestrator.v4.component_verdicts import verify_component_verdicts

    verified, summaries = verify_component_verdicts(
        receipt["component_verdicts"],
        expected_context_hash=fixture["expected_context_hash"],
        registry=registry,
        verification_time=fixture["verification_time"],
        verifier=verify_test_only_component_signature,
    )
    unsigned = build_unsigned_receipt_payload(
        request_id=receipt["request_id"],
        context_hash=receipt["context_hash"],
        freshness_nonce=receipt["freshness_nonce"],
        not_before=receipt["not_before"],
        not_after=receipt["not_after"],
        component_verdicts=verified,
        component_signature_results=summaries,
        final_outcome=receipt["final_outcome"],
        dominant_reason_ids=receipt["dominant_reason_ids"],
        key_registry_version=receipt["key_registry_version"],
        adamantineos_handoff=receipt["adamantineos_handoff"],
    )
    shell = build_signed_receipt_envelope(
        unsigned_payload=unsigned,
        signature_bundle=build_signature_bundle(
            policy_version="policy.v1",
            signatures=[
                build_test_only_orchestrator_signature_entry(
                    algorithm=algorithm,
                    signed_hash="0" * 64,
                )
                for algorithm in ("classical-ed25519", "ml-dsa")
            ],
        ),
    )
    signatures = [
        build_test_only_orchestrator_signature_entry(
            algorithm=algorithm,
            signed_hash=shell["signed_payload_hash"],
        )
        for algorithm in ("classical-ed25519", "ml-dsa")
    ]
    receipt = build_signed_receipt_envelope(
        unsigned_payload=unsigned,
        signature_bundle=build_signature_bundle(policy_version="policy.v1", signatures=signatures),
    )
    _, sink = _verify(receipt=receipt)
    events = _decode(sink.batches[0])
    adn_events = [event for event in events if event.get("artifact_id") == "adn"]
    assert adn_events
    assert {event["request_id_hash"] for event in adn_events} == {
        audit_request_id_hash("component-specific-request")
    }


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        (lambda receipt: receipt.__setitem__("context_hash", "b" * 64), V4_CONTEXT_MISMATCH),
        (lambda receipt: receipt.__setitem__("receipt_hash", "0" * 64), V4_HASH_MISMATCH),
        (lambda receipt: receipt.__setitem__("schema_version", "invalid"), V4_CONTRACT_INVALID),
    ],
)
def test_v410b_receipt_failures_commit_sanitized_terminal(
    mutation, expected_reason: str
) -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    mutation(receipt)
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=expected_reason) as error:
        _verify(receipt=receipt, sink=sink)
    assert error.value.__cause__ is None
    events = _decode(sink.batches[0])
    expected_event = (
        VERIFICATION_PREFLIGHT_EVENT
        if expected_reason in {V4_CONTEXT_MISMATCH, V4_HASH_MISMATCH, V4_CONTRACT_INVALID}
        else ARTIFACT_VERIFICATION_EVENT
    )
    assert events[-1]["event_type"] == expected_event
    assert events[-1]["reason_id"] == expected_reason
    assert events[-1]["verification_passed"] is False


def test_v410b_expected_request_and_registry_floor_fail_in_preflight_without_crypto() -> None:
    calls = 0

    def verifier(_entry, _key) -> bool:
        nonlocal calls
        calls += 1
        return True

    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_REQUEST_MISMATCH):
        _verify(expected_request_id="wrong-request", component_verifier=verifier, sink=sink)
    assert calls == 0
    assert _decode(sink.batches[0]) == [
        {**_decode(sink.batches[0])[0], "reason_id": V4_REQUEST_MISMATCH}
    ]

    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_REGISTRY_INVALID):
        _verify(minimum_registry_version=2, component_verifier=verifier, sink=sink)
    assert calls == 0
    event = _decode(sink.batches[0])[0]
    assert event["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert event["verification_passed"] is False
    assert event["reason_id"] == V4_REGISTRY_INVALID


def test_v410b_downgraded_outer_schema_is_single_terminal_preflight_before_crypto() -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    receipt["schema_version"] = "shield.receipt.v1"
    calls = 0

    def verifier(_entry, _key) -> bool:
        nonlocal calls
        calls += 1
        return True

    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=audit.V4_DOWNGRADE_REJECTED):
        _verify(receipt=receipt, component_verifier=verifier, sink=sink)
    assert calls == 0
    events = _decode(sink.batches[0])
    assert len(events) == 1
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[0]["verification_passed"] is False
    assert events[0]["reason_id"] == audit.V4_DOWNGRADE_REJECTED


def test_v410b_wrong_outer_policy_is_single_terminal_preflight_before_crypto() -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    receipt["signature_policy"] = "policy.v0"
    calls = 0

    def verifier(_entry, _key) -> bool:
        nonlocal calls
        calls += 1
        return True

    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=audit.V4_POLICY_INVALID):
        _verify(receipt=receipt, component_verifier=verifier, sink=sink)
    assert calls == 0
    events = _decode(sink.batches[0])
    assert len(events) == 1
    assert events[0]["reason_id"] == audit.V4_POLICY_INVALID
    assert events[0]["verification_passed"] is False


@pytest.mark.parametrize(
    ("result", "reason"),
    [(False, V4_SIGNATURE_INVALID), (1, V4_BACKEND_FAILURE)],
)
def test_v410b_component_backend_failure_is_recorded_without_raw_result(result, reason: str) -> None:
    sink = RecordingSink()

    def verifier(_entry, _key):
        return result

    with pytest.raises(ShieldV4VerificationError):
        _verify(component_verifier=verifier, sink=sink)
    events = _decode(sink.batches[0])
    assert events[1]["reason_id"] == reason
    assert events[1]["verification_passed"] is False
    assert events[-1]["reason_id"] == reason


def test_v410b_backend_exception_secret_never_escapes() -> None:
    sink = RecordingSink()

    def verifier(_entry, _key) -> bool:
        raise RuntimeError("TOP-SECRET-BACKEND-DIAGNOSTIC")

    with pytest.raises(ShieldV4VerificationError, match=V4_BACKEND_FAILURE) as error:
        _verify(component_verifier=verifier, sink=sink)
    assert error.value.__cause__ is None
    assert "TOP-SECRET" not in str(error.value)
    assert b"TOP-SECRET" not in b"\n".join(sink.batches[0])


@pytest.mark.parametrize(
    "ack",
    [
        None,
        {},
        {
            "schema_version": AUDIT_APPEND_ACK_SCHEMA_VERSION,
            "batch_sha256": "0" * 64,
            "record_count": 14,
            "durably_committed": True,
        },
        {
            "schema_version": AUDIT_APPEND_ACK_SCHEMA_VERSION,
            "batch_sha256": "0" * 64,
            "record_count": True,
            "durably_committed": True,
        },
        {
            "schema_version": AUDIT_APPEND_ACK_SCHEMA_VERSION,
            "batch_sha256": "0" * 64,
            "record_count": 14,
            "durably_committed": 1,
        },
    ],
)
def test_v410b_missing_or_malformed_ack_fails_closed_without_result(ack: Any) -> None:
    with pytest.raises(ShieldV4AuditSinkError, match="V4_AUDIT_SINK_FAILURE") as error:
        _verify(sink=BadSink(ack))
    assert error.value.__cause__ is None


def test_v410b_sink_exception_is_sanitized_and_has_no_cause() -> None:
    with pytest.raises(ShieldV4AuditSinkError, match="V4_AUDIT_SINK_FAILURE") as error:
        _verify(sink=BadSink(raises=True))
    assert error.value.__cause__ is None
    assert "SECRET" not in str(error.value)


@pytest.mark.parametrize("failure_surface", ["iteration", "getitem"])
def test_v410b_hostile_ack_object_is_fully_sanitized(failure_surface: str) -> None:
    class HostileAck(dict):
        def __iter__(self):
            if failure_surface == "iteration":
                raise RuntimeError("SECRET-ACK-ITER")
            return super().__iter__()

        def __getitem__(self, key):
            if failure_surface == "getitem":
                raise RuntimeError("SECRET-ACK-GET")
            return super().__getitem__(key)

    ack = HostileAck(
        {
            "schema_version": AUDIT_APPEND_ACK_SCHEMA_VERSION,
            "batch_sha256": "0" * 64,
            "record_count": 14,
            "durably_committed": True,
        }
    )
    with pytest.raises(ShieldV4AuditSinkError, match="V4_AUDIT_SINK_FAILURE") as error:
        _verify(sink=BadSink(ack))
    assert error.value.__cause__ is None
    assert "SECRET" not in str(error.value)
    assert type(ack) is not dict


@pytest.mark.parametrize(
    ("argument", "value", "message"),
    [
        ("artifact_transport_hash", "A" * 64, "artifact_transport_hash"),
        ("expected_context_hash", "x" * 64, "expected_context_hash"),
        ("minimum_registry_version", True, "minimum_registry_version"),
        ("verification_time", "2026-06-21T00:01:00.000Z", "verification_time"),
    ],
)
def test_v410b_trusted_boundary_argument_errors_are_programmer_errors(
    argument: str, value: Any, message: str
) -> None:
    fixture = _fixture()
    receipt = fixture["receipt"]
    kwargs = {
        "artifact_transport_hash": _transport_hash(receipt),
        "expected_context_hash": fixture["expected_context_hash"],
        "expected_request_id": fixture["expected_request_id"],
        "registry": load_key_registry(fixture["trusted_key_registry"]),
        "minimum_registry_version": 1,
        "verification_time": fixture["verification_time"],
        "component_verifier": verify_test_only_component_signature,
        "receipt_verifier": verify_test_only_orchestrator_signature,
        "audit_sink": RecordingSink(),
    }
    kwargs[argument] = value
    with pytest.raises(ValueError, match=message):
        verify_v4_receipt_with_audit(receipt, **kwargs)


def test_v410b_event_serializer_rejects_noncanonical_or_oversized_records() -> None:
    _, sink = _verify()
    event = _decode(sink.batches[0])[0]
    with pytest.raises(ValueError, match="exact schema"):
        serialize_audit_event({**event, "secret": "forbidden"})
    with pytest.raises(ValueError, match="immutable bytes"):
        audit_batch_sha256((bytearray(sink.batches[0][0]),))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="record count"):
        audit_batch_sha256(tuple())
    with pytest.raises(ValueError, match="record count"):
        audit_batch_sha256((sink.batches[0][0],) * (MAX_AUDIT_RECORDS + 1))
    with pytest.raises(ValueError, match="byte length"):
        audit_batch_sha256((b"x" * (MAX_AUDIT_RECORD_BYTES + 1),))
    with pytest.raises(ValueError, match="canonical UTF-8 JSON"):
        audit_batch_sha256((b"not-json",))
    with pytest.raises(ValueError, match="exact canonical"):
        audit_batch_sha256((json.dumps(event, indent=2).encode("utf-8"),))


def test_v410b_exact_union_validator_rejects_every_invalid_discriminator_and_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, sink = _verify()
    preflight, signature, artifact = _decode(sink.batches[0])[0:2] + [_decode(sink.batches[0])[-1]]

    cases = [
        (None, "must be dict"),
        ({**preflight, "schema_version": "wrong"}, "schema mismatch"),
        ({**preflight, "event_type": SIGNATURE_VERIFICATION_EVENT}, "exact schema"),
        ({**preflight, "verifier_id": "wrong"}, "verifier mismatch"),
        ({**preflight, "verification_passed": 1}, "exact bool"),
        ({**preflight, "reason_id": "UNKNOWN"}, "reason_id"),
        ({**preflight, "reason_id": V4_SIGNATURE_INVALID}, "must agree"),
        (
            {**preflight, "verification_passed": False, "reason_id": V4_VERIFY_OK},
            "must agree",
        ),
        ({**preflight, "artifact_type": "unknown"}, "artifact_type"),
        (
            {**preflight, "artifact_type": "component_verdict"},
            "preflight artifact_type",
        ),
        ({**preflight, "expected_artifact_schema_version": "wrong"}, "expected schema"),
        ({**preflight, "required_policy_version": "wrong"}, "preflight policy"),
        ({**signature, "extra": "forbidden"}, "signature event fields"),
        ({**signature, "artifact_type": "unknown"}, "unsupported audit artifact_type"),
        ({**artifact, "extra": "forbidden"}, "artifact event fields"),
        ({**artifact, "event_type": "unknown"}, "unsupported audit event_type"),
        ({**artifact, "artifact_schema_version": "wrong"}, "artifact schema"),
        ({**artifact, "artifact_id": ""}, "artifact_id"),
        ({**artifact, "artifact_id": "adn"}, "receipt audit artifact_id"),
        (
            {
                **signature,
                "artifact_type": "component_verdict",
                "artifact_schema_version": "shield.verdict.v2",
                "artifact_id": "unknown",
            },
            "component audit artifact_id",
        ),
        ({**artifact, "policy_version": "wrong"}, "audit policy"),
        ({**artifact, "registry_version": True}, "registry_version"),
        ({**signature, "key_version": 0}, "key_version"),
        ({**signature, "algorithm": "unknown"}, "unsupported Shield"),
        ({**signature, "standard_profile": "wrong"}, "standard_profile"),
    ]
    for value, message in cases:
        with pytest.raises(ValueError, match=message):
            serialize_audit_event(value)  # type: ignore[arg-type]

    bad_timestamp = {**preflight, "verification_timestamp": "2026-99-99T00:00:00Z"}
    with pytest.raises(ValueError, match="verification_time"):
        serialize_audit_event(bad_timestamp)
    with pytest.raises(ValueError, match="non-empty string"):
        audit_request_id_hash("")
    with pytest.raises(ValueError, match="non-empty string"):
        audit_key_id_hash(1)  # type: ignore[arg-type]

    monkeypatch.setattr(audit, "MAX_AUDIT_RECORD_BYTES", 1)
    with pytest.raises(ValueError, match="record exceeds"):
        serialize_audit_event(preflight)
    monkeypatch.setattr(audit, "MAX_AUDIT_RECORD_BYTES", MAX_AUDIT_RECORD_BYTES)
    monkeypatch.setattr(audit, "MAX_AUDIT_BATCH_BYTES", 1)
    with pytest.raises(ValueError, match="batch exceeds"):
        audit_batch_sha256((sink.batches[0][0],))


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("request mismatch", V4_REQUEST_MISMATCH),
        ("authority bypass", audit.V4_AUTHORITY_BYPASS),
        ("policy mismatch", audit.V4_POLICY_INVALID),
        ("registry mismatch", V4_REGISTRY_INVALID),
        ("freshness invalid", audit.V4_FRESHNESS_INVALID),
        ("signature bad", V4_SIGNATURE_INVALID),
        ("anything else", V4_CONTRACT_INVALID),
        ("context mismatch", V4_CONTEXT_MISMATCH),
    ],
)
def test_v410b_stable_error_classifier_has_no_raw_text(message: str, expected: str) -> None:
    assert audit._classify_error(ValueError(message), fallback=V4_CONTRACT_INVALID) == expected


def test_v410b_error_classifier_is_total_when_exception_stringification_fails() -> None:
    class HostileError(Exception):
        def __str__(self) -> str:
            raise RuntimeError("SECRET-ERROR-STRING")

    assert (
        audit._classify_error(HostileError(), fallback=V4_CONTRACT_INVALID)
        == V4_CONTRACT_INVALID
    )


def test_v410b_malformed_component_and_summary_fail_preflight_safely() -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    receipt["component_verdicts"] = receipt["component_verdicts"][:-1]
    _refresh_outer_hashes(receipt)
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        _verify(receipt=receipt, sink=sink)
    assert len(sink.batches[0]) == 1
    assert _decode(sink.batches[0])[0]["verification_passed"] is False

    receipt = copy.deepcopy(_fixture()["receipt"])
    receipt["component_signature_results"] = list(reversed(receipt["component_signature_results"]))
    _refresh_outer_hashes(receipt)
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        _verify(receipt=receipt, sink=sink)
    events = _decode(sink.batches[0])
    assert len(events) == 1
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[0]["reason_id"] == V4_CONTRACT_INVALID
    assert events[0]["verification_passed"] is False


@pytest.mark.parametrize("replacement", ["not-an-object", {"component_id": "unknown"}])
def test_v410b_non_object_or_unknown_component_is_audited_preflight_failure(
    replacement: Any,
) -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    receipt["component_verdicts"][0] = replacement
    _refresh_outer_hashes(receipt)
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        _verify(receipt=receipt, sink=sink)
    events = _decode(sink.batches[0])
    assert len(events) == 1
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[0]["verification_passed"] is False


def test_v410b_extra_outer_field_is_single_contract_preflight_failure() -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    receipt["unexpected_field"] = "forbidden"
    component_calls = 0

    def component_verifier(_entry, _key) -> bool:
        nonlocal component_calls
        component_calls += 1
        return True

    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        _verify(receipt=receipt, component_verifier=component_verifier, sink=sink)
    assert component_calls == 0
    events = _decode(sink.batches[0])
    assert len(events) == 1
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[0]["reason_id"] == V4_CONTRACT_INVALID
    assert events[0]["verification_passed"] is False


def test_v410b_receipt_semantic_failure_ends_in_validated_artifact_terminal() -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    receipt["final_outcome"] = "DENY"
    _refresh_outer_hashes(receipt)
    sink = RecordingSink()

    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        _verify(receipt=receipt, sink=sink)

    events = _decode(sink.batches[0])
    assert len(events) == 1
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[0]["reason_id"] == V4_CONTRACT_INVALID
    assert events[0]["verification_passed"] is False


def test_v410b_untrusted_bad_component_hash_is_not_promoted_to_artifact_event() -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    receipt["component_verdicts"][0]["signed_payload_hash"] = "0" * 64
    _refresh_outer_hashes(receipt)
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_HASH_MISMATCH):
        _verify(receipt=receipt, sink=sink)
    events = _decode(sink.batches[0])
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[0]["reason_id"] == V4_HASH_MISMATCH


@pytest.mark.parametrize(
    ("field", "value", "reason_id"),
    [
        ("context_hash", "b" * 64, V4_CONTEXT_MISMATCH),
        ("key_registry_version", 2, V4_REGISTRY_INVALID),
    ],
)
def test_v410b_component_binding_failures_stop_in_preflight(
    field: str,
    value: Any,
    reason_id: str,
) -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    receipt["component_verdicts"][0][field] = value
    _refresh_outer_hashes(receipt)
    calls = 0

    def verifier(_entry, _key) -> bool:
        nonlocal calls
        calls += 1
        return True

    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=reason_id):
        _verify(receipt=receipt, component_verifier=verifier, sink=sink)
    assert calls == 0
    events = _decode(sink.batches[0])
    assert len(events) == 1
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[0]["reason_id"] == reason_id
    assert events[0]["verification_passed"] is False


@pytest.mark.parametrize("component_index", [0, 1])
def test_v410b_component_bundle_shape_failure_has_safe_terminal_order(
    component_index: int,
) -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    receipt["component_verdicts"][component_index]["signature_bundle"][
        "schema_version"
    ] = "invalid"
    _refresh_outer_hashes(receipt)
    sink = RecordingSink()

    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        _verify(receipt=receipt, sink=sink)

    events = _decode(sink.batches[0])
    assert events[-1]["verification_passed"] is False
    assert events[-1]["reason_id"] == V4_CONTRACT_INVALID
    assert len(events) == 1
    assert events[-1]["event_type"] == VERIFICATION_PREFLIGHT_EVENT


def test_v410b_duplicate_component_identity_fails_preflight_before_crypto() -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    receipt["component_verdicts"][1]["component_id"] = "adn"
    _refresh_outer_hashes(receipt)
    calls = 0

    def verifier(_entry, _key) -> bool:
        nonlocal calls
        calls += 1
        return True

    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        _verify(receipt=receipt, component_verifier=verifier, sink=sink)
    assert calls == 0
    events = _decode(sink.batches[0])
    assert len(events) == 1
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[0]["reason_id"] == V4_CONTRACT_INVALID
    assert events[0]["verification_passed"] is False


def test_v410b_duplicate_id_never_aliases_attacker_hash_into_signature_event() -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    true_first_hash = receipt["component_verdicts"][0]["signed_payload_hash"]
    attacker_stale_hash = receipt["component_verdicts"][1]["signed_payload_hash"]
    assert attacker_stale_hash != true_first_hash
    receipt["component_verdicts"][1]["component_id"] = "adn"
    _refresh_outer_hashes(receipt)
    calls = 0

    def verifier(_entry, _key) -> bool:
        nonlocal calls
        calls += 1
        return True

    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        _verify(receipt=receipt, component_verifier=verifier, sink=sink)
    assert calls == 0
    events = _decode(sink.batches[0])
    assert len(events) == 1
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert not any(event["event_type"] == SIGNATURE_VERIFICATION_EVENT for event in events)
    assert not any(event.get("artifact_hash") == attacker_stale_hash for event in events)


def test_v410b_bad_outer_artifact_hash_uses_only_transport_preflight_fallback() -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    receipt["signed_payload_hash"] = "bad"
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_HASH_MISMATCH):
        _verify(receipt=receipt, sink=sink)
    events = _decode(sink.batches[0])
    assert events[-1]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[-1]["verification_passed"] is False


def test_v410b_valid_hex_but_unverified_outer_hash_is_never_promoted() -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    receipt["signed_payload_hash"] = "0" * 64
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_HASH_MISMATCH):
        _verify(receipt=receipt, sink=sink)
    events = _decode(sink.batches[0])
    assert events[-1]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[-1]["verification_passed"] is False
    assert events[-1]["reason_id"] == V4_HASH_MISMATCH
    assert not any(event.get("artifact_hash") == "0" * 64 for event in events)


@pytest.mark.parametrize("mutation", ["reverse_summaries", "duplicate_component"])
def test_v410b_alternate_failure_branches_never_promote_unverified_outer_hash(
    mutation: str,
) -> None:
    receipt = copy.deepcopy(_fixture()["receipt"])
    if mutation == "reverse_summaries":
        receipt["component_signature_results"] = list(
            reversed(receipt["component_signature_results"])
        )
    else:
        receipt["component_verdicts"][1]["component_id"] = "adn"
    receipt["signed_payload_hash"] = "0" * 64
    component_calls = 0

    def component_verifier(_entry, _key) -> bool:
        nonlocal component_calls
        component_calls += 1
        return True

    sink = RecordingSink()
    expected_reason = V4_CONTRACT_INVALID
    with pytest.raises(ShieldV4VerificationError, match=expected_reason):
        _verify(receipt=receipt, component_verifier=component_verifier, sink=sink)
    assert component_calls == 0
    events = _decode(sink.batches[0])
    assert len(events) == 1
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[0]["verification_passed"] is False
    assert events[0]["reason_id"] == expected_reason
    assert "artifact_hash" not in events[0]
    assert b"0" * 64 not in sink.batches[0][0]


def test_v410b_hostile_receipt_containers_are_sanitized_and_audited() -> None:
    class HostileReceipt(dict):
        def __iter__(self):
            raise RuntimeError("SECRET-RECEIPT-ITER")

    class HostileComponents(list):
        def __iter__(self):
            raise RuntimeError("SECRET-COMPONENT-ITER")

    fixture = _fixture()
    cases: list[dict[str, Any]] = [HostileReceipt(fixture["receipt"])]
    receipt = copy.deepcopy(fixture["receipt"])
    receipt["component_verdicts"] = HostileComponents(receipt["component_verdicts"])
    cases.append(receipt)

    for hostile in cases:
        sink = RecordingSink()
        transport_hash = hashlib.sha256(b"trusted-hostile-transport").hexdigest()
        fixture = _fixture()
        with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID) as error:
            verify_v4_receipt_with_audit(
                hostile,
                artifact_transport_hash=transport_hash,
                expected_context_hash=fixture["expected_context_hash"],
                expected_request_id=fixture["expected_request_id"],
                registry=load_key_registry(fixture["trusted_key_registry"]),
                minimum_registry_version=1,
                verification_time=fixture["verification_time"],
                component_verifier=verify_test_only_component_signature,
                receipt_verifier=verify_test_only_orchestrator_signature,
                audit_sink=sink,
            )
        assert error.value.__cause__ is None
        assert "SECRET" not in str(error.value)
        events = _decode(sink.batches[0])
        assert len(events) == 1
        assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
        assert events[0]["verification_passed"] is False
        assert events[0]["reason_id"] == V4_CONTRACT_INVALID


def test_v410b_nested_hostile_json_containers_are_sanitized_and_audited() -> None:
    class HostileError(Exception):
        def __str__(self) -> str:
            raise RuntimeError("SECRET-NESTED-ERROR-STRING")

    class HostileMap(dict):
        def items(self):
            raise HostileError()

    class HostileList(list):
        def __iter__(self):
            raise HostileError()

    fixture = _fixture()
    cases = []
    receipt = copy.deepcopy(fixture["receipt"])
    receipt["adamantineos_handoff"] = HostileMap(receipt["adamantineos_handoff"])
    cases.append(receipt)
    receipt = copy.deepcopy(fixture["receipt"])
    receipt["component_verdicts"][0]["metadata"]["nested"] = HostileList(["value"])
    cases.append(receipt)
    receipt = copy.deepcopy(fixture["receipt"])
    receipt["adamantineos_handoff"][1] = "non-string-key"
    cases.append(receipt)

    for hostile in cases:
        sink = RecordingSink()
        with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID) as error:
            _verify(
                receipt=hostile,
                artifact_transport_hash=hashlib.sha256(
                    b"trusted-nested-hostile-transport"
                ).hexdigest(),
                sink=sink,
            )
        assert error.value.__cause__ is None
        assert "SECRET" not in str(error.value)
        events = _decode(sink.batches[0])
        assert len(events) == 1
        assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
        assert events[0]["reason_id"] == V4_CONTRACT_INVALID
        assert events[0]["verification_passed"] is False


def test_v410b_hostile_scalar_subclass_is_rejected_before_artifact_extraction() -> None:
    class HostileString(str):
        def lower(self) -> str:
            raise RuntimeError("SECRET-SCALAR-LOWER")

    receipt = copy.deepcopy(_fixture()["receipt"])
    existing_hash = receipt["component_verdicts"][0]["signed_payload_hash"]
    receipt["component_verdicts"][0]["signed_payload_hash"] = HostileString(existing_hash)
    sink = RecordingSink()

    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID) as error:
        _verify(receipt=receipt, sink=sink)
    assert error.value.__cause__ is None
    assert "SECRET" not in str(error.value)
    events = _decode(sink.batches[0])
    assert len(events) == 1
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[0]["reason_id"] == V4_CONTRACT_INVALID
    assert events[0]["verification_passed"] is False


def test_v410b_receipt_signature_false_emits_failed_signature_and_terminal() -> None:
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_SIGNATURE_INVALID):
        _verify(receipt_verifier=lambda _entry, _key: False, sink=sink)
    events = _decode(sink.batches[0])
    assert events[-2]["event_type"] == SIGNATURE_VERIFICATION_EVENT
    assert events[-2]["verification_passed"] is False
    assert events[-1]["event_type"] == ARTIFACT_VERIFICATION_EVENT
    assert events[-1]["reason_id"] == V4_SIGNATURE_INVALID


def test_v410b_rejection_with_bad_sink_uses_dedicated_sink_error() -> None:
    with pytest.raises(ShieldV4AuditSinkError, match="V4_AUDIT_SINK_FAILURE"):
        _verify(expected_request_id="wrong", sink=BadSink(None))


@pytest.mark.parametrize("field", ["schema_version", "batch_sha256", "record_count"])
def test_v410b_ack_scalar_subclasses_are_rejected(field: str) -> None:
    class StringSubclass(str):
        pass

    class IntegerSubclass(int):
        pass

    class SubclassAckSink:
        def append_batch(self, records: tuple[bytes, ...]) -> dict[str, Any]:
            acknowledgement: dict[str, Any] = {
                "schema_version": AUDIT_APPEND_ACK_SCHEMA_VERSION,
                "batch_sha256": audit_batch_sha256(records),
                "record_count": len(records),
                "durably_committed": True,
            }
            if field == "record_count":
                acknowledgement[field] = IntegerSubclass(acknowledgement[field])
            else:
                acknowledgement[field] = StringSubclass(acknowledgement[field])
            return acknowledgement

    with pytest.raises(ShieldV4AuditSinkError, match="V4_AUDIT_SINK_FAILURE") as error:
        _verify(sink=SubclassAckSink())
    assert error.value.__cause__ is None


def test_v410b_loaded_registry_and_private_role_helpers_reject_invalid_input() -> None:
    fixture = _fixture()
    receipt = fixture["receipt"]
    with pytest.raises(ValueError, match="loaded KeyRegistry"):
        verify_v4_receipt_with_audit(
            receipt,
            artifact_transport_hash=_transport_hash(receipt),
            expected_context_hash=fixture["expected_context_hash"],
            expected_request_id=fixture["expected_request_id"],
            registry=fixture["trusted_key_registry"],  # type: ignore[arg-type]
            minimum_registry_version=1,
            verification_time=fixture["verification_time"],
            component_verifier=verify_test_only_component_signature,
            receipt_verifier=verify_test_only_orchestrator_signature,
            audit_sink=RecordingSink(),
        )
    key = load_key_registry(fixture["trusted_key_registry"]).entries[-1]
    object.__setattr__(key, "role", "unsupported")
    with pytest.raises(ValueError, match="unsupported component key role"):
        audit._component_id_for_key(key)


def test_v410b_non_mapping_receipt_is_audited_preflight_failure() -> None:
    fixture = _fixture()
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        verify_v4_receipt_with_audit(
            [],  # type: ignore[arg-type]
            artifact_transport_hash=hashlib.sha256(b"bounded-transport").hexdigest(),
            expected_context_hash=fixture["expected_context_hash"],
            expected_request_id=fixture["expected_request_id"],
            registry=load_key_registry(fixture["trusted_key_registry"]),
            minimum_registry_version=1,
            verification_time=fixture["verification_time"],
            component_verifier=verify_test_only_component_signature,
            receipt_verifier=verify_test_only_orchestrator_signature,
            audit_sink=sink,
        )
    event = _decode(sink.batches[0])[0]
    assert event["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert event["verification_passed"] is False
