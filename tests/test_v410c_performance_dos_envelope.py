from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import shield_orchestrator.v4.real_crypto_backend as real_backend
import shield_orchestrator.v4.verification_audit as audit
import shield_orchestrator.v4.work_budget as budget
from shield_orchestrator.v4.canonical_json import (
    ORCHESTRATOR_RECEIPT_DOMAIN,
    signed_payload_hash,
)
from shield_orchestrator.v4.contracts.v4_receipt import (
    UNSIGNED_RECEIPT_EXCLUDED_FIELDS,
    build_receipt_hash,
)
from shield_orchestrator.v4.key_registry import KeyRegistry, KeyRegistryEntry, load_key_registry
from shield_orchestrator.v4.verification_audit import (
    AUDIT_APPEND_ACK_SCHEMA_VERSION,
    SIGNATURE_VERIFICATION_EVENT,
    V4_AUTHORITY_BYPASS,
    V4_BACKEND_FAILURE,
    V4_CONTRACT_INVALID,
    V4_FRESHNESS_INVALID,
    V4_HASH_MISMATCH,
    V4_POLICY_INVALID,
    V4_REGISTRY_INVALID,
    V4_SIGNATURE_INVALID,
    VERIFICATION_PREFLIGHT_EVENT,
    ShieldV4VerificationError,
    audit_batch_sha256,
    verify_v4_receipt_with_audit,
)

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FIXTURE = ROOT / "tests/fixtures/v4/full_multi_repo_v4_allow_flow.json"
OPTIONAL_FIXTURE = ROOT / "tests/fixtures/v4/full_multi_repo_v4_fn_dsa_allow_flow.json"
FIXTURE_SHA256 = "279f69dce971d5695ff2ac61f3aca5921e9cd936e059405e79ece38824899ce9"


class RecordingSink:
    def __init__(self) -> None:
        self.batches: list[tuple[bytes, ...]] = []

    def append_batch(self, records: tuple[bytes, ...]) -> dict[str, Any]:
        self.batches.append(records)
        return {
            "schema_version": AUDIT_APPEND_ACK_SCHEMA_VERSION,
            "batch_sha256": audit_batch_sha256(records),
            "record_count": len(records),
            "durably_committed": True,
        }


def _fixture(path: Path = REQUIRED_FIXTURE) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _transport_hash(receipt: dict[str, Any]) -> str:
    encoded = json.dumps(
        receipt,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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


def _verify(
    fixture: dict[str, Any],
    *,
    receipt: dict[str, Any] | None = None,
    registry: KeyRegistry | None = None,
    component_verifier=None,
    receipt_verifier=None,
    transport_hash: str | None = None,
) -> tuple[dict[str, Any], RecordingSink]:
    checked_receipt = fixture["receipt"] if receipt is None else receipt
    sink = RecordingSink()
    allow = lambda _entry, _key: True
    result = verify_v4_receipt_with_audit(
        checked_receipt,
        artifact_transport_hash=(
            _transport_hash(checked_receipt) if transport_hash is None else transport_hash
        ),
        expected_context_hash=fixture["expected_context_hash"],
        expected_request_id=fixture["expected_request_id"],
        registry=(
            load_key_registry(fixture["trusted_key_registry"])
            if registry is None
            else registry
        ),
        minimum_registry_version=1,
        verification_time=fixture["verification_time"],
        component_verifier=allow if component_verifier is None else component_verifier,
        receipt_verifier=allow if receipt_verifier is None else receipt_verifier,
        audit_sink=sink,
    )
    return result, sink


def _decoded(sink: RecordingSink) -> list[dict[str, Any]]:
    return [json.loads(item.decode("utf-8")) for item in sink.batches[0]]


def _assert_rejects_without_payload_or_backend_work(
    *,
    fixture: dict[str, Any],
    receipt: dict[str, Any],
    registry: KeyRegistry,
    expected_reason: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload_work = 0
    backend_calls = 0

    def forbidden_payload_work(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal payload_work
        payload_work += 1
        raise AssertionError("payload canonical/hash work must not start")

    def verifier(_entry: dict[str, Any], _key: KeyRegistryEntry) -> bool:
        nonlocal backend_calls
        backend_calls += 1
        return True

    monkeypatch.setattr(budget, "to_canonical_json", forbidden_payload_work)
    monkeypatch.setattr(audit, "build_receipt_hash", forbidden_payload_work)
    monkeypatch.setattr(audit, "signed_payload_hash", forbidden_payload_work)
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=expected_reason):
        verify_v4_receipt_with_audit(
            receipt,
            artifact_transport_hash=hashlib.sha256(b"trusted-transport").hexdigest(),
            expected_context_hash=fixture["expected_context_hash"],
            expected_request_id=fixture["expected_request_id"],
            registry=registry,
            minimum_registry_version=1,
            verification_time=fixture["verification_time"],
            component_verifier=verifier,
            receipt_verifier=verifier,
            audit_sink=sink,
        )
    assert payload_work == 0
    assert backend_calls == 0
    events = _decoded(sink)
    assert len(events) == 1
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[0]["reason_id"] == expected_reason


def test_v410c_constants_and_required_fixture_are_frozen() -> None:
    assert hashlib.sha256(REQUIRED_FIXTURE.read_bytes()).hexdigest() == FIXTURE_SHA256
    assert budget.MAX_CANONICAL_RECEIPT_BYTES == 131_072
    assert budget.MAX_SNAPSHOT_SCALAR_BYTES == 131_072
    assert budget.MAX_TEXT_FIELD_BYTES == 8_192
    assert budget.MAX_SIGNATURE_BUNDLE_BYTES == 32_768
    assert budget.MAX_CONTAINER_DEPTH == 16
    assert budget.MAX_CONTAINER_NODES == 4_096
    assert budget.MAX_SIGNED_INTEGER_BITS == 64
    assert budget.EXPECTED_COMPONENT_BUNDLE_COUNT == 5
    assert budget.EXPECTED_RECEIPT_BUNDLE_COUNT == 1
    assert budget.MIN_SIGNATURES_PER_BUNDLE == 2
    assert budget.MAX_SIGNATURES_PER_BUNDLE == 3
    assert budget.MAX_SIGNATURE_BUNDLES == 6
    assert budget.MAX_VERIFICATION_CALLS == 18
    assert budget.MAX_PQC_VERIFICATION_CALLS == 12
    assert budget.MAX_TRUSTED_REGISTRY_ENTRIES == 64


def test_v410c_pinned_performance_assets_are_frozen() -> None:
    workflow = (ROOT / ".github/workflows/shield-v4-performance-dos.yml").read_text(
        encoding="utf-8"
    )
    script = (ROOT / "scripts/benchmark_v410c_verification.py").read_text(
        encoding="utf-8"
    )
    envelope = (
        ROOT / "docs/v4/SHIELD_V4_PERFORMANCE_DOS_ENVELOPE_V1.md"
    ).read_text(encoding="utf-8")
    compile(script, "scripts/benchmark_v410c_verification.py", "exec")
    for lock in (
        "runs-on: ubuntu-24.04",
        "timeout-minutes: 15",
        "python-version: \"3.11.15\"",
        "PYTHONHASHSEED: \"0\"",
        "TZ: UTC",
        "LC_ALL: C.UTF-8",
        "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
        "actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38",
        "pip==25.2",
        "setuptools==80.9.0",
        "wheel==0.45.1",
        "pytest==8.4.1",
        "pytest-cov==6.2.1",
    ):
        assert lock in workflow
    for lock in (
        'SCHEMA_VERSION = "shield-v4-v410c-performance-v1"',
        f'FIXTURE_SHA256 = "{FIXTURE_SHA256}"',
        "WARMUPS = 20",
        "SAMPLES = 200",
        '"packages": {package: version(package) for package in PINNED_PACKAGES}',
    ):
        assert lock in script
    assert "required-only audited verification     <= 50.0 ms" in envelope
    assert "oversize receipt rejection             <= 20.0 ms" in envelope


@pytest.mark.parametrize(
    ("fixture_path", "expected_calls", "expected_pqc"),
    [(REQUIRED_FIXTURE, 12, 6), (OPTIONAL_FIXTURE, 18, 12)],
)
def test_v410c_global_algorithm_waves_and_exact_call_ceilings(
    fixture_path: Path,
    expected_calls: int,
    expected_pqc: int,
) -> None:
    fixture = _fixture(fixture_path)
    calls: list[tuple[str, str]] = []

    def verifier(entry: dict[str, Any], key: KeyRegistryEntry) -> bool:
        calls.append((entry["algorithm"], key.role))
        return True

    _, sink = _verify(
        fixture,
        component_verifier=verifier,
        receipt_verifier=verifier,
    )
    expected_roles = [
        "shield_component_adn",
        "shield_component_dqsn",
        "shield_component_guardian_wallet",
        "shield_component_qwg",
        "shield_component_sentinel_ai",
        "shield_orchestrator",
    ]
    algorithms = ["classical-ed25519", "ml-dsa"]
    if expected_calls == 18:
        algorithms.append("fn-dsa")
    assert calls == [(algorithm, role) for algorithm in algorithms for role in expected_roles]
    assert len(calls) == expected_calls
    assert sum(algorithm != "classical-ed25519" for algorithm, _role in calls) == expected_pqc
    events = _decoded(sink)
    signature_events = [
        event for event in events if event["event_type"] == SIGNATURE_VERIFICATION_EVENT
    ]
    assert [event["algorithm"] for event in signature_events] == [item[0] for item in calls]
    assert len(events) == expected_calls + 2


def test_v410c_classical_failure_stops_before_every_pqc_callback() -> None:
    fixture = _fixture()
    calls: list[str] = []

    def verifier(entry: dict[str, Any], _key: KeyRegistryEntry) -> bool:
        calls.append(entry["algorithm"])
        return len(calls) < 4

    with pytest.raises(ShieldV4VerificationError, match=V4_SIGNATURE_INVALID):
        _verify(fixture, component_verifier=verifier, receipt_verifier=verifier)
    assert calls == ["classical-ed25519"] * 4


@pytest.mark.parametrize("bad_result", [1, "yes"])
def test_v410c_non_boolean_backend_result_fails_closed(bad_result: Any) -> None:
    fixture = _fixture()
    sink = RecordingSink()

    with pytest.raises(ShieldV4VerificationError, match=V4_BACKEND_FAILURE):
        verify_v4_receipt_with_audit(
            fixture["receipt"],
            artifact_transport_hash=_transport_hash(fixture["receipt"]),
            expected_context_hash=fixture["expected_context_hash"],
            expected_request_id=fixture["expected_request_id"],
            registry=load_key_registry(fixture["trusted_key_registry"]),
            minimum_registry_version=1,
            verification_time=fixture["verification_time"],
            component_verifier=lambda _entry, _key: bad_result,
            receipt_verifier=lambda _entry, _key: True,
            audit_sink=sink,
        )
    assert _decoded(sink)[1]["reason_id"] == V4_BACKEND_FAILURE


def test_v410c_backend_exception_fails_closed_without_pqc_rescue() -> None:
    fixture = _fixture()
    calls = 0

    def verifier(_entry: dict[str, Any], _key: KeyRegistryEntry) -> bool:
        nonlocal calls
        calls += 1
        raise RuntimeError("private provider diagnostic")

    with pytest.raises(ShieldV4VerificationError, match=V4_BACKEND_FAILURE) as error:
        _verify(fixture, component_verifier=verifier)
    assert calls == 1
    assert error.value.__cause__ is None
    assert "private" not in str(error.value)


@pytest.mark.parametrize(
    ("callback_result", "expected_reason", "expected_calls"),
    [
        ("true", None, 12),
        ("false", V4_SIGNATURE_INVALID, 1),
        ("raise", V4_BACKEND_FAILURE, 1),
    ],
)
def test_v410c_backend_callback_cannot_mutate_planned_entry_or_key(
    callback_result: str,
    expected_reason: str | None,
    expected_calls: int,
) -> None:
    fixture = _fixture()
    original_entry = copy.deepcopy(
        fixture["receipt"]["component_verdicts"][0]["signature_bundle"][
            "signatures"
        ][0]
    )
    original_key_id = original_entry["key_id"]
    calls = 0

    def verifier(entry: dict[str, Any], key: KeyRegistryEntry) -> bool:
        nonlocal calls
        calls += 1
        entry.clear()
        object.__setattr__(key, "key_id", "evil-mutated-key")
        if callback_result == "raise":
            raise RuntimeError("hostile callback")
        return callback_result == "true"

    sink = RecordingSink()
    kwargs = {
        "artifact_transport_hash": _transport_hash(fixture["receipt"]),
        "expected_context_hash": fixture["expected_context_hash"],
        "expected_request_id": fixture["expected_request_id"],
        "registry": load_key_registry(fixture["trusted_key_registry"]),
        "minimum_registry_version": 1,
        "verification_time": fixture["verification_time"],
        "component_verifier": verifier,
        "receipt_verifier": verifier,
        "audit_sink": sink,
    }
    if expected_reason is None:
        checked = verify_v4_receipt_with_audit(fixture["receipt"], **kwargs)
        assert (
            checked["component_verdicts"][0]["signature_bundle"]["signatures"][0]
            == original_entry
        )
    else:
        with pytest.raises(ShieldV4VerificationError, match=expected_reason):
            verify_v4_receipt_with_audit(fixture["receipt"], **kwargs)
    assert calls == expected_calls
    assert (
        fixture["receipt"]["component_verdicts"][0]["signature_bundle"][
            "signatures"
        ][0]
        == original_entry
    )
    signature_events = [
        event
        for event in _decoded(sink)
        if event["event_type"] == SIGNATURE_VERIFICATION_EVENT
    ]
    assert signature_events[0]["key_id_hash"] == audit.audit_key_id_hash(
        original_key_id
    )
    assert signature_events[0]["algorithm"] == "classical-ed25519"


def _bad_receipts() -> list[tuple[dict[str, Any], str]]:
    fixture = _fixture()
    output: list[tuple[dict[str, Any], str]] = []

    receipt = copy.deepcopy(fixture["receipt"])
    receipt["component_verdicts"][0]["metadata"]["oversize"] = "x" * 8_193
    output.append((receipt, V4_CONTRACT_INVALID))

    receipt = copy.deepcopy(fixture["receipt"])
    receipt["component_verdicts"][0]["signature_bundle"]["signatures"] *= 2
    output.append((receipt, V4_CONTRACT_INVALID))

    receipt = copy.deepcopy(fixture["receipt"])
    receipt["component_verdicts"][0]["signature_bundle"]["signatures"][0][
        "algorithm"
    ] = "unknown"
    _refresh_outer_hashes(receipt)
    output.append((receipt, V4_POLICY_INVALID))

    receipt = copy.deepcopy(fixture["receipt"])
    receipt["component_verdicts"][0]["signature_bundle"]["signatures"][0][
        "standard_profile"
    ] = "unknown"
    _refresh_outer_hashes(receipt)
    output.append((receipt, V4_POLICY_INVALID))

    receipt = copy.deepcopy(fixture["receipt"])
    receipt["component_verdicts"][0]["signature_bundle"]["signatures"][0][
        "signed_payload_hash"
    ] = "not-a-hash"
    _refresh_outer_hashes(receipt)
    output.append((receipt, V4_HASH_MISMATCH))

    receipt = copy.deepcopy(fixture["receipt"])
    receipt["component_verdicts"][0]["signature_bundle"]["signatures"][0][
        "key_version"
    ] = 0
    _refresh_outer_hashes(receipt)
    output.append((receipt, V4_REGISTRY_INVALID))
    return output


@pytest.mark.parametrize(("receipt", "expected_reason"), _bad_receipts())
def test_v410c_every_cheap_malformed_case_has_zero_backend_calls(
    receipt: dict[str, Any],
    expected_reason: str,
) -> None:
    fixture = _fixture()
    calls = 0

    def verifier(_entry: dict[str, Any], _key: KeyRegistryEntry) -> bool:
        nonlocal calls
        calls += 1
        return True

    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=expected_reason):
        verify_v4_receipt_with_audit(
            receipt,
            artifact_transport_hash=hashlib.sha256(b"trusted-transport").hexdigest(),
            expected_context_hash=fixture["expected_context_hash"],
            expected_request_id=fixture["expected_request_id"],
            registry=load_key_registry(fixture["trusted_key_registry"]),
            minimum_registry_version=1,
            verification_time=fixture["verification_time"],
            component_verifier=verifier,
            receipt_verifier=verifier,
            audit_sink=sink,
        )
    assert calls == 0
    events = _decoded(sink)
    assert len(events) == 1
    assert events[0]["event_type"] == VERIFICATION_PREFLIGHT_EVENT
    assert events[0]["reason_id"] == expected_reason


@pytest.mark.parametrize("failure_kind", ["late_bundle", "late_registry"])
def test_v410c_all_cheap_preflight_finishes_before_payload_canonical_or_hash_work(
    failure_kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    raw_registry = copy.deepcopy(fixture["trusted_key_registry"])
    expected_reason = V4_POLICY_INVALID
    if failure_kind == "late_bundle":
        receipt["signature_bundle"]["signatures"][-1]["standard_profile"] = (
            "unknown-profile"
        )
    else:
        expected_reason = V4_REGISTRY_INVALID
        for entry in raw_registry["entries"]:
            if (
                entry["role"] == "shield_orchestrator"
                and entry["algorithm"] == "ml-dsa"
            ):
                entry["status"] = "revoked"
                break

    _assert_rejects_without_payload_or_backend_work(
        fixture=fixture,
        receipt=receipt,
        registry=load_key_registry(raw_registry),
        expected_reason=expected_reason,
        monkeypatch=monkeypatch,
    )


@pytest.mark.parametrize(
    ("failure_kind", "expected_reason"),
    [
        ("late_summary", V4_REGISTRY_INVALID),
        ("final_outcome", V4_CONTRACT_INVALID),
        ("handoff_authority", V4_AUTHORITY_BYPASS),
    ],
)
def test_v410c_outer_semantics_reject_before_payload_canonical_or_hash_work(
    failure_kind: str,
    expected_reason: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    if failure_kind == "late_summary":
        receipt["component_signature_results"][-1]["component_role"] = "wrong"
    elif failure_kind == "final_outcome":
        receipt["final_outcome"] = "DENY"
    else:
        receipt["adamantineos_handoff"]["execute"] = True
    _assert_rejects_without_payload_or_backend_work(
        fixture=fixture,
        receipt=receipt,
        registry=load_key_registry(fixture["trusted_key_registry"]),
        expected_reason=expected_reason,
        monkeypatch=monkeypatch,
    )


def test_v410c_valid_shape_but_bundle_inconsistent_summary_rejects_before_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    summary = receipt["component_signature_results"][-1]
    summary["verified_algorithms"].append("fn-dsa")
    summary["verified_standard_profiles"].append(
        "fips206-draft-falcon1024-v1"
    )
    _assert_rejects_without_payload_or_backend_work(
        fixture=fixture,
        receipt=receipt,
        registry=load_key_registry(fixture["trusted_key_registry"]),
        expected_reason=V4_CONTRACT_INVALID,
        monkeypatch=monkeypatch,
    )


@pytest.mark.parametrize(
    "failure_kind",
    ["expired_receipt", "future_receipt", "late_component"],
)
def test_v410c_artifact_freshness_rejects_before_payload_or_backend_work(
    failure_kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    if failure_kind == "expired_receipt":
        receipt["not_after"] = "2026-06-21T00:01:00Z"
    elif failure_kind == "future_receipt":
        receipt["not_before"] = "2026-06-21T00:03:00Z"
    else:
        receipt["component_verdicts"][-1]["not_after"] = "2026-06-21T00:01:00Z"
    _assert_rejects_without_payload_or_backend_work(
        fixture=fixture,
        receipt=receipt,
        registry=load_key_registry(fixture["trusted_key_registry"]),
        expected_reason=V4_FRESHNESS_INVALID,
        monkeypatch=monkeypatch,
    )


@pytest.mark.parametrize(
    ("invalid_signature", "expected_reason"),
    [("", V4_SIGNATURE_INVALID), (" " * 8_193, V4_CONTRACT_INVALID)],
)
def test_v410c_empty_or_oversize_whitespace_signature_rejects_before_payload_work(
    invalid_signature: str,
    expected_reason: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    receipt["signature_bundle"]["signatures"][-1]["signature"] = invalid_signature
    _assert_rejects_without_payload_or_backend_work(
        fixture=fixture,
        receipt=receipt,
        registry=load_key_registry(fixture["trusted_key_registry"]),
        expected_reason=expected_reason,
        monkeypatch=monkeypatch,
    )


@pytest.mark.parametrize(
    ("field", "value", "expected_reason"),
    [
        ("contract_version", 3, V4_CONTRACT_INVALID),
        ("canonicalization_profile", "unknown", V4_POLICY_INVALID),
        ("fail_closed", False, V4_CONTRACT_INVALID),
        ("key_registry_version", 2, V4_REGISTRY_INVALID),
    ],
)
def test_v410c_outer_contract_state_rejects_before_payload_or_backend_work(
    field: str,
    value: Any,
    expected_reason: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    receipt[field] = value
    _assert_rejects_without_payload_or_backend_work(
        fixture=fixture,
        receipt=receipt,
        registry=load_key_registry(fixture["trusted_key_registry"]),
        expected_reason=expected_reason,
        monkeypatch=monkeypatch,
    )


def test_v410c_non_mapping_signature_entry_rejects_before_payload_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    receipt["component_verdicts"][0]["signature_bundle"]["signatures"][0] = (
        "not-an-entry"
    )
    _assert_rejects_without_payload_or_backend_work(
        fixture=fixture,
        receipt=receipt,
        registry=load_key_registry(fixture["trusted_key_registry"]),
        expected_reason=V4_SIGNATURE_INVALID,
        monkeypatch=monkeypatch,
    )


def test_v410c_non_string_signature_rejects_before_payload_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    receipt["signature_bundle"]["signatures"][-1]["signature"] = 1
    _assert_rejects_without_payload_or_backend_work(
        fixture=fixture,
        receipt=receipt,
        registry=load_key_registry(fixture["trusted_key_registry"]),
        expected_reason=V4_SIGNATURE_INVALID,
        monkeypatch=monkeypatch,
    )


@pytest.mark.parametrize("surrogate_location", ["value", "key"])
def test_v410c_invalid_utf8_receipt_rejects_without_payload_or_backend_work(
    surrogate_location: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    metadata = receipt["component_verdicts"][0]["metadata"]
    if surrogate_location == "value":
        metadata["invalid_utf8"] = "\ud800"
    else:
        metadata["\ud800"] = "invalid_utf8"
    _assert_rejects_without_payload_or_backend_work(
        fixture=fixture,
        receipt=receipt,
        registry=load_key_registry(fixture["trusted_key_registry"]),
        expected_reason=V4_CONTRACT_INVALID,
        monkeypatch=monkeypatch,
    )


def test_v410c_canonical_receipt_expansion_rejects_before_hash_or_crypto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    metadata = receipt["component_verdicts"][0]["metadata"]
    for index in range(8):
        metadata[f"escape_padding_{index}"] = "\x01" * 8_192

    hash_calls = 0
    backend_calls = 0

    def forbidden_hash(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal hash_calls
        hash_calls += 1
        raise AssertionError("hash work must not start after canonical budget failure")

    def verifier(_entry: dict[str, Any], _key: KeyRegistryEntry) -> bool:
        nonlocal backend_calls
        backend_calls += 1
        return True

    monkeypatch.setattr(audit, "build_receipt_hash", forbidden_hash)
    monkeypatch.setattr(audit, "signed_payload_hash", forbidden_hash)
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        verify_v4_receipt_with_audit(
            receipt,
            artifact_transport_hash=hashlib.sha256(b"trusted-transport").hexdigest(),
            expected_context_hash=fixture["expected_context_hash"],
            expected_request_id=fixture["expected_request_id"],
            registry=load_key_registry(fixture["trusted_key_registry"]),
            minimum_registry_version=1,
            verification_time=fixture["verification_time"],
            component_verifier=verifier,
            receipt_verifier=verifier,
            audit_sink=sink,
        )
    assert hash_calls == 0
    assert backend_calls == 0
    assert _decoded(sink)[0]["reason_id"] == V4_CONTRACT_INVALID


def test_v410c_signature_and_public_key_exact_text_boundary_is_accepted() -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    receipt["signature_bundle"]["signatures"][-1]["signature"] = "s" * 8_192
    raw_registry = copy.deepcopy(fixture["trusted_key_registry"])
    for entry in raw_registry["entries"]:
        if (
            entry["role"] == "shield_orchestrator"
            and entry["algorithm"] == "ml-dsa"
        ):
            entry["public_key"] = "p" * 8_192
            break
    checked, _sink = _verify(
        fixture,
        receipt=receipt,
        registry=load_key_registry(raw_registry),
    )
    assert checked["signature_bundle"]["signatures"][-1]["signature"] == "s" * 8_192


@pytest.mark.parametrize("oversize_field", ["signature", "public_key"])
def test_v410c_signature_and_public_key_oversize_reject_without_payload_work(
    oversize_field: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    raw_registry = copy.deepcopy(fixture["trusted_key_registry"])
    if oversize_field == "signature":
        receipt["signature_bundle"]["signatures"][-1]["signature"] = "s" * 8_193
    else:
        for entry in raw_registry["entries"]:
            if (
                entry["role"] == "shield_orchestrator"
                and entry["algorithm"] == "ml-dsa"
            ):
                entry["public_key"] = "p" * 8_193
                break

    payload_work = 0
    backend_calls = 0

    def forbidden_payload_work(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal payload_work
        payload_work += 1
        raise AssertionError("payload canonical/hash work must not start")

    def verifier(_entry: dict[str, Any], _key: KeyRegistryEntry) -> bool:
        nonlocal backend_calls
        backend_calls += 1
        return True

    monkeypatch.setattr(budget, "to_canonical_json", forbidden_payload_work)
    monkeypatch.setattr(audit, "build_receipt_hash", forbidden_payload_work)
    monkeypatch.setattr(audit, "signed_payload_hash", forbidden_payload_work)
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        verify_v4_receipt_with_audit(
            receipt,
            artifact_transport_hash=hashlib.sha256(b"trusted-transport").hexdigest(),
            expected_context_hash=fixture["expected_context_hash"],
            expected_request_id=fixture["expected_request_id"],
            registry=load_key_registry(raw_registry),
            minimum_registry_version=1,
            verification_time=fixture["verification_time"],
            component_verifier=verifier,
            receipt_verifier=verifier,
            audit_sink=sink,
        )
    assert payload_work == 0
    assert backend_calls == 0
    assert _decoded(sink)[0]["reason_id"] == V4_CONTRACT_INVALID


def test_v410c_duplicate_optional_algorithm_cannot_multiply_work() -> None:
    fixture = _fixture(OPTIONAL_FIXTURE)
    receipt = copy.deepcopy(fixture["receipt"])
    entries = receipt["component_verdicts"][0]["signature_bundle"]["signatures"]
    entries[1] = copy.deepcopy(entries[2])
    _refresh_outer_hashes(receipt)
    calls = 0

    def verifier(_entry: dict[str, Any], _key: KeyRegistryEntry) -> bool:
        nonlocal calls
        calls += 1
        return True

    with pytest.raises(ShieldV4VerificationError, match=V4_POLICY_INVALID):
        _verify(fixture, receipt=receipt, component_verifier=verifier)
    assert calls == 0


def test_v410c_bundle_and_registry_overcounts_reject_before_callbacks() -> None:
    fixture = _fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    bundle = receipt["component_verdicts"][0]["signature_bundle"]
    for entry in bundle["signatures"]:
        entry["signature"] = "s" * 8_192
        entry["key_id"] = "k" * 8_192
    calls = 0

    def verifier(_entry: dict[str, Any], _key: KeyRegistryEntry) -> bool:
        nonlocal calls
        calls += 1
        return True

    with pytest.raises(ShieldV4VerificationError, match=V4_REGISTRY_INVALID):
        _verify(fixture, receipt=receipt, component_verifier=verifier)

    loaded = load_key_registry(fixture["trusted_key_registry"])
    oversized_registry = KeyRegistry(
        schema_version=loaded.schema_version,
        registry_version=loaded.registry_version,
        entries=(loaded.entries[0],) * 65,
    )
    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        _verify(fixture, registry=oversized_registry, component_verifier=verifier)
    assert calls == 0


def test_v410c_hostile_registry_subclass_rejects_without_attribute_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    payload_work = 0
    backend_calls = 0

    class HostileRegistry(KeyRegistry):
        def __getattribute__(self, _name: str) -> Any:
            raise AssertionError("hostile registry attribute access must not run")

    hostile_registry = object.__new__(HostileRegistry)

    def forbidden_payload_work(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal payload_work
        payload_work += 1
        raise AssertionError("payload canonical/hash work must not start")

    def verifier(_entry: dict[str, Any], _key: KeyRegistryEntry) -> bool:
        nonlocal backend_calls
        backend_calls += 1
        return True

    monkeypatch.setattr(budget, "to_canonical_json", forbidden_payload_work)
    monkeypatch.setattr(audit, "build_receipt_hash", forbidden_payload_work)
    monkeypatch.setattr(audit, "signed_payload_hash", forbidden_payload_work)
    sink = RecordingSink()
    with pytest.raises(ValueError, match="loaded KeyRegistry"):
        verify_v4_receipt_with_audit(
            fixture["receipt"],
            artifact_transport_hash=_transport_hash(fixture["receipt"]),
            expected_context_hash=fixture["expected_context_hash"],
            expected_request_id=fixture["expected_request_id"],
            registry=hostile_registry,
            minimum_registry_version=1,
            verification_time=fixture["verification_time"],
            component_verifier=verifier,
            receipt_verifier=verifier,
            audit_sink=sink,
        )
    assert payload_work == 0
    assert backend_calls == 0
    assert sink.batches == []


@pytest.mark.parametrize("invalid_floor", [True, 1 << 63])
def test_v410c_registry_floor_precondition_is_positive_signed64_before_audit(
    invalid_floor: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    payload_work = 0
    backend_calls = 0

    def forbidden_payload_work(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal payload_work
        payload_work += 1
        raise AssertionError("payload canonical/hash work must not start")

    def verifier(_entry: dict[str, Any], _key: KeyRegistryEntry) -> bool:
        nonlocal backend_calls
        backend_calls += 1
        return True

    monkeypatch.setattr(budget, "to_canonical_json", forbidden_payload_work)
    monkeypatch.setattr(audit, "build_receipt_hash", forbidden_payload_work)
    monkeypatch.setattr(audit, "signed_payload_hash", forbidden_payload_work)
    sink = RecordingSink()
    with pytest.raises(ValueError, match="positive signed 64-bit"):
        verify_v4_receipt_with_audit(
            fixture["receipt"],
            artifact_transport_hash=_transport_hash(fixture["receipt"]),
            expected_context_hash=fixture["expected_context_hash"],
            expected_request_id=fixture["expected_request_id"],
            registry=load_key_registry(fixture["trusted_key_registry"]),
            minimum_registry_version=invalid_floor,
            verification_time=fixture["verification_time"],
            component_verifier=verifier,
            receipt_verifier=verifier,
            audit_sink=sink,
        )
    assert payload_work == 0
    assert backend_calls == 0
    assert sink.batches == []


def test_v410c_bounded_snapshot_counts_all_json_scalars_and_rejects_graph_attacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        budget,
        "to_canonical_json",
        lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")),
    )
    snapshot = budget.snapshot_bounded_receipt({"a": [None, True, False, 1, ""]})
    assert snapshot.node_count == 7
    assert snapshot.scalar_bytes == 15
    empty_snapshot = budget.snapshot_bounded_receipt({"": ""})
    assert empty_snapshot.value == {"": ""}
    assert empty_snapshot.scalar_bytes == 0
    assert budget.require_canonical_receipt_budget(snapshot.value) == len(
        b'{"a":[null,true,false,1,""]}'
    )
    monkeypatch.undo()

    cyclic: dict[str, Any] = {}
    cyclic["cycle"] = cyclic
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="acyclic"):
        budget.snapshot_bounded_receipt(cyclic)
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="exact JSON"):
        budget.snapshot_bounded_receipt({"bad": 1.5})
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="exact dict"):
        budget.snapshot_bounded_receipt([])
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="valid UTF-8"):
        budget.require_bounded_text("\ud800", field="invalid")
    for invalid_utf8 in ({"bad": "\ud800"}, {"\ud800": "bad"}):
        with pytest.raises(budget.ShieldV4WorkBudgetError, match="valid UTF-8"):
            budget.snapshot_bounded_receipt(invalid_utf8)
    for hostile_integer in (1 << 63, -(1 << 63) - 1):
        with pytest.raises(budget.ShieldV4WorkBudgetError, match="64-bit"):
            budget.snapshot_bounded_receipt({"bad": hostile_integer})

    class HostileDict(dict):
        def __iter__(self):
            raise AssertionError("dict subclass iterator must not run")

        def get(self, *_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("dict subclass get must not run")

        def items(self):
            raise AssertionError("dict subclass items must not run")

    class HostileList(list):
        def __iter__(self):
            raise AssertionError("list subclass iterator must not run")

    for hostile_container in (HostileDict({"a": 1}), HostileList([1])):
        with pytest.raises(budget.ShieldV4WorkBudgetError, match="exact JSON"):
            budget.snapshot_bounded_receipt(hostile_container)

    monkeypatch.setattr(budget, "MAX_CONTAINER_DEPTH", 2)
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="depth"):
        budget.snapshot_bounded_receipt({"a": [[]]})
    monkeypatch.setattr(budget, "MAX_CONTAINER_DEPTH", 16)
    monkeypatch.setattr(budget, "MAX_CONTAINER_NODES", 2)
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="node"):
        budget.snapshot_bounded_receipt({"a": [None]})
    monkeypatch.setattr(budget, "MAX_CONTAINER_NODES", 4_096)
    monkeypatch.setattr(budget, "MAX_SNAPSHOT_SCALAR_BYTES", 1)
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="scalar"):
        budget.snapshot_bounded_receipt({"aa": ""})
    monkeypatch.setattr(budget, "MAX_SNAPSHOT_SCALAR_BYTES", 131_072)
    monkeypatch.setattr(budget, "MAX_CANONICAL_RECEIPT_BYTES", 1)
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="canonical"):
        budget.require_canonical_receipt_budget(
            budget.snapshot_bounded_receipt({"a": "b"}).value
        )


def test_v410c_text_bundle_and_count_guards_cover_exact_failure_classes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert budget.require_bounded_text("", field="x", allow_empty=True) == ""
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="exact non-empty"):
        budget.require_bounded_text("", field="x")
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="exact non-empty"):
        budget.require_bounded_text(1, field="x")
    monkeypatch.setattr(budget, "MAX_TEXT_FIELD_BYTES", 2)
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="byte budget"):
        budget.require_bounded_text("xxx", field="x")
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="byte budget"):
        budget.require_bounded_text("ee".replace("e", "\u00e9"), field="x")
    monkeypatch.setattr(budget, "MAX_TEXT_FIELD_BYTES", 8_192)

    valid_bundle = {"signatures": [{}, {}]}
    assert budget.require_signature_bundle_budget(valid_bundle) is valid_bundle
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="exact dict"):
        budget.require_signature_bundle_budget([])
    for signatures in ([], [{}], [{}, {}, {}, {}]):
        with pytest.raises(budget.ShieldV4WorkBudgetError, match="count"):
            budget.require_signature_bundle_budget({"signatures": signatures})
    monkeypatch.setattr(budget, "MAX_SIGNATURE_BUNDLE_BYTES", 1)
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="canonical"):
        budget.require_canonical_signature_bundle_budget(valid_bundle)

    budget.require_complete_bundle_count(component_count=5, receipt_count=1)
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="exact integers"):
        budget.require_complete_bundle_count(component_count=True, receipt_count=1)
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="five"):
        budget.require_complete_bundle_count(component_count=4, receipt_count=1)
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="one receipt"):
        budget.require_complete_bundle_count(component_count=5, receipt_count=2)


def test_v410c_plan_and_runtime_counters_enforce_total_and_pqc_caps() -> None:
    budget.require_planned_call_budget(("classical-ed25519", "ml-dsa"))
    for invalid in (["ml-dsa"], (1,)):
        with pytest.raises(budget.ShieldV4WorkBudgetError, match="exact tuple"):
            budget.require_planned_call_budget(invalid)  # type: ignore[arg-type]
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="callback"):
        budget.require_planned_call_budget(("classical-ed25519",) * 19)
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="PQC"):
        budget.require_planned_call_budget(("ml-dsa",) * 13)
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="unsupported"):
        budget.require_planned_call_budget(("unknown",))

    total = budget.VerificationWorkCounter()
    for _ in range(18):
        total.record_callback_attempt("classical-ed25519")
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="callback"):
        total.record_callback_attempt("classical-ed25519")
    pqc = budget.VerificationWorkCounter()
    for _ in range(12):
        pqc.record_callback_attempt("ml-dsa")
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="PQC"):
        pqc.record_callback_attempt("fn-dsa")
    with pytest.raises(budget.ShieldV4WorkBudgetError, match="unsupported"):
        budget.VerificationWorkCounter().record_callback_attempt("unknown")


def test_v410c_real_backend_rejects_encoded_oversize_before_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_decode(_value: str) -> bytes:
        raise AssertionError("decoder must not run")

    monkeypatch.setattr(real_backend.base64, "urlsafe_b64decode", forbidden_decode)
    with pytest.raises(real_backend.ShieldV4RealCryptoBackendError, match="byte limit"):
        real_backend.decode_binary_signature_material("b64u:" + "A" * 8_192)
    with pytest.raises(real_backend.ShieldV4RealCryptoBackendError, match="byte limit"):
        real_backend.decode_binary_signature_material("\u00e9" * 8_192)
    with pytest.raises(real_backend.ShieldV4RealCryptoBackendError, match="valid UTF-8"):
        real_backend.decode_binary_signature_material("\ud800")
    with pytest.raises(real_backend.ShieldV4RealCryptoBackendError, match="byte limit"):
        real_backend.encode_binary_signature_material(b"x" * 6_141)


def _plan(
    *, artifact_id: str, entry: dict[str, Any], key: KeyRegistryEntry
) -> audit._PlannedVerification:
    artifact = {"artifact_id": artifact_id}
    return audit._PlannedVerification(
        artifact_id=artifact_id,
        artifact=artifact,
        entry=entry,
        key=key,
        verifier=lambda _entry, _key: True,
        verifier_kind="component",
    )


def _prehashed_plan(
    *, artifact_id: str, entry: dict[str, Any], key: KeyRegistryEntry
) -> audit._PrehashedVerification:
    return audit._PrehashedVerification(
        artifact_id=artifact_id,
        entry=entry,
        key=key,
        verifier=lambda _entry, _key: True,
        verifier_kind="component",
    )


def test_v410c_private_plan_and_cache_guards_reject_internal_duplicates() -> None:
    key = KeyRegistryEntry(
        role="shield_component_adn",
        key_id="key",
        key_version=1,
        algorithm="classical-ed25519",
        not_before="2026-01-01T00:00:00Z",
        not_after="2030-01-01T00:00:00Z",
        status="active",
        public_key="public",
    )
    with pytest.raises(ValueError, match="all six"):
        audit._validate_complete_plan([_plan(artifact_id="adn", entry={}, key=key)])

    artifacts = [*audit.SUPPORTED_COMPONENTS, audit.ORCHESTRATOR_ARTIFACT_ID]
    shared_entry: dict[str, Any] = {}
    plans = [
        _plan(artifact_id=artifact, entry=shared_entry, key=key)
        for artifact in artifacts
        for _ in range(2)
    ]
    with pytest.raises(ValueError, match="duplicate"):
        audit._validate_complete_plan(plans)

    unique_plans = [
        _plan(artifact_id=artifact, entry={"n": index}, key=key)
        for index, artifact in enumerate(artifacts)
        for _ in range(2)
    ]
    unique_plans.pop()
    with pytest.raises(ValueError, match="signature count"):
        audit._validate_complete_plan(unique_plans)

    remaining: set[tuple[Any, ...]] = set()
    cached = audit._make_cached_verifier(verifier_kind="component", remaining=remaining)
    assert cached({}, key) is False
    with pytest.raises(ValueError, match="signed 64-bit"):
        audit._require_signed_positive_int(0, field="value")


def test_v410c_private_prehash_and_registry_guards_cover_defensive_boundaries() -> None:
    loaded = load_key_registry(_fixture()["trusted_key_registry"])
    key = loaded.entries[0]
    assert audit._preflight_reason(
        ShieldV4VerificationError(V4_POLICY_INVALID)
    ) == V4_POLICY_INVALID
    assert audit._component_id_for_key(key) == "adn"

    for invalid_registry in (
        KeyRegistry(
            schema_version=loaded.schema_version,
            registry_version=loaded.registry_version,
            entries=(),
        ),
        KeyRegistry(
            schema_version="wrong",
            registry_version=loaded.registry_version,
            entries=(key,),
        ),
        KeyRegistry(
            schema_version=loaded.schema_version,
            registry_version=loaded.registry_version,
            entries=(object(),),  # type: ignore[arg-type]
        ),
    ):
        with pytest.raises(ValueError):
            audit._require_loaded_registry_budget(invalid_registry)

    with pytest.raises(ValueError, match="exact list"):
        audit._require_complete_bundle_budgets({"component_verdicts": {}})
    with pytest.raises(ValueError, match="freshness"):
        audit._require_artifact_freshness_window(
            not_before="2026-06-21T00:05:00Z",
            not_after="2026-06-21T00:05:00Z",
            verification_time="2026-06-21T00:05:00Z",
        )

    with pytest.raises(ValueError, match="all six"):
        audit._validate_prehashed_plan(
            [_prehashed_plan(artifact_id="adn", entry={}, key=key)]
        )
    artifacts = [*audit.SUPPORTED_COMPONENTS, audit.ORCHESTRATOR_ARTIFACT_ID]
    with pytest.raises(ValueError, match="signature count"):
        audit._validate_prehashed_plan(
            [
                _prehashed_plan(artifact_id=artifact, entry={}, key=key)
                for artifact in artifacts
            ]
        )
    shared_entry: dict[str, Any] = {}
    with pytest.raises(ValueError, match="duplicate"):
        audit._validate_prehashed_plan(
            [
                _prehashed_plan(artifact_id=artifact, entry=shared_entry, key=key)
                for artifact in artifacts
                for _ in range(2)
            ]
        )


def test_v410c_unconsumed_preflight_cache_fails_before_backend_callbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    backend_calls = 0

    def skip_component_cache(
        *_args: Any, **_kwargs: Any
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return [], fixture["receipt"]["component_signature_results"]

    def verifier(_entry: dict[str, Any], _key: KeyRegistryEntry) -> bool:
        nonlocal backend_calls
        backend_calls += 1
        return True

    monkeypatch.setattr(audit, "verify_component_verdicts", skip_component_cache)
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        verify_v4_receipt_with_audit(
            fixture["receipt"],
            artifact_transport_hash=_transport_hash(fixture["receipt"]),
            expected_context_hash=fixture["expected_context_hash"],
            expected_request_id=fixture["expected_request_id"],
            registry=load_key_registry(fixture["trusted_key_registry"]),
            minimum_registry_version=1,
            verification_time=fixture["verification_time"],
            component_verifier=verifier,
            receipt_verifier=verifier,
            audit_sink=sink,
        )
    assert backend_calls == 0
    assert _decoded(sink)[0]["reason_id"] == V4_CONTRACT_INVALID


@pytest.mark.parametrize("failure_kind", ["summary_mismatch", "unconsumed_cache"])
def test_v410c_post_callback_cached_validation_failures_are_audited(
    failure_kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    original = audit.verify_component_verdicts
    validation_calls = 0
    backend_calls = 0

    def staged_validation(*args: Any, **kwargs: Any):
        nonlocal validation_calls
        validation_calls += 1
        if validation_calls == 1:
            return original(*args, **kwargs)
        if failure_kind == "unconsumed_cache":
            return [], fixture["receipt"]["component_signature_results"]
        verified, summaries = original(*args, **kwargs)
        altered = copy.deepcopy(summaries)
        altered[-1]["verified"] = False
        return verified, altered

    def verifier(_entry: dict[str, Any], _key: KeyRegistryEntry) -> bool:
        nonlocal backend_calls
        backend_calls += 1
        return True

    monkeypatch.setattr(audit, "verify_component_verdicts", staged_validation)
    sink = RecordingSink()
    with pytest.raises(ShieldV4VerificationError, match=V4_CONTRACT_INVALID):
        verify_v4_receipt_with_audit(
            fixture["receipt"],
            artifact_transport_hash=_transport_hash(fixture["receipt"]),
            expected_context_hash=fixture["expected_context_hash"],
            expected_request_id=fixture["expected_request_id"],
            registry=load_key_registry(fixture["trusted_key_registry"]),
            minimum_registry_version=1,
            verification_time=fixture["verification_time"],
            component_verifier=verifier,
            receipt_verifier=verifier,
            audit_sink=sink,
        )
    assert validation_calls == 2
    assert backend_calls == 12
    events = _decoded(sink)
    assert events[-1]["event_type"] == audit.ARTIFACT_VERIFICATION_EVENT
    assert events[-1]["reason_id"] == V4_CONTRACT_INVALID
