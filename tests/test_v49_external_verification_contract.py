from __future__ import annotations

import copy
import hashlib
import hmac
import json
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from shield_orchestrator.v4.canonical_json import (
    COMPONENT_VERDICT_DOMAIN,
    ORCHESTRATOR_RECEIPT_DOMAIN,
    domain_separated_payload_bytes,
    parse_json_no_duplicate_keys,
    signed_payload_hash,
    to_canonical_json,
)
from shield_orchestrator.v4.component_verdicts import (
    COMPONENT_ROLES,
    REQUIRED_SIGNED_VERDICT_FIELDS,
    TEST_ONLY_SIGNATURE_PREFIXES,
    build_test_component_signature_entry,
    unsigned_component_payload,
    verify_component_verdicts,
    verify_test_only_component_signature,
)
from shield_orchestrator.v4.contracts.v4_receipt import (
    COMPONENT_SIGNATURE_RESULT_FIELDS,
    REQUIRED_RECEIPT_FIELDS,
    UNSIGNED_RECEIPT_EXCLUDED_FIELDS,
    build_receipt_hash,
    build_signed_receipt_envelope,
    build_unsigned_receipt_payload,
    validate_receipt_envelope,
)
from shield_orchestrator.v4.crypto_algorithms import (
    DEFAULT_STANDARD_PROFILE_BY_ALGORITHM,
    SIGNATURE_POLICY_V1,
)
from shield_orchestrator.v4.key_registry import build_test_registry, load_key_registry
from shield_orchestrator.v4.orchestrate import (
    build_test_only_orchestrator_signature_entry,
    verify_test_only_orchestrator_signature,
)
from shield_orchestrator.v4.real_crypto_backend import build_real_crypto_signature_input
from shield_orchestrator.v4.signature_bundle import (
    SIGNATURE_ENTRY_FIELDS,
    build_signature_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "tests/fixtures/v4/external_verifier_contract_v1_kat.json"
MANIFEST_PATH = ROOT / "docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_PACKAGE_V1.json"
CONTRACT_PATH = ROOT / "docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_CONTRACT_V1.md"
KAT_DOC_PATH = ROOT / "docs/v4/SHIELD_V4_KAT_VECTORS.md"
HISTORICAL_KAT_PATH = ROOT / "tests/fixtures/v4/orchestrator_receipt_policy_v1_kat.json"

ALGORITHMS = ("classical-ed25519", "ml-dsa", "fn-dsa")
COMPONENT_IDS = ("adn", "dqsn", "guardian_wallet", "qwg", "sentinel_ai")
SIGNATURE_BUNDLE_FIELDS = {"policy_version", "schema_version", "signatures"}
STALE_HISTORICAL_HASHES = (
    "4dcf7fc66317e8f06fbd24edf8c839a7ddf0d38b88b70af321cc7732d0ab46f5",
    "d4e4c277f99e9320a27a3502e3b26196638c1e4d8bdf5dcee0ad533559240ca3",
)
TOP_LEVEL_FIELDS = {
    "author_attribution",
    "canonicalization_profile",
    "contract_version",
    "expected_result",
    "inputs",
    "kat_artifacts",
    "receipt",
    "schema_version",
    "signature_policy",
    "verifier_controlled_test_registry",
    "warning",
}
INPUT_FIELDS = {
    "expected_context_hash",
    "expected_request_id",
    "minimum_key_registry_version",
    "rejected_receipt_hashes",
    "seen_request_ids",
    "verification_time",
}
EXPECTED_RESULT_FIELDS = {
    "accepted_as_evidence",
    "dominant_reason_ids",
    "final_approval",
    "final_outcome",
    "handoff_allowed",
    "reason_id",
    "state",
    "verified",
}
REGISTRY_FIELDS = {"entries", "registry_version", "schema_version"}
REGISTRY_ENTRY_FIELDS = {
    "algorithm",
    "key_id",
    "key_version",
    "not_after",
    "not_before",
    "public_key",
    "role",
    "status",
}
ARTIFACT_FIELDS = {
    "artifact_id",
    "canonical_json_hex",
    "canonical_json_utf8",
    "domain_separated_payload_hex",
    "domain_separated_payload_utf8",
    "domain_tag",
    "role",
    "signature_inputs",
    "signed_payload_hash",
    "unsigned_payload",
    "unsigned_payload_sha256",
}
SIGNATURE_INPUT_FIELDS = {
    "algorithm",
    "deterministic_signature",
    "domain_tag",
    "key_id",
    "key_version",
    "public_key_hex",
    "public_key_utf8",
    "real_crypto_signature_input_hex",
    "real_crypto_signature_input_utf8",
    "signed_payload_hash",
    "standard_profile",
    "test_only_signature_input_hex",
    "test_only_signature_input_utf8",
    "test_only_signature_scheme",
}
PACKAGE_FILES = (
    "docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_CONTRACT_V1.md",
    "docs/v4/SHIELD_V4_KAT_VECTORS.md",
    "tests/fixtures/v4/external_verifier_contract_v1_kat.json",
)


def _load_json(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    parsed = parse_json_no_duplicate_keys(raw)
    assert json.loads(raw) == parsed
    return parsed


def _fixture() -> dict[str, Any]:
    return _load_json(FIXTURE_PATH)


def _strip_component_summary(verdict: dict[str, Any]) -> dict[str, Any]:
    output = copy.deepcopy(verdict)
    output.pop("verification_summary", None)
    return output


def _rebuild_components(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    rebuilt: list[dict[str, Any]] = []
    for verdict in receipt["component_verdicts"]:
        payload = unsigned_component_payload(verdict)
        payload_hash = signed_payload_hash(
            domain_tag=COMPONENT_VERDICT_DOMAIN,
            payload=payload,
        )
        signatures = [
            build_test_component_signature_entry(
                component_id=verdict["component_id"],
                algorithm=algorithm,
                signed_hash=payload_hash,
            )
            for algorithm in ALGORITHMS
        ]
        rebuilt.append(
            {
                **payload,
                "signed_payload_hash": payload_hash,
                "signature_bundle": build_signature_bundle(
                    policy_version="policy.v1",
                    signatures=signatures,
                ),
            }
        )
    return rebuilt


def _rebuild_receipt(fixture: dict[str, Any]) -> dict[str, Any]:
    receipt = fixture["receipt"]
    registry = fixture["verifier_controlled_test_registry"]
    components = _rebuild_components(receipt)
    checked, summaries = verify_component_verdicts(
        components,
        expected_context_hash=fixture["inputs"]["expected_context_hash"],
        registry=registry,
        verification_time=fixture["inputs"]["verification_time"],
        verifier=verify_test_only_component_signature,
    )
    unsigned_receipt = build_unsigned_receipt_payload(
        request_id=receipt["request_id"],
        context_hash=receipt["context_hash"],
        freshness_nonce=receipt["freshness_nonce"],
        not_before=receipt["not_before"],
        not_after=receipt["not_after"],
        component_verdicts=[_strip_component_summary(item) for item in checked],
        component_signature_results=summaries,
        final_outcome=receipt["final_outcome"],
        dominant_reason_ids=receipt["dominant_reason_ids"],
        key_registry_version=receipt["key_registry_version"],
        adamantineos_handoff=receipt["adamantineos_handoff"],
    )
    shell = build_signed_receipt_envelope(
        unsigned_payload=unsigned_receipt,
        signature_bundle=build_signature_bundle(
            policy_version="policy.v1",
            signatures=[],
        ),
    )
    signatures = [
        build_test_only_orchestrator_signature_entry(
            algorithm=algorithm,
            signed_hash=shell["signed_payload_hash"],
        )
        for algorithm in ALGORITHMS
    ]
    return build_signed_receipt_envelope(
        unsigned_payload=unsigned_receipt,
        signature_bundle=build_signature_bundle(
            policy_version="policy.v1",
            signatures=signatures,
        ),
    )


def _signature_entries_by_artifact(receipt: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    entries = {
        verdict["component_id"]: verdict["signature_bundle"]["signatures"]
        for verdict in receipt["component_verdicts"]
    }
    entries["shield_orchestrator"] = receipt["signature_bundle"]["signatures"]
    return entries


def test_v49k_external_fixture_is_standalone_reproducible_and_valid() -> None:
    fixture = _fixture()
    assert _rebuild_receipt(fixture) == fixture["receipt"]
    assert fixture["verifier_controlled_test_registry"] == build_test_registry()

    validated = validate_receipt_envelope(
        fixture["receipt"],
        expected_context_hash=fixture["inputs"]["expected_context_hash"],
        registry=fixture["verifier_controlled_test_registry"],
        verification_time=fixture["inputs"]["verification_time"],
        verifier=verify_test_only_orchestrator_signature,
    )
    validated.pop("verification_summary")
    assert validated == fixture["receipt"]
    assert build_receipt_hash(
        {
            key: fixture["receipt"][key]
            for key in fixture["receipt"]
            if key not in UNSIGNED_RECEIPT_EXCLUDED_FIELDS
        }
    ) == fixture["receipt"]["receipt_hash"]


def test_v49k_external_fixture_freezes_exact_contract_shapes_and_policy() -> None:
    fixture = _fixture()
    receipt = fixture["receipt"]
    registry = fixture["verifier_controlled_test_registry"]

    assert set(fixture) == TOP_LEVEL_FIELDS
    assert set(fixture["inputs"]) == INPUT_FIELDS
    assert set(fixture["expected_result"]) == EXPECTED_RESULT_FIELDS
    assert set(receipt) == REQUIRED_RECEIPT_FIELDS
    assert set(registry) == REGISTRY_FIELDS
    assert len(registry["entries"]) == 18
    assert all(set(entry) == REGISTRY_ENTRY_FIELDS for entry in registry["entries"])
    assert all("standard_profile" not in entry for entry in registry["entries"])
    load_key_registry(registry)

    assert [item["component_id"] for item in receipt["component_verdicts"]] == list(COMPONENT_IDS)
    assert [item["component_id"] for item in receipt["component_signature_results"]] == list(COMPONENT_IDS)
    assert all(set(item) == COMPONENT_SIGNATURE_RESULT_FIELDS for item in receipt["component_signature_results"])
    assert "verification_summary" not in receipt
    for verdict in receipt["component_verdicts"]:
        assert set(verdict) == REQUIRED_SIGNED_VERDICT_FIELDS
        assert "verification_summary" not in verdict
        assert set(verdict["signature_bundle"]) == SIGNATURE_BUNDLE_FIELDS
        assert all(set(entry) == SIGNATURE_ENTRY_FIELDS for entry in verdict["signature_bundle"]["signatures"])
        assert [entry["algorithm"] for entry in verdict["signature_bundle"]["signatures"]] == list(ALGORITHMS)
    assert set(receipt["signature_bundle"]) == SIGNATURE_BUNDLE_FIELDS
    assert [entry["algorithm"] for entry in receipt["signature_bundle"]["signatures"]] == list(ALGORITHMS)
    assert SIGNATURE_POLICY_V1.required_algorithms == ALGORITHMS[:2]
    assert SIGNATURE_POLICY_V1.optional_algorithms == ALGORITHMS[2:]
    for bundle in [
        *(item["signature_bundle"] for item in receipt["component_verdicts"]),
        receipt["signature_bundle"],
    ]:
        for entry in bundle["signatures"]:
            assert entry["standard_profile"] == DEFAULT_STANDARD_PROFILE_BY_ALGORITHM[entry["algorithm"]]

    assert fixture["expected_result"] == {
        "accepted_as_evidence": True,
        "dominant_reason_ids": ["ORCH_OK_ALL_COMPONENTS_ALLOW"],
        "final_approval": False,
        "final_outcome": "ALLOW",
        "handoff_allowed": True,
        "reason_id": "EVIDENCE_OK",
        "state": "VERIFIED_ALLOW_EVIDENCE_CONTINUE_CHECKS",
        "verified": True,
    }


def test_v49k_external_fixture_freezes_all_canonical_and_signature_input_bytes() -> None:
    fixture = _fixture()
    receipt = fixture["receipt"]
    entry_map = _signature_entries_by_artifact(receipt)
    component_map = {
        verdict["component_id"]: verdict
        for verdict in receipt["component_verdicts"]
    }
    expected_artifacts = [*COMPONENT_IDS, "shield_orchestrator"]
    assert [item["artifact_id"] for item in fixture["kat_artifacts"]] == expected_artifacts

    for artifact in fixture["kat_artifacts"]:
        assert set(artifact) == ARTIFACT_FIELDS
        if artifact["artifact_id"] == "shield_orchestrator":
            expected_unsigned = {
                key: receipt[key]
                for key in receipt
                if key not in UNSIGNED_RECEIPT_EXCLUDED_FIELDS
            }
            assert artifact["role"] == "shield_orchestrator"
            assert artifact["domain_tag"] == ORCHESTRATOR_RECEIPT_DOMAIN
        else:
            expected_unsigned = unsigned_component_payload(
                component_map[artifact["artifact_id"]]
            )
            assert artifact["role"] == COMPONENT_ROLES[artifact["artifact_id"]]
            assert artifact["domain_tag"] == COMPONENT_VERDICT_DOMAIN
        assert artifact["unsigned_payload"] == expected_unsigned
        canonical_json = to_canonical_json(artifact["unsigned_payload"])
        canonical_bytes = canonical_json.encode("utf-8")
        domain_bytes = domain_separated_payload_bytes(
            domain_tag=artifact["domain_tag"],
            payload=artifact["unsigned_payload"],
        )
        assert artifact["canonical_json_utf8"] == canonical_json
        assert bytes.fromhex(artifact["canonical_json_hex"]) == canonical_bytes
        assert artifact["domain_separated_payload_utf8"].encode("utf-8") == domain_bytes
        assert bytes.fromhex(artifact["domain_separated_payload_hex"]) == domain_bytes
        assert artifact["unsigned_payload_sha256"] == hashlib.sha256(canonical_bytes).hexdigest()
        assert artifact["signed_payload_hash"] == hashlib.sha256(domain_bytes).hexdigest()
        assert artifact["signature_inputs"] == sorted(
            artifact["signature_inputs"],
            key=lambda item: ALGORITHMS.index(item["algorithm"]),
        )
        assert len(artifact["signature_inputs"]) == 3

        expected_entries = entry_map[artifact["artifact_id"]]
        assert {
            entry["signed_payload_hash"] for entry in expected_entries
        } == {artifact["signed_payload_hash"]}
        for vector, entry in zip(artifact["signature_inputs"], expected_entries, strict=True):
            assert set(vector) == SIGNATURE_INPUT_FIELDS
            assert vector["algorithm"] == entry["algorithm"]
            assert vector["domain_tag"] == entry["domain_tag"]
            assert vector["key_id"] == entry["key_id"]
            assert vector["key_version"] == entry["key_version"]
            assert vector["standard_profile"] == entry["standard_profile"]
            assert vector["signed_payload_hash"] == entry["signed_payload_hash"]
            assert vector["deterministic_signature"] == entry["signature"]
            registry_matches = [
                key
                for key in fixture["verifier_controlled_test_registry"]["entries"]
                if key["role"] == artifact["role"]
                and key["algorithm"] == vector["algorithm"]
                and key["key_id"] == vector["key_id"]
                and key["key_version"] == vector["key_version"]
            ]
            assert len(registry_matches) == 1
            assert vector["public_key_utf8"] == registry_matches[0]["public_key"]
            assert bytes.fromhex(vector["public_key_hex"]) == vector["public_key_utf8"].encode("utf-8")
            test_input = vector["test_only_signature_input_utf8"].encode("utf-8")
            assert bytes.fromhex(vector["test_only_signature_input_hex"]) == test_input
            real_input = build_real_crypto_signature_input(
                algorithm=vector["algorithm"],
                standard_profile=vector["standard_profile"],
                domain_tag=vector["domain_tag"],
                signed_payload_hash=vector["signed_payload_hash"],
                key_id=vector["key_id"],
                key_version=vector["key_version"],
            )
            assert vector["real_crypto_signature_input_utf8"].encode("utf-8") == real_input
            assert bytes.fromhex(vector["real_crypto_signature_input_hex"]) == real_input
            if artifact["artifact_id"] == "shield_orchestrator":
                assert vector["test_only_signature_scheme"] == "hmac-sha256-test-contract-double"
                expected_signature = hmac.new(
                    vector["public_key_utf8"].encode("utf-8"),
                    test_input,
                    "sha256",
                ).hexdigest()
            else:
                assert vector["test_only_signature_scheme"] == "sha256-test-contract-double"
                assert test_input.startswith(
                    (TEST_ONLY_SIGNATURE_PREFIXES[artifact["artifact_id"]] + "\n").encode("utf-8")
                )
                expected_signature = hashlib.sha256(test_input).hexdigest()
            assert vector["deterministic_signature"] == expected_signature


def test_v49k_registry_is_external_verifier_input_and_cannot_be_receipt_authority() -> None:
    fixture = _fixture()
    assert "trusted_key_registry" not in fixture["receipt"]
    assert "verifier_controlled_test_registry" not in fixture["receipt"]
    untrusted_mutation = copy.deepcopy(fixture["verifier_controlled_test_registry"])
    target = next(
        entry
        for entry in untrusted_mutation["entries"]
        if entry["role"] == "shield_orchestrator"
        and entry["algorithm"] == "classical-ed25519"
    )
    target["public_key"] = "UNTRUSTED-RECEIPT-SUPPLIED-KEY"
    with pytest.raises(ValueError, match="signature verification failed"):
        validate_receipt_envelope(
            fixture["receipt"],
            expected_context_hash=fixture["inputs"]["expected_context_hash"],
            registry=untrusted_mutation,
            verification_time=fixture["inputs"]["verification_time"],
            verifier=verify_test_only_orchestrator_signature,
        )


def test_v49k_external_package_manifest_is_exact_self_excluding_and_current() -> None:
    manifest = _load_json(MANIFEST_PATH)
    assert set(manifest) == {
        "author_attribution",
        "contract_version",
        "manifest_policy",
        "normative_files",
        "schema_version",
    }
    assert manifest["author_attribution"] == "DarekDGB"
    assert manifest["contract_version"] == 1
    assert manifest["schema_version"] == "shield.external_verification_package.v1"
    assert [item["path"] for item in manifest["normative_files"]] == list(PACKAGE_FILES)
    assert all(set(item) == {"path", "sha256"} for item in manifest["normative_files"])
    assert MANIFEST_PATH.relative_to(ROOT).as_posix() not in {
        item["path"] for item in manifest["normative_files"]
    }
    for item in manifest["normative_files"]:
        assert hashlib.sha256((ROOT / item["path"]).read_bytes()).hexdigest() == item["sha256"]


def test_v49k_kat_document_records_current_historical_and_external_hashes() -> None:
    historical = _load_json(HISTORICAL_KAT_PATH)
    external = _fixture()
    text = KAT_DOC_PATH.read_text(encoding="ascii")
    assert historical["receipt_hash"] in text
    assert historical["signed_payload_hash"] in text
    assert external["receipt"]["receipt_hash"] in text
    assert external["receipt"]["signed_payload_hash"] in text
    assert all(stale not in text for stale in STALE_HISTORICAL_HASHES)


def test_v49k_changed_contract_files_are_ascii_safe_and_darekdgb_only() -> None:
    changed = (
        CONTRACT_PATH,
        MANIFEST_PATH,
        KAT_DOC_PATH,
        FIXTURE_PATH,
        Path(__file__),
    )
    for path in changed:
        raw = path.read_bytes()
        assert raw
        assert raw.endswith(b"\n")
        assert b"\r" not in raw
        assert b"\x00" not in raw
        assert not raw.startswith(b"\xef\xbb\xbf")
        text = raw.decode("utf-8", errors="strict")
        assert text.isascii()
        assert unicodedata.normalize("NFC", text) == text
        assert "\ufffd" not in text
        assert not any(0x80 <= ord(character) <= 0x9F for character in text)
    combined = "\n".join(path.read_text(encoding="utf-8") for path in changed)
    assert "Author attribution: DarekDGB" in combined
    assert '"author_attribution": "DarekDGB"' in combined
