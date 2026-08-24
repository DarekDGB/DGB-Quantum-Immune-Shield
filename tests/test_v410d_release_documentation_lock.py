from __future__ import annotations

import ast
import hashlib
import json
import re
import tomllib
import unicodedata
from pathlib import Path

from shield_orchestrator.v3.contracts.v3_2_receipt import PACKAGE_VERSION
from shield_orchestrator.v4 import (
    CANONICALIZATION_PROFILE,
    KEY_REGISTRY_SCHEMA_VERSION,
    POLICY_VERSION,
    RECEIPT_SCHEMA_VERSION,
    SIGNATURE_BUNDLE_SCHEMA_VERSION,
    VERDICT_SCHEMA_VERSION,
)


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_AUTHOR = "DarekDGB"

REQUIRED_V4_DOCUMENTS = (
    "docs/v4/SHIELD_V4_CANONICALIZATION_SPEC.md",
    "docs/v4/SHIELD_V4_CONTRACT_INVARIANTS.md",
    "docs/v4/SHIELD_V4_THREAT_MODEL.md",
    "docs/v4/SHIELD_V4_TEST_MATRIX.md",
    "docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_CONTRACT_V1.md",
    "docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_PACKAGE_V1.json",
    "docs/v4/SHIELD_V4_KAT_VECTORS.md",
    "docs/v4/SHIELD_V4_PROOF_PACK.md",
    "docs/v4/SHIELD_V4_RELEASE_STATUS_v4.0.0.md",
    "docs/v4/SHIELD_V4_VERIFICATION_AUDIT_V1.md",
    "docs/v4/SHIELD_V4_PERFORMANCE_DOS_ENVELOPE_V1.md",
    "docs/v4/SHIELD_V4_PQC_SCOPE_LOCK.md",
    "docs/v4/SHIELD_V4_QID_CRYPTO_ALIGNMENT.md",
    "docs/v4/SHIELD_V4_REAL_CRYPTO_BACKEND.md",
)

CONTROLLED_D_FILES = (
    "pyproject.toml",
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs/v3/PROOF_PACK.md",
    "docs/v3/REASON_IDS.md",
    "docs/v3/RELEASE_STATUS_v3.2.0.md",
    "docs/v4/SHIELD_V4_TEST_MATRIX.md",
    "docs/v4/SHIELD_V4_PROOF_PACK.md",
    "docs/v4/SHIELD_V4_RELEASE_STATUS_v4.0.0.md",
    "tests/test_v410d_release_documentation_lock.py",
)

FROZEN_EVIDENCE_HASHES = {
    "docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_CONTRACT_V1.md": (
        "7119b3ee26d3aad8fb6040d349734dfdeca0251cdce743f47516282374098bea"
    ),
    "docs/v4/SHIELD_V4_KAT_VECTORS.md": (
        "c39080f077dec9ae599d5cba3a518274446f2efd8975ab14dc3d79bfcf58067a"
    ),
    "docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_PACKAGE_V1.json": (
        "44a3b3cf59efb22b90a11ca9a971abd3ec00282f0c00272c98ef7582151b1223"
    ),
    "tests/fixtures/v4/external_verifier_contract_v1_kat.json": (
        "308b9aadd993cf07665a125c4294d8e22cbe3f747419e346e104f127093e951f"
    ),
    "tests/fixtures/v4/orchestrator_receipt_policy_v1_kat.json": (
        "636773fe7bef34525e48a004b019529c811d2f5f16c1a5f97cf073545715886d"
    ),
    "tests/fixtures/v4/fn_dsa_signed_message_draft_profile_kat.json": (
        "ab05e603ba6c9711651f3a23ee0f3526e3d8aa781e763974bd002d864d286a59"
    ),
    "tests/fixtures/v4/full_multi_repo_v4_allow_flow.json": (
        "279f69dce971d5695ff2ac61f3aca5921e9cd936e059405e79ece38824899ce9"
    ),
}


def _bytes(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


def _text(relative: str) -> str:
    return _bytes(relative).decode("utf-8", errors="strict")


def _sha256(relative: str) -> str:
    return hashlib.sha256(_bytes(relative)).hexdigest()


def test_v410d_distribution_version_author_and_protocol_identities_are_locked() -> None:
    project = tomllib.loads(_text("pyproject.toml"))["project"]

    assert project["version"] == "4.0.0"
    assert project["authors"] == [{"name": EXPECTED_AUTHOR}]
    assert project["description"] == (
        "DigiByte Quantum Shield Orchestrator - deterministic Shield v4 "
        "evidence boundary."
    )

    assert PACKAGE_VERSION == "3.2.0"
    assert CANONICALIZATION_PROFILE == "shield-v4-canon.v1"
    assert POLICY_VERSION == "policy.v1"
    assert VERDICT_SCHEMA_VERSION == "shield.verdict.v2"
    assert RECEIPT_SCHEMA_VERSION == "shield.receipt.v2"
    assert SIGNATURE_BUNDLE_SCHEMA_VERSION == "shield.signature_bundle.v1"
    assert KEY_REGISTRY_SCHEMA_VERSION == "shield.key_registry.v1"


def test_v410d_required_document_set_exists_and_readme_links_every_file() -> None:
    readme = _text("README.md")

    for relative in REQUIRED_V4_DOCUMENTS:
        assert (ROOT / relative).is_file()
        assert relative in readme

    assert "controlled pre-release; not released and not tagged" in readme
    assert "Candidate tag: `v4.0.0`" in readme


def test_v410d_matrix_maps_every_invariant_exactly_once() -> None:
    matrix = _text("docs/v4/SHIELD_V4_TEST_MATRIX.md")
    mapped = re.findall(r"\bV4-INV-(\d{3})\b", matrix)

    assert mapped == [f"{value:03d}" for value in range(1, 24)]


def test_v410d_every_matrix_test_node_resolves_to_a_real_function() -> None:
    matrix = _text("docs/v4/SHIELD_V4_TEST_MATRIX.md")
    references = set(
        re.findall(r"`(tests/[^`]+\.py::test_[A-Za-z0-9_]+)`", matrix)
    )

    assert len(references) >= 23
    for reference in sorted(references):
        relative, function_name = reference.split("::", maxsplit=1)
        tree = ast.parse(_text(relative), filename=relative)
        top_level_functions = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert function_name in top_level_functions, reference


def test_v410d_external_package_manifest_and_frozen_evidence_are_unchanged() -> None:
    for relative, expected in FROZEN_EVIDENCE_HASHES.items():
        assert _sha256(relative) == expected

    manifest = json.loads(
        _text("docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_PACKAGE_V1.json")
    )
    expected_files = {
        "docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_CONTRACT_V1.md": (
            FROZEN_EVIDENCE_HASHES[
                "docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_CONTRACT_V1.md"
            ]
        ),
        "docs/v4/SHIELD_V4_KAT_VECTORS.md": FROZEN_EVIDENCE_HASHES[
            "docs/v4/SHIELD_V4_KAT_VECTORS.md"
        ],
        "tests/fixtures/v4/external_verifier_contract_v1_kat.json": (
            FROZEN_EVIDENCE_HASHES[
                "tests/fixtures/v4/external_verifier_contract_v1_kat.json"
            ]
        ),
    }
    actual_files = {
        item["path"]: item["sha256"] for item in manifest["normative_files"]
    }

    assert actual_files == expected_files
    assert "docs/v4/SHIELD_V4_EXTERNAL_VERIFICATION_PACKAGE_V1.json" not in actual_files


def test_v410d_proof_pack_records_every_frozen_evidence_hash() -> None:
    proof = _text("docs/v4/SHIELD_V4_PROOF_PACK.md")

    for expected in FROZEN_EVIDENCE_HASHES.values():
        assert expected in proof

    assert "d4d4f7338b4109d4914bf6861b62a8e9e2dfd0f5" in proof
    assert "889ed72fc515e51364af3698921083e51408daa537c38b8e897b5584b6d6d100" in proof
    assert "no persisted JUnit archive SHA-256 is claimed" in proof


def test_v410d_policy_order_no_rescue_and_authority_boundaries_are_explicit() -> None:
    documents = {
        relative: _text(relative)
        for relative in (
            "README.md",
            "SECURITY.md",
            "docs/v4/SHIELD_V4_PROOF_PACK.md",
            "docs/v4/SHIELD_V4_RELEASE_STATUS_v4.0.0.md",
        )
    }
    readme = documents["README.md"]
    proof = documents["docs/v4/SHIELD_V4_PROOF_PACK.md"]
    expected_readme_order = (
        "```text\n"
        "classical-ed25519\n"
        "ml-dsa\n"
        "fn-dsa                    optional and last only\n"
        "```"
    )

    assert readme.count(expected_readme_order) == 1
    assert proof.index("| `classical-ed25519` |") < proof.index("| `ml-dsa` |")
    assert proof.index("| `ml-dsa` |") < proof.index("| `fn-dsa` |")
    for text in documents.values():
        normalized = " ".join(text.split())
        assert "classical-ed25519" in normalized
        assert "ml-dsa" in normalized
        assert "fn-dsa" in normalized
        assert "fips206-draft-falcon1024-v1" in normalized
        assert "cannot replace or rescue" in normalized
        assert "not final FIPS 206 proof" in normalized

    assert "sign or broadcast transactions" in readme
    assert "AdamantineOS remains the final" in readme
    assert "AdamantineOS remains the final" in documents["SECURITY.md"]
    assert "AdamantineOS remains the final" in documents[
        "docs/v4/SHIELD_V4_RELEASE_STATUS_v4.0.0.md"
    ]
    assert "No path grants transaction signing, broadcast" in proof
    assert "AdamantineOS bypass" in proof


def test_v410d_v3_tag_history_is_complete_without_changing_compatibility() -> None:
    historical_paths = (
        "docs/v3/PROOF_PACK.md",
        "docs/v3/REASON_IDS.md",
        "docs/v3/RELEASE_STATUS_v3.2.0.md",
    )
    forbidden_pending_patterns = (
        r"\b(?:do not|must not|may not|cannot)\s+(?:create|move)\s+"
        r"(?:the\s+)?`?v?3\.2\.0`?\s+tag\b",
        r"\b(?:do not|must not|may not|cannot)\s+(?:create|move)\s+the\s+tag\b",
        r"\bno\s+`?v?3\.2\.0`?\s+tag\s+is\s+allowed\b",
        r"\bready\b[^\n]{0,80}\btag\b[^\n]{0,40}\bonly after\b",
    )

    for relative in historical_paths:
        text = _text(relative)
        assert "5290124cd0d4938543f588d48bcd47fe0ba035ca" in text
        assert all(
            re.search(pattern, text, flags=re.IGNORECASE) is None
            for pattern in forbidden_pending_patterns
        )

    compatibility = _text("src/shield_orchestrator/v3/contracts/v3_2_receipt.py")
    assert 'PACKAGE_VERSION = "3.2.0"' in compatibility
    assert 'VERDICT_SCHEMA_VERSION = "shield.verdict.v1"' in compatibility
    assert 'RECEIPT_SCHEMA_VERSION = "shield.receipt.v1"' in compatibility


def test_v410d_controlled_files_are_ascii_strict_utf8_nfc_lf() -> None:
    allowed_attribution_lines = {
        "Author attribution: DarekDGB",
        "Maintainer: DarekDGB",
        "Copyright 2025 DarekDGB",
    }
    for relative in CONTROLLED_D_FILES:
        payload = _bytes(relative)
        text = payload.decode("utf-8", errors="strict")

        assert payload
        assert payload.endswith(b"\n"), relative
        assert not payload.startswith(b"\xef\xbb\xbf"), relative
        assert b"\r" not in payload, relative
        assert b"\x00" not in payload, relative
        assert text.isascii(), relative
        assert text == unicodedata.normalize("NFC", text), relative
        assert EXPECTED_AUTHOR in text, relative

        for line in text.splitlines():
            normalized = line.replace("**", "").strip()
            attribution_line = normalized.lower().startswith(
                ("author attribution:", "co-author attribution:", "maintainer:")
            ) or normalized.lower().startswith("copyright ")
            if attribution_line:
                assert normalized in allowed_attribution_lines, (relative, line)


def test_v410d_release_status_is_candidate_only_and_tag_is_forbidden() -> None:
    status = _text("docs/v4/SHIELD_V4_RELEASE_STATUS_v4.0.0.md")
    expected_fields = {
        "Status": "CONTROLLED PRE-RELEASE",
        "Release decision": "NOT YET AUTHORIZED",
        "Distribution version": "4.0.0",
        "Candidate tag": "v4.0.0",
        "Tag created": "no",
    }

    for field, expected in expected_fields.items():
        values = re.findall(
            rf"^{re.escape(field)}:\s*(.+?)\s*$",
            status,
            flags=re.IGNORECASE | re.MULTILINE,
        )
        assert values == [expected], (field, values)
    for step in "EFGHIJKL":
        assert f"V4.10-{step}:" in status
    assert "Do not create or move `v4.0.0`" in status
