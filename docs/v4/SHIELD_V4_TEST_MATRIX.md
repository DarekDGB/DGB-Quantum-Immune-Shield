# Shield v4 Test Matrix

Status: V4.10-D controlled release-candidate evidence
Author attribution: DarekDGB

## Purpose

This matrix maps every invariant in
`SHIELD_V4_CONTRACT_INVARIANTS.md` to committed test evidence. Tests and
normative contract documents define truth. A mapping proves only the behavior
asserted by the cited node.

## Invariant mapping

| Invariant | Locked behavior | Primary test node |
|---|---|---|
| V4-INV-001 | Shield output is evidence, not final authority | `tests/test_v4_full_multi_repo_negative_matrix.py::test_v48b_orchestrator_rejects_receipt_authority_and_semantic_bypass` |
| V4-INV-002 | AdamantineOS remains the final boundary | `tests/test_v4_full_multi_repo_negative_matrix.py::test_v48b_orchestrator_rejects_receipt_authority_and_semantic_bypass` |
| V4-INV-003 | V4 is parallel and v3 downgrade fails closed | `tests/test_v4_component_verdict_verification.py::test_v4_orchestrator_rejects_component_downgrade_to_v3` |
| V4-INV-004 | Canonical UTF-8, NFC, types, and key order | `tests/test_v4_canonical_json_lock.py::test_v4_canonical_json_normalizes_unicode_and_orders_keys` |
| V4-INV-005 | Component and set-valued ordering is deterministic | `tests/test_v4_receipt_schema_lock.py::test_v4_receipt_envelope_validates_and_locks_stable_kat_hashes` |
| V4-INV-006 | Component and receipt signature domains differ | `tests/test_v4_canonical_json_lock.py::test_v4_domain_separated_hashes_are_distinct_and_stable` |
| V4-INV-007 | Every signature binds the same signed payload hash | `tests/test_v4_signature_bundle_contract.py::test_v4_signature_bundle_negative_matrix` |
| V4-INV-008 | Signed freshness, request, and replay fields fail closed | `tests/test_v4_crypto_negative_matrix.py::test_v4_negative_matrix_rejects_payload_tamper_and_replay_fields` |
| V4-INV-009 | Keys are restricted to exact component roles | `tests/test_v4_signature_bundle_contract.py::test_v4_signature_bundle_rejects_missing_required_and_duplicates_and_wrong_role` |
| V4-INV-010 | Registry lifecycle, revocation, expiry, and rollback fail closed | `tests/test_v4_key_registry_fail_closed.py::test_v4_key_registry_rejects_duplicate_revoked_expired_and_rollback` |
| V4-INV-011 | Required classical plus ML-DSA; optional FN-DSA cannot rescue | `tests/test_v48h_fn_dsa_policy_contract.py::test_v48h_valid_fn_dsa_cannot_replace_missing_ml_dsa` |
| V4-INV-012 | Received signature order and bundle identity are canonical | `tests/test_v4_signature_bundle_contract.py::test_v49h_signature_bundle_rejects_noncanonical_order_before_key_lookup_or_crypto` |
| V4-INV-013 | ML-DSA and FN-DSA names and profiles remain separate | `tests/test_v49f_qid_crypto_alignment_lock.py::test_v49f_runtime_constants_match_independent_literal_locks` |
| V4-INV-014 | Metadata cannot inject approval or bypass authority | `tests/test_v4_full_multi_repo_negative_matrix.py::test_v48b_orchestrator_rejects_receipt_authority_and_semantic_bypass` |
| V4-INV-015 | AdamantineOS receives only the Orchestrator receipt | `tests/test_v4_full_multi_repo_integration_harness.py::test_v4_full_multi_repo_fixture_revalidates_all_components_and_final_receipt` |
| V4-INV-016 | External consumers verify evidence and never infer final approval | `tests/test_v49_external_verification_contract.py::test_v49k_external_fixture_freezes_exact_contract_shapes_and_policy` |
| V4-INV-017 | Shared KAT bytes and package manifest are frozen | `tests/test_v49_external_verification_contract.py::test_v49k_external_fixture_freezes_all_canonical_and_signature_input_bytes` |
| V4-INV-018 | Complete cheap preflight precedes hashes and crypto | `tests/test_v410c_performance_dos_envelope.py::test_v410c_all_cheap_preflight_finishes_before_payload_canonical_or_hash_work` |
| V4-INV-019 | Trusted policy controls v4-required mode | `tests/test_v4_crypto_negative_matrix.py::test_v4_negative_matrix_rejects_v3_downgrade_and_future_or_stale_windows` |
| V4-INV-020 | Durable audit acknowledgement precedes result release | `tests/test_v410b_verification_audit.py::test_v410b_missing_or_malformed_ack_fails_closed_without_result` |
| V4-INV-021 | Input, bundle, registry, and callback budgets are frozen | `tests/test_v410c_performance_dos_envelope.py::test_v410c_constants_and_required_fixture_are_frozen` |
| V4-INV-022 | Negative-first matrix rejects cryptographic and policy abuse | `tests/test_v4_crypto_negative_matrix.py::test_v4_negative_matrix_rejects_signature_and_policy_abuse` |
| V4-INV-023 | Six-bundle global waves and exact callback ceilings hold | `tests/test_v410c_performance_dos_envelope.py::test_v410c_global_algorithm_waves_and_exact_call_ceilings` |

The parallel v3 compatibility gate remains independently locked by
`tests/test_v3_version_gate.py::test_v3_rejects_non_v3_contract_version_fail_closed`.

## External contract and KAT locks

| Evidence | Test node |
|---|---|
| Exact external package manifest and self-exclusion | `tests/test_v49_external_verification_contract.py::test_v49k_external_package_manifest_is_exact_self_excluding_and_current` |
| Exact external field shapes and algorithm policy | `tests/test_v49_external_verification_contract.py::test_v49k_external_fixture_freezes_exact_contract_shapes_and_policy` |
| Current and historical KAT hashes | `tests/test_v49_external_verification_contract.py::test_v49k_kat_document_records_current_historical_and_external_hashes` |
| Real-backend component and receipt interface | `tests/test_v48g_real_backend_interface_contract_integration.py::test_v48g_orchestrator_verifies_real_backend_component_and_receipt_interface_contract` |
| Full optional FN-DSA profile reporting | `tests/test_v48h_e_full_hybrid_integration_lock.py::test_v48h_e_full_hybrid_fn_dsa_present_everywhere_is_accepted_and_reported` |
| Durable audit sink failures withhold results | `tests/test_v410b_verification_audit.py::test_v410b_missing_or_malformed_ack_fails_closed_without_result` |
| Work counters cannot exceed total or PQC caps | `tests/test_v410c_performance_dos_envelope.py::test_v410c_plan_and_runtime_counters_enforce_total_and_pqc_caps` |

## Workflow proof boundaries

| Workflow | Required proof | Standard-suite substitute? |
|---|---|---|
| `CI` | Python 3.11 and 3.13 full suite; 100 percent statement coverage | Not applicable |
| `Shield Live Integration` | Exact two cross-repository nodes; zero skips, failures, and errors | No |
| `Shield v4 Performance and DoS Envelope` | Exact Python and software pins; 54 focused tests; one benchmark JSON `PASS`; 20 warmups and 200 samples | No |
| `Shield v4 Real OQS ML-DSA and Falcon-1024 Proof` | Exact ML-DSA and Falcon-1024 nodes; tests=2; skipped=0; failures=0; errors=0 | No |

Default CI uses deterministic test doubles for most cryptographic behavior. It
does not prove that native liboqs ran. Conversely, the guarded native workflow
does not prove production-key custody, an HSM deployment, or final FIPS 206
conformance.

## Approved standard-suite skips

The default full suite has four approved opt-in skips:

1. native ML-DSA proof requires `SHIELD_V4_REAL_OQS=1`;
2. native Falcon-1024 proof requires `SHIELD_V4_REAL_OQS_FALCON=1`;
3. live cross-repository allow proof requires all component packages; and
4. live cross-repository deny proof requires all component packages.

Dedicated workflows must execute those exact nodes and reject every skip.

## Coverage boundary

Standard CI enforces 100 percent statement coverage for
`shield_orchestrator`. Branch coverage is not currently enforced and must not
be claimed. Documentation, JSON fixtures, workflow YAML, and native provider
code are outside the Python statement denominator.
