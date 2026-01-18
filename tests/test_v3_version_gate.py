from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request
from shield_orchestrator.v3.orchestrate import orchestrate


def test_v3_rejects_non_v3_contract_version_fail_closed():
    req = OrchestratorV3Request(
        contract_version=2,
        wallet_id="w1",
        action="SEND",
        nonce="n1",
        ttl_seconds=60,
        payload={},
    )

    resp = orchestrate(req)
    assert resp.contract_version == 3
    assert resp.outcome == "DENY"
    assert "INVALID_CONTRACT_VERSION" in resp.reason_ids
