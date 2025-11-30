from shield_orchestrator import FullShieldPipeline


def test_full_pipeline_low_risk():
    """A calm event should stay LOW."""
    pipeline = FullShieldPipeline.from_default_config()

    event = {
        "entropy_drop": 0.02,
        "reorg_depth": 0,
        "cluster_risk": 0.0,
        "global_alerts": 0,
        "local_anomaly": 0.0,
        "lockdown_triggered": False,
        "amount_dgb": 1_000.0,
        "recent_txs": 1,
        "quantum_hint": 0.0,
        "key_reuse_detected": False,
    }

    result = pipeline.process_event(event)

    assert 0.0 <= result.final_score <= 0.4
    assert result.final_level in {"LOW", "ELEVATED"}
    assert len(result.layer_results) == 6
    assert any("Sentinel" in log for log in result.logs)


def test_full_pipeline_high_risk():
    """A clearly malicious pattern should escalate to HIGH/CRITICAL."""
    pipeline = FullShieldPipeline.from_default_config()

    event = {
        "entropy_drop": 0.5,
        "reorg_depth": 3,
        "cluster_risk": 0.7,
        "global_alerts": 2,
        "local_anomaly": 0.8,
        "lockdown_triggered": True,
        "amount_dgb": 500_000.0,
        "recent_txs": 12,
        "quantum_hint": 0.9,
        "key_reuse_detected": True,
    }

    result = pipeline.process_event(event)

    assert 0.5 <= result.final_score <= 1.0
    assert result.final_level in {"HIGH", "CRITICAL"}
    assert len(result.layer_results) == 6
    # Adaptive core must be present as last layer.
    assert result.layer_results[-1].name == "adaptive_core_v2"
