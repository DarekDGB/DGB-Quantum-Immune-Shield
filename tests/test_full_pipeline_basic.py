from shield_orchestrator.pipeline import FullShieldPipeline

def test_pipeline_runs():
    pipeline = FullShieldPipeline.from_default_config()

    result = pipeline.process_event({"type": "test"})

    assert "flow" in result
    assert len(result["flow"]) == 5
    assert "immune" in result
    assert result["immune"]["passed"] is True
