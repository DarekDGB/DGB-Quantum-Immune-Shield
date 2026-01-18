from shield_orchestrator.config import ShieldConfig
from shield_orchestrator.context import ShieldContext


def test_context_log_prints_when_enabled(capsys) -> None:
    cfg = ShieldConfig()
    cfg.enable_logging = True
    ctx = ShieldContext(cfg)

    ctx.log("hello")

    out = capsys.readouterr().out
    assert "[Shield] hello" in out
