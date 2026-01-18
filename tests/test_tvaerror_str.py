from shield_orchestrator.errors import TVAError


def test_tvaerror_str_includes_reason_and_message() -> None:
    e = TVAError("X", "boom")
    assert str(e) == "X: boom"
