from adversa.workflow_temporal.workflows import WorkflowEngine, is_config_required_error


def test_waiting_transition_cycle() -> None:
    engine = WorkflowEngine()
    assert is_config_required_error("401 Unauthorized") is True

    engine.mark_waiting("LLM provider config required")
    assert engine.status.waiting_for_config is True

    engine.resume()
    assert engine.status.waiting_for_config is False
    assert engine.status.waiting_reason is None
