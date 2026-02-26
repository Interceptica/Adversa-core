from adversa.workflow_temporal.workflows import WorkflowEngine


def test_waiting_for_config_state() -> None:
    engine = WorkflowEngine()
    engine.mark_waiting("LLM provider config required")
    assert engine.status.waiting_for_config is True
    assert "config" in (engine.status.waiting_reason or "")
