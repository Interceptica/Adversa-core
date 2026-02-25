from adversa.workflow_temporal.workflows import WorkflowEngine


def test_pause_resume_signals() -> None:
    engine = WorkflowEngine()
    engine.pause()
    assert engine.status.paused is True
    engine.resume()
    assert engine.status.paused is False
