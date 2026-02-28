import asyncio
from datetime import timedelta

from temporalio.exceptions import ApplicationError

from adversa.workflow_temporal.activities import to_activity_error
from adversa.workflow_temporal.workflows import AdversaRunWorkflow, WorkflowEngine, workflow


def test_waiting_for_config_state() -> None:
    engine = WorkflowEngine()
    engine.mark_waiting("LLM provider config required")
    assert engine.status.waiting_for_config is True
    assert "config" in (engine.status.waiting_reason or "")


def test_typed_config_required_error_moves_workflow_to_waiting(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    async def fake_execute_activity(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise ApplicationError("Missing env var: OPENAI_API_KEY", type="config_required", non_retryable=True)

    observed = {"timeout": None}

    async def fake_wait_condition(fn, timeout=None):  # type: ignore[no-untyped-def]
        observed["timeout"] = timeout
        assert fn() is False
        wf.cancel()
        return None

    monkeypatch.setattr(workflow, "execute_activity", fake_execute_activity)
    monkeypatch.setattr(workflow, "wait_condition", fake_wait_condition)

    wf = AdversaRunWorkflow()
    payload = {
        "workspace": "runs/ws",
        "repo_path": "repos/target",
        "url": "https://example.com",
        "effective_config_path": "adversa.toml",
        "safe_mode": True,
        "run_id": "run-001",
        "force": False,
    }
    status = asyncio.run(wf.run(payload))

    assert observed["timeout"] == timedelta(hours=24)
    assert status["canceled"] is True


def test_to_activity_error_marks_config_errors_non_retryable() -> None:
    err = to_activity_error(RuntimeError("401 Unauthorized"))
    assert err.type == "config_required"
    assert err.non_retryable is True
