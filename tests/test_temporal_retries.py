from __future__ import annotations

from datetime import timedelta

from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

from adversa.constants import TASK_QUEUE
from adversa.llm.errors import LLMErrorKind, LLMProviderError
from adversa.workflow_temporal.activities import classify_provider_error, to_activity_error
from adversa.workflow_temporal.worker import build_worker, run_worker
from adversa.workflow_temporal.workflows import PHASE_ACTIVITY_RETRY_POLICY, PHASE_ACTIVITY_TIMEOUT, is_config_required_error


def test_phase_activity_retry_policy_matches_expected_matrix() -> None:
    assert PHASE_ACTIVITY_TIMEOUT == timedelta(minutes=10)
    assert isinstance(PHASE_ACTIVITY_RETRY_POLICY, RetryPolicy)
    assert PHASE_ACTIVITY_RETRY_POLICY.initial_interval == timedelta(seconds=2)
    assert PHASE_ACTIVITY_RETRY_POLICY.backoff_coefficient == 2.0
    assert PHASE_ACTIVITY_RETRY_POLICY.maximum_interval == timedelta(seconds=30)
    assert PHASE_ACTIVITY_RETRY_POLICY.maximum_attempts == 3
    assert PHASE_ACTIVITY_RETRY_POLICY.non_retryable_error_types == ["config_required", "fatal"]


def test_to_activity_error_marks_config_required_non_retryable() -> None:
    err = to_activity_error(LLMProviderError("Missing env var: OPENAI_API_KEY", LLMErrorKind.CONFIG_REQUIRED))
    assert isinstance(err, ApplicationError)
    assert err.type == "config_required"
    assert err.non_retryable is True
    assert is_config_required_error(err) is True


def test_to_activity_error_keeps_transient_errors_retryable() -> None:
    err = to_activity_error(LLMProviderError("Transient provider failure", LLMErrorKind.TRANSIENT))
    assert err.type == "transient"
    assert err.non_retryable is False
    assert is_config_required_error(err) is False


def test_classify_provider_error_uses_expected_taxonomy() -> None:
    assert classify_provider_error(RuntimeError("401 Unauthorized")).kind == LLMErrorKind.CONFIG_REQUIRED
    assert classify_provider_error(RuntimeError("429 timeout")).kind == LLMErrorKind.TRANSIENT
    assert classify_provider_error(RuntimeError("unexpected failure")).kind == LLMErrorKind.FATAL


def test_build_worker_registers_expected_workflow_and_activities() -> None:
    class FakeWorker:
        def __init__(self, client, task_queue, workflows, activities):  # type: ignore[no-untyped-def]
            self.client = client
            self.task_queue = task_queue
            self.workflows = workflows
            self.activities = activities

    import adversa.workflow_temporal.worker as worker_module

    original_worker = worker_module.Worker
    worker_module.Worker = FakeWorker
    try:
        worker = build_worker(client=object())
    finally:
        worker_module.Worker = original_worker

    assert worker.task_queue == TASK_QUEUE
    assert len(worker.workflows) == 1
    assert len(worker.activities) == 2


def test_run_worker_builds_and_runs_worker(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    state = {"connected": False, "ran": False}

    class FakeBuiltWorker:
        async def run(self) -> None:
            state["ran"] = True

    async def fake_get_client():  # type: ignore[no-untyped-def]
        state["connected"] = True
        return object()

    def fake_build_worker(client):  # type: ignore[no-untyped-def]
        assert client is not None
        return FakeBuiltWorker()

    monkeypatch.setattr("adversa.workflow_temporal.worker.get_client", fake_get_client)
    monkeypatch.setattr("adversa.workflow_temporal.worker.build_worker", fake_build_worker)

    import asyncio

    asyncio.run(run_worker())

    assert state == {"connected": True, "ran": True}
