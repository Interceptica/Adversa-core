from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

from adversa.state.models import PHASES, WorkflowInput, WorkflowStatus
from adversa.workflow_temporal.activities import run_phase_activity


PHASE_ACTIVITY_TIMEOUT = timedelta(minutes=10)
PHASE_ACTIVITY_RETRY_POLICY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
    non_retryable_error_types=["config_required", "fatal"],
)


@dataclass
class WorkflowEngine:
    status: WorkflowStatus = field(default_factory=WorkflowStatus)

    def pause(self) -> None:
        if not self.status.canceled:
            self.status.paused = True

    def resume(self) -> None:
        if not self.status.canceled:
            self.status.paused = False

    def cancel(self) -> None:
        self.status.canceled = True
        self.status.paused = False
        self.status.waiting_for_config = False
        self.status.waiting_reason = None

    def mark_waiting(self, reason: str) -> None:
        self.status.waiting_for_config = True
        self.status.waiting_reason = reason
        self.status.paused = False

    def mark_config_updated(self) -> None:
        self.status.waiting_for_config = False
        self.status.waiting_reason = None
        self.status.last_error = None

    def start_phase(self, phase: str) -> None:
        self.status.current_phase = phase

    def record_completion(self, phase: str) -> None:
        self.status.current_phase = phase
        if phase not in self.status.completed_phases:
            self.status.completed_phases.append(phase)
        self.status.last_error = None


def is_config_required_error(exc: Exception) -> bool:
    if isinstance(exc, ApplicationError):
        return exc.type == "config_required"
    lowered = str(exc).lower()
    return "config_required" in lowered or "missing env var" in lowered or "401" in lowered


@workflow.defn
class AdversaRunWorkflow:
    def __init__(self) -> None:
        self.engine = WorkflowEngine()
        self._update_config = False

    @workflow.signal
    def pause(self) -> None:
        self.engine.pause()

    @workflow.signal
    def resume(self) -> None:
        self.engine.resume()

    @workflow.signal
    def cancel(self) -> None:
        self.engine.cancel()

    @workflow.signal
    def update_config(self) -> None:
        self._update_config = True
        self.engine.mark_config_updated()
        self.engine.resume()

    @workflow.query
    def status(self) -> dict:
        return self.engine.status.model_dump()

    @workflow.run
    async def run(self, payload: dict) -> dict:
        inp = WorkflowInput.model_validate(payload)
        self.engine.status.artifact_index_path = f"{inp.workspace}/{inp.run_id}/artifacts/index.json"

        for phase in PHASES:
            phase_done = False
            while not phase_done and not self.engine.status.canceled:
                self.engine.start_phase(phase)
                while self.engine.status.paused and not self.engine.status.canceled:
                    await workflow.sleep(timedelta(seconds=2))

                if self.engine.status.canceled:
                    break

                try:
                    result = await workflow.execute_activity(
                        run_phase_activity,
                        inp.workspace,
                        inp.workspace,
                        inp.run_id,
                        inp.repo_path,
                        inp.url,
                        phase,
                        inp.force,
                        start_to_close_timeout=PHASE_ACTIVITY_TIMEOUT,
                        retry_policy=PHASE_ACTIVITY_RETRY_POLICY,
                    )
                    if result.get("status") in {"completed", "skipped"}:
                        self.engine.record_completion(phase)
                    phase_done = True
                except Exception as exc:
                    message = str(exc)
                    if is_config_required_error(exc):
                        self.engine.mark_waiting("LLM provider config required")
                        await workflow.wait_condition(
                            lambda: self._update_config or self.engine.status.canceled,
                            timeout=timedelta(hours=24),
                        )
                        self._update_config = False
                        continue
                    self.engine.status.last_error = message
                    raise

        return self.engine.status.model_dump()
