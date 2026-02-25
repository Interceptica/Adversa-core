from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

from adversa.state.models import PHASES, WorkflowInput, WorkflowStatus
from adversa.workflow_temporal.activities import run_phase_activity


@dataclass
class WorkflowEngine:
    status: WorkflowStatus = field(default_factory=WorkflowStatus)

    def pause(self) -> None:
        self.status.paused = True

    def resume(self) -> None:
        self.status.paused = False
        self.status.waiting_for_config = False
        self.status.waiting_reason = None

    def cancel(self) -> None:
        self.status.canceled = True

    def mark_waiting(self, reason: str) -> None:
        self.status.waiting_for_config = True
        self.status.waiting_reason = reason

    def record_completion(self, phase: str) -> None:
        self.status.current_phase = phase
        if phase not in self.status.completed_phases:
            self.status.completed_phases.append(phase)


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
        self.engine.resume()

    @workflow.query
    def status(self) -> dict:
        return self.engine.status.model_dump()

    @workflow.run
    async def run(self, payload: dict) -> dict:
        inp = WorkflowInput.model_validate(payload)

        for phase in PHASES:
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
                    start_to_close_timeout=timedelta(minutes=10),
                    retry_policy=RetryPolicy(
                        initial_interval=timedelta(seconds=2),
                        backoff_coefficient=2.0,
                        maximum_interval=timedelta(seconds=30),
                        maximum_attempts=3,
                    ),
                )
                if result.get("status") == "completed":
                    self.engine.record_completion(phase)
            except Exception as exc:
                message = str(exc)
                if "config_required" in message or "Missing env var" in message:
                    self.engine.mark_waiting("LLM provider config required")
                    await workflow.wait_condition(
                        lambda: self._update_config or self.engine.status.canceled,
                        timeout=timedelta(hours=24),
                    )
                    self._update_config = False
                    if self.engine.status.canceled:
                        break
                    continue
                self.engine.status.last_error = message
                raise

        return self.engine.status.model_dump()
