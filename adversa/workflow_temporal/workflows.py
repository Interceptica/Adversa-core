from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

from adversa.state.models import PHASES, WorkflowInput, WorkflowStatus

# Activities import heavy non-deterministic deps (urllib3, httpx, deepagents).
# Mark as pass-through so the sandbox doesn't try to validate them.
with workflow.unsafe.imports_passed_through():
    from adversa.workflow_temporal.activities import (
        provider_health_check,
        run_intake_activity,
        run_netdisc_activity,
        run_prerecon_activity,
        run_recon_activity,
        run_report_activity,
        run_vuln_activity,
    )

# Maps each phase to its dedicated activity (distinct name shown in Temporal UI)
_PHASE_ACTIVITY_MAP = {
    "intake": run_intake_activity,
    "prerecon": run_prerecon_activity,
    "netdisc": run_netdisc_activity,
    "recon": run_recon_activity,
    "vuln": run_vuln_activity,
    "report": run_report_activity,
}


PHASE_ACTIVITY_TIMEOUT = timedelta(minutes=10)
AGENT_PHASE_ACTIVITY_TIMEOUT = timedelta(minutes=30)
VULN_PHASE_ACTIVITY_TIMEOUT = timedelta(minutes=30)

_AGENT_PHASES = {"prerecon", "recon", "vuln", "report"}

# Fast phases (intake, netdisc in stub mode): quick retries, 3 attempts
FAST_PHASE_RETRY_POLICY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
    non_retryable_error_types=["config_required", "fatal"],
)

# LLM-backed agent phases: longer backoff to handle rate limits and transient errors
AGENT_PHASE_RETRY_POLICY = RetryPolicy(
    initial_interval=timedelta(minutes=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(minutes=10),
    maximum_attempts=10,
    non_retryable_error_types=["config_required", "fatal"],
)

# Kept for backwards-compat; maps to the fast policy
PHASE_ACTIVITY_RETRY_POLICY = FAST_PHASE_RETRY_POLICY

REMEDIATION_HINTS: dict[str, str] = {
    "config_required": (
        "Set the required API key environment variable (e.g. ANTHROPIC_API_KEY) "
        "and send the update_config signal: `adversa resume --workspace <name>`."
    ),
    "401": (
        "Your API key was rejected (HTTP 401). Verify the key is valid and has sufficient credits, "
        "then send the update_config signal."
    ),
    "missing env var": (
        "A required environment variable is missing. Check your adversa.toml [provider] section "
        "and ensure the api_key_env variable is exported in the worker environment."
    ),
    "default": (
        "Check `adversa status --workspace <name>` for details. "
        "Fix the underlying issue and send the resume signal."
    ),
}


def _unwrap_error(exc: Exception) -> Exception:
    """Traverse .cause chain to find the innermost error (unwrap Temporal ActivityError wrappers)."""
    from temporalio.exceptions import ActivityError

    while isinstance(exc, ActivityError) and exc.__cause__:
        exc = exc.__cause__
    return exc


def _remediation_hint_for(exc: Exception) -> str:
    lowered = str(exc).lower()
    for key, hint in REMEDIATION_HINTS.items():
        if key == "default":
            continue
        if key in lowered:
            return hint
    return REMEDIATION_HINTS["default"]


def is_config_required_error(exc: Exception) -> bool:
    exc = _unwrap_error(exc)
    if isinstance(exc, ApplicationError):
        return exc.type == "config_required"
    lowered = str(exc).lower()
    return "config_required" in lowered or "missing env var" in lowered or "401" in lowered


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

    def mark_waiting(self, reason: str, exc: Exception | None = None) -> None:
        self.status.waiting_for_config = True
        self.status.waiting_reason = reason
        self.status.paused = False
        self.status.remediation_hint = _remediation_hint_for(exc) if exc is not None else REMEDIATION_HINTS["default"]

    def mark_config_updated(self) -> None:
        self.status.waiting_for_config = False
        self.status.waiting_reason = None
        self.status.last_error = None
        self.status.remediation_hint = None

    def start_phase(self, phase: str, phase_started_at: str | None = None) -> None:
        self.status.current_phase = phase
        if phase_started_at is not None:
            self.status.phase_started_at = phase_started_at

    def record_completion(self, phase: str) -> None:
        self.status.current_phase = phase
        if phase not in self.status.completed_phases:
            self.status.completed_phases.append(phase)
        self.status.last_error = None


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
        self.engine.status.artifact_index_path = f"{inp.workspace_root}/{inp.workspace}/{inp.run_id}/artifacts/index.json"
        self.engine.status.started_at = workflow.now().isoformat()

        # Provider preflight: surface config errors before wasting a full phase run
        try:
            await workflow.execute_activity(
                provider_health_check,
                args=[inp.effective_config_path],
                start_to_close_timeout=PHASE_ACTIVITY_TIMEOUT,
                retry_policy=FAST_PHASE_RETRY_POLICY,
            )
        except Exception as exc:
            if is_config_required_error(exc):
                self.engine.mark_waiting("LLM provider config required", exc=exc)
                await workflow.wait_condition(
                    lambda: self._update_config or self.engine.status.canceled,
                    timeout=timedelta(hours=24),
                )
                self._update_config = False
                if self.engine.status.canceled:
                    return self.engine.status.model_dump()
                # Retry health check is implicit: proceed to phase loop
            else:
                self.engine.status.last_error = str(exc)
                raise

        for phase in PHASES:
            phase_done = False
            while not phase_done and not self.engine.status.canceled:
                self.engine.start_phase(phase, workflow.now().isoformat())
                while self.engine.status.paused and not self.engine.status.canceled:
                    await workflow.sleep(timedelta(seconds=2))

                if self.engine.status.canceled:
                    break

                retry_policy = AGENT_PHASE_RETRY_POLICY if phase in _AGENT_PHASES else FAST_PHASE_RETRY_POLICY
                try:
                    timeout = AGENT_PHASE_ACTIVITY_TIMEOUT if phase in _AGENT_PHASES else PHASE_ACTIVITY_TIMEOUT
                    result = await workflow.execute_activity(
                        _PHASE_ACTIVITY_MAP[phase],
                        args=[
                            inp.workspace_root,
                            inp.workspace,
                            inp.run_id,
                            inp.repo_path,
                            inp.url,
                            inp.force,
                            inp.effective_config_path,
                        ],
                        start_to_close_timeout=timeout,
                        retry_policy=retry_policy,
                    )
                    if result.get("status") in {"completed", "skipped"}:
                        self.engine.record_completion(phase)
                    phase_done = True
                except Exception as exc:
                    message = str(exc)
                    if is_config_required_error(exc):
                        self.engine.mark_waiting("LLM provider config required", exc=exc)
                        await workflow.wait_condition(
                            lambda: self._update_config or self.engine.status.canceled,
                            timeout=timedelta(hours=24),
                        )
                        self._update_config = False
                        continue
                    self.engine.status.last_error = message
                    raise

        return self.engine.status.model_dump()
