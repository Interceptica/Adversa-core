from __future__ import annotations

from pathlib import Path
import json

from temporalio import activity
from temporalio.exceptions import ApplicationError

from adversa.agent_runtime.context import AdversaAgentContext
from adversa.agent_runtime.executor import execute_phase_agent
from adversa.artifacts.store import ArtifactStore
from adversa.config.load import load_config
from adversa.config.models import AdversaConfig
from adversa.llm.errors import LLMErrorKind, LLMProviderError
from adversa.llm.providers import ProviderClient
from adversa.logging.audit import AuditLogger
from adversa.security.rule_compiler import compile_rules
from adversa.security.rules import RuntimeTarget, evaluate_rules
from adversa.state.models import EvidenceRef, ManifestState, PhaseOutput
from adversa.state.schemas import validate_phase_output


PHASE_EXTRA_ARTIFACTS: dict[str, dict[str, dict]] = {
    "intake": {
        "scope.json": {"authorized": True, "target_type": "staging", "url_source": "workflow_input"},
        "plan.json": {"phases": ["intake", "prerecon", "recon", "vuln", "report"], "safe_mode": True},
        "coverage_intake.json": {"phase": "intake", "status": "stub"},
    },
    "prerecon": {
        "pre_recon.json": {"phase": "prerecon", "status": "stub"},
    },
    "recon": {
        "system_map.json": {"phase": "recon", "assets": []},
        "attack_surface.json": {"phase": "recon", "entries": []},
    },
    "vuln": {
        "findings.json": {"phase": "vuln", "findings": [], "safe_mode": True},
        "risk_register.json": {"phase": "vuln", "risks": [], "safe_mode": True},
    },
    "report": {
        "report.md": "# Adversa Report\n\nStub safe-mode report.\n",
        "exec_summary.md": "# Executive Summary\n\nStub summary.\n",
        "retest_plan.json": {"phase": "report", "retest_steps": []},
    },
}


def _write_extra_phase_artifacts(store: ArtifactStore, phase: str) -> list[Path]:
    phase_dir = store.phase_dir(phase)
    written: list[Path] = []
    for filename, payload in PHASE_EXTRA_ARTIFACTS.get(phase, {}).items():
        path = phase_dir / filename
        if filename.endswith(".md"):
            path.write_text(str(payload), encoding="utf-8")
        else:
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        written.append(path)
    return written


@activity.defn
async def run_phase_activity(
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    phase: str,
    force: bool,
    effective_config_path: str = "adversa.toml",
) -> dict:
    store = ArtifactStore(Path(workspace_root), workspace, run_id)
    audit = AuditLogger(store.logs_dir)
    cfg = load_config(effective_config_path)
    runtime_target = RuntimeTarget.from_inputs(phase=phase, url=url, repo_path=repo_path)
    compiled_rules = compile_rules(cfg)
    rule_decision = evaluate_rules(runtime_target, compiled_rules)
    manifest = store.read_manifest() or ManifestState(
        workspace=workspace,
        run_id=run_id,
        url=url,
        repo_path=repo_path,
    )
    audit.log_agent_event(
        {
            "event_type": "phase_started",
            "workspace": workspace,
            "run_id": run_id,
            "phase": phase,
            "repo_path": repo_path,
            "url": url,
        }
    )
    audit.log_tool_call(
        {
            "event_type": "rules_evaluated",
            "workspace": workspace,
            "run_id": run_id,
            "phase": phase,
            "runtime_target": runtime_target.__dict__,
            "selected_analyzers": rule_decision.selected_analyzers,
            "applied_rules": [rule.__dict__ for rule in rule_decision.applied_rules],
        }
    )

    if rule_decision.blocked_reason:
        manifest.last_error = rule_decision.blocked_reason
        store.write_manifest(manifest)
        audit.log_agent_event(
            {
                "event_type": "phase_blocked_by_rule",
                "workspace": workspace,
                "run_id": run_id,
                "phase": phase,
                "reason": rule_decision.blocked_reason,
            }
        )
        raise ApplicationError(rule_decision.blocked_reason, type="fatal", non_retryable=True)

    if store.should_skip_phase(phase, force=force):
        audit.log_agent_event(
            {
                "event_type": "phase_skipped",
                "workspace": workspace,
                "run_id": run_id,
                "phase": phase,
            }
        )
        return {"phase": phase, "status": "skipped"}

    agent_execution = execute_phase_agent(
        context=AdversaAgentContext(
            phase=phase,
            url=url,
            repo_path=repo_path,
            workspace=workspace,
            run_id=run_id,
            workspace_root=workspace_root,
            config_path=effective_config_path,
        ),
        selected_analyzers=rule_decision.selected_analyzers,
    )
    audit.log_tool_call(
        {
            "event_type": "agent_runtime_initialized",
            "workspace": workspace,
            "run_id": run_id,
            "phase": phase,
            "agent_name": agent_execution.agent_name,
            "middleware": agent_execution.middleware,
            "executed": agent_execution.executed,
        }
    )

    output = PhaseOutput(
        phase=phase,
        summary=f"Stub {phase} phase completed in safe mode.",
        evidence=[EvidenceRef(id=f"{phase}-e1", path=f"{phase}/evidence/stub.txt", note="stub evidence")],
        data={
            "safe_mode": True,
            "selected_analyzers": rule_decision.selected_analyzers,
            "applied_rules": [rule.__dict__ for rule in rule_decision.applied_rules],
            "agent_runtime": {
                "status": agent_execution.status,
                "agent_name": agent_execution.agent_name,
                "middleware": agent_execution.middleware,
                "executed": agent_execution.executed,
            },
        },
    )

    files = store.write_phase_artifacts(output)
    if not validate_phase_output(files["output"]):
        message = f"Invalid phase output generated for phase '{phase}'"
        manifest.last_error = message
        store.write_manifest(manifest)
        activity.logger.error(message)
        audit.log_agent_event(
            {
                "event_type": "phase_failed",
                "workspace": workspace,
                "run_id": run_id,
                "phase": phase,
                "error": message,
            }
        )
        raise ApplicationError(message, type="invalid_phase_output", non_retryable=True)

    evidence_path = store.phase_dir(phase) / "evidence" / "stub.txt"
    evidence_path.write_text("evidence", encoding="utf-8")
    extra_files = _write_extra_phase_artifacts(store, phase)
    store.append_index([*files.values(), evidence_path, *extra_files])
    audit.log_tool_call(
        {
            "event_type": "phase_artifacts_written",
            "workspace": workspace,
            "run_id": run_id,
            "phase": phase,
            "paths": [str(path.relative_to(store.base)) for path in [*files.values(), evidence_path, *extra_files]],
        }
    )

    if phase not in manifest.completed_phases:
        manifest.completed_phases.append(phase)
    manifest.current_phase = phase
    manifest.last_error = None
    store.write_manifest(manifest)
    audit.log_agent_event(
        {
            "event_type": "phase_completed",
            "workspace": workspace,
            "run_id": run_id,
            "phase": phase,
            "workflow_id": manifest.workflow_id,
        }
    )
    return {"phase": phase, "status": "completed"}


@activity.defn
async def provider_health_check(config: dict) -> None:
    cfg = AdversaConfig.model_validate(config)
    logs_dir = Path(cfg.run.workspace_root) / "_system" / "provider_health" / "logs"
    audit = AuditLogger(logs_dir)
    audit.log_tool_call(
        {
            "event_type": "provider_health_check_started",
            "provider": cfg.provider.provider,
            "model": cfg.provider.model,
            "api_key_env": cfg.provider.api_key_env,
        }
    )
    client = ProviderClient(cfg.provider)
    try:
        client.health_check()
    except Exception as exc:
        audit.log_agent_event(
            {
                "event_type": "provider_health_check_failed",
                "provider": cfg.provider.provider,
                "error": str(exc),
            }
        )
        raise
    audit.log_agent_event(
        {
            "event_type": "provider_health_check_completed",
            "provider": cfg.provider.provider,
        }
    )


def classify_provider_error(exc: Exception) -> LLMProviderError:
    if isinstance(exc, LLMProviderError):
        return exc
    msg = str(exc).lower()
    if any(k in msg for k in ["401", "invalid api key", "credits", "quota"]):
        return LLMProviderError(str(exc), LLMErrorKind.CONFIG_REQUIRED)
    if any(k in msg for k in ["429", "timeout", "temporarily unavailable"]):
        return LLMProviderError(str(exc), LLMErrorKind.TRANSIENT)
    return LLMProviderError(str(exc), LLMErrorKind.FATAL)


def to_activity_error(exc: Exception) -> ApplicationError:
    provider_error = classify_provider_error(exc)
    non_retryable = provider_error.kind in {LLMErrorKind.CONFIG_REQUIRED, LLMErrorKind.FATAL}
    return ApplicationError(
        str(provider_error),
        type=provider_error.kind.value,
        non_retryable=non_retryable,
    )
