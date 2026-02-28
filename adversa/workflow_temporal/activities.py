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
from adversa.intake.plan import build_run_plan
from adversa.llm.errors import LLMErrorKind, LLMProviderError
from adversa.llm.providers import ProviderClient
from adversa.logging.audit import AuditLogger
from adversa.prerecon.controller import build_prerecon_report
from adversa.security.rule_compiler import compile_rules
from adversa.security.rules import RuntimeTarget, evaluate_rules
from adversa.state.models import EvidenceRef, ManifestState, PhaseOutput
from adversa.state.schemas import validate_phase_output, validate_pre_recon


PHASE_EXTRA_ARTIFACTS: dict[str, dict[str, object]] = {
    "intake": {
        "scope.json": {"authorized": True, "target_type": "staging", "url_source": "workflow_input"},
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


def _write_extra_phase_artifacts(
    store: ArtifactStore,
    phase: str,
    *,
    cfg: AdversaConfig,
    url: str,
    repo_path: str,
    safe_mode: bool,
) -> list[Path]:
    phase_dir = store.phase_dir(phase)
    written: list[Path] = []
    payloads = dict(PHASE_EXTRA_ARTIFACTS.get(phase, {}))
    if phase == "intake":
        payloads["plan.json"] = build_run_plan(
            url=url,
            repo_path=repo_path,
            config=cfg,
            safe_mode=safe_mode,
        ).model_dump(mode="json")

    for filename, payload in payloads.items():
        path = phase_dir / filename
        if filename.endswith(".md"):
            path.write_text(str(payload), encoding="utf-8")
        else:
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        written.append(path)
    return written


def _write_prerecon_artifacts(
    store: ArtifactStore,
    *,
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    effective_config_path: str,
) -> list[Path]:
    phase_dir = store.phase_dir("prerecon")
    try:
        report = build_prerecon_report(
            workspace_root=workspace_root,
            workspace=workspace,
            run_id=run_id,
            repo_path=repo_path,
            url=url,
            config_path=effective_config_path,
        )
    except Exception as exc:
        classified = classify_provider_error(exc)
        raise ApplicationError(
            str(classified),
            type=classified.kind.value,
            non_retryable=classified.kind != LLMErrorKind.TRANSIENT,
        ) from exc
    pre_recon_path = phase_dir / "pre_recon.json"
    pre_recon_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    if not validate_pre_recon(pre_recon_path):
        raise ApplicationError("Invalid prerecon artifact generated.", type="invalid_prerecon_output", non_retryable=True)
    evidence_path = phase_dir / "evidence" / "baseline.json"
    evidence_path.write_text(
        json.dumps(
            {
                "target_url": report.target_url,
                "canonical_url": report.canonical_url,
                "framework_signals": report.framework_signals,
                "candidate_routes": report.candidate_routes,
                "scope_inputs": report.scope_inputs,
                "plan_inputs": report.plan_inputs,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return [pre_recon_path, evidence_path]


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

    agent_context = AdversaAgentContext(
        phase=phase,
        url=url,
        repo_path=repo_path,
        workspace=workspace,
        run_id=run_id,
        workspace_root=workspace_root,
        config_path=effective_config_path,
    )
    agent_execution = execute_phase_agent(
        context=agent_context,
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

    evidence = [EvidenceRef(id=f"{phase}-e1", path=f"{phase}/evidence/stub.txt", note="stub evidence")]
    phase_summary = f"Stub {phase} phase completed in safe mode."
    phase_data = {
        "safe_mode": True,
        "selected_analyzers": rule_decision.selected_analyzers,
        "applied_rules": [rule.__dict__ for rule in rule_decision.applied_rules],
        "agent_runtime": {
            "status": agent_execution.status,
            "agent_name": agent_execution.agent_name,
            "middleware": agent_execution.middleware,
            "executed": agent_execution.executed,
        },
    }
    extra_files: list[Path] = []
    if phase == "prerecon":
        extra_files = _write_prerecon_artifacts(
            store,
            workspace_root=workspace_root,
            workspace=workspace,
            run_id=run_id,
            repo_path=repo_path,
            url=url,
            effective_config_path=effective_config_path,
        )
        prerecon_payload = json.loads(extra_files[0].read_text(encoding="utf-8"))
        phase_summary = (
            f"Prerecon inspected host '{prerecon_payload['host']}' and inferred "
            f"{len(prerecon_payload['candidate_routes'])} candidate routes."
        )
        phase_data["agent_runtime"] = {
            "status": "completed",
            "agent_name": "adversa-prerecon",
            "middleware": agent_execution.middleware,
            "executed": True,
            "runner": "deepagents",
        }
        evidence = [
            EvidenceRef(
                id="prerecon-baseline",
                path="prerecon/evidence/baseline.json",
                note="Prerecon baseline inputs, route candidates, and framework signals.",
            )
        ]
        phase_data["prerecon"] = {
            "framework_signals": prerecon_payload["framework_signals"],
            "candidate_routes": prerecon_payload["candidate_routes"],
            "warnings": prerecon_payload["warnings"],
        }

    output = PhaseOutput(
        phase=phase,
        summary=phase_summary,
        evidence=evidence,
        data=phase_data,
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

    if phase == "prerecon":
        prerecon_payload = json.loads(extra_files[0].read_text(encoding="utf-8"))
        files["coverage"].write_text(
            json.dumps(
                {
                    "phase": "prerecon",
                    "status": "complete",
                    "framework_signal_count": len(prerecon_payload["framework_signals"]),
                    "candidate_route_count": len(prerecon_payload["candidate_routes"]),
                    "warnings": prerecon_payload["warnings"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    evidence_path = store.phase_dir(phase) / "evidence" / "stub.txt"
    if phase != "prerecon":
        evidence_path.write_text("evidence", encoding="utf-8")
    if phase != "prerecon":
        extra_files = _write_extra_phase_artifacts(
            store,
            phase,
            cfg=cfg,
            url=url,
            repo_path=repo_path,
            safe_mode=cfg.safety.safe_mode,
        )
    index_paths = [*files.values(), *extra_files]
    if phase != "prerecon":
        index_paths.append(evidence_path)
    store.append_index(index_paths)
    audit.log_tool_call(
        {
            "event_type": "phase_artifacts_written",
            "workspace": workspace,
            "run_id": run_id,
            "phase": phase,
            "paths": [str(path.relative_to(store.base)) for path in index_paths],
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
