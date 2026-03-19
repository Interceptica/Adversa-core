from __future__ import annotations

import asyncio
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
from adversa.security.rule_compiler import compile_rules
from adversa.security.rules import RuntimeTarget, evaluate_rules
from adversa.state.models import EvidenceRef, ManifestState, PhaseOutput
from adversa.state.schemas import validate_phase_output

# Phase artifact writers — imported at module level so tests can monkeypatch them.
from adversa.prerecon.controller import write_prerecon_artifacts
from adversa.netdisc.controller import write_netdisc_artifacts
from adversa.recon.controller import write_recon_artifacts
from adversa.vuln.controller import write_vuln_artifacts
from adversa.report.controller import write_report_artifacts


PHASE_EXTRA_ARTIFACTS: dict[str, dict[str, object]] = {
    "intake": {
        "scope.json": {"authorized": True, "target_type": "staging", "url_source": "workflow_input"},
        "coverage_intake.json": {"phase": "intake", "status": "stub"},
    },
    "prerecon": {
        "pre_recon.json": {"phase": "prerecon", "status": "stub"},
    },
    "netdisc": {
        "network_discovery.json": {"phase": "netdisc", "status": "stub"},
    },
    "recon": {
        "recon.json": {"phase": "recon", "status": "stub"},
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
    workspace: str = "",
) -> list[Path]:
    from urllib.parse import urlparse as _urlparse

    from adversa.state.models import ScopeContract

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

        # Build a real ScopeContract from the toml/cli config so downstream
        # phases (netdisc etc.) can load it with ScopeContract.model_validate().
        _parsed = _urlparse(url)
        _focus_hosts = [r.value for r in cfg.rules.focus if r.type == "host"]
        _focus_subdomains = [r.value for r in cfg.rules.focus if r.type == "subdomain"]
        _focus_paths = [r.value for r in cfg.rules.focus if r.type == "path"]
        _avoid_values = [r.value for r in cfg.rules.avoid]
        payloads["scope.json"] = ScopeContract(
            target_url=url,
            repo_path=repo_path,
            workspace=workspace,
            authorized=True,
            safe_mode=safe_mode,
            source_precedence=["toml", "cli"],
            normalized_host=(_parsed.hostname or "").lower(),
            normalized_path=_parsed.path or "/",
            allowed_hosts=_focus_hosts,
            allowed_subdomains=_focus_subdomains,
            allowed_paths=_focus_paths,
            exclusions=_avoid_values,
            capability_constraints=(["safe_mode"] if safe_mode else []),
            repo_root_validated=True,
            rules_summary={
                "focus": [{"type": r.type, "value": r.value} for r in cfg.rules.focus],
                "avoid": [{"type": r.type, "value": r.value} for r in cfg.rules.avoid],
            },
        ).model_dump(mode="json")

    for filename, payload in payloads.items():
        path = phase_dir / filename
        if filename.endswith(".md"):
            path.write_text(str(payload), encoding="utf-8")
        else:
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        written.append(path)
    return written


async def _run_phase_impl(
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

    # Heartbeat loop: keeps Temporal informed that the activity is still alive
    # during long-running LLM/tool phases so hung activities are detected quickly.
    async def _heartbeat_loop() -> None:
        while True:
            activity.heartbeat()
            await asyncio.sleep(5)

    heartbeat_task = asyncio.create_task(_heartbeat_loop())
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

    _REAL_PHASES = ("prerecon", "netdisc", "recon", "vuln", "report")

    if phase == "prerecon":
        try:
            extra_files = await asyncio.to_thread(
                write_prerecon_artifacts,
                store,
                workspace_root=workspace_root,
                workspace=workspace,
                run_id=run_id,
                repo_path=repo_path,
                url=url,
                effective_config_path=effective_config_path,
            )
        except ApplicationError:
            raise
        except Exception as exc:
            raise to_activity_error(exc) from exc
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
            "auth_signals": prerecon_payload["auth_signals"],
            "schema_files": prerecon_payload["schema_files"],
            "external_integrations": prerecon_payload["external_integrations"],
            "security_config": prerecon_payload["security_config"],
            "vulnerability_sinks": prerecon_payload["vulnerability_sinks"],
            "data_flow_patterns": prerecon_payload["data_flow_patterns"],
            "warnings": prerecon_payload["warnings"],
        }

    elif phase == "netdisc":
        try:
            extra_files = await write_netdisc_artifacts(
                store,
                workspace_root=workspace_root,
                workspace=workspace,
                run_id=run_id,
                repo_path=repo_path,
                url=url,
                effective_config_path=effective_config_path,
            )
        except ApplicationError:
            raise
        except Exception as exc:
            raise to_activity_error(exc) from exc
        netdisc_payload = json.loads(extra_files[0].read_text(encoding="utf-8"))
        phase_summary = (
            f"Network discovery found {len(netdisc_payload['discovered_hosts'])} hosts "
            f"and {len(netdisc_payload['service_fingerprints'])} service fingerprints."
        )
        phase_data["agent_runtime"] = {
            "status": "completed",
            "agent_name": "adversa-netdisc",
            "middleware": agent_execution.middleware,
            "executed": True,
            "runner": "tools",
        }
        evidence = [
            EvidenceRef(
                id="netdisc-baseline",
                path="netdisc/evidence/baseline.json",
                note="Network discovery baseline with discovered hosts, fingerprints, and TLS observations.",
            )
        ]
        phase_data["netdisc"] = {
            "discovered_hosts": netdisc_payload["discovered_hosts"],
            "service_fingerprints": netdisc_payload["service_fingerprints"],
            "tls_observations": netdisc_payload["tls_observations"],
            "port_services": netdisc_payload["port_services"],
            "passive_discovery_enabled": netdisc_payload["passive_discovery_enabled"],
            "active_scanning_enabled": netdisc_payload["active_scanning_enabled"],
            "warnings": netdisc_payload["warnings"],
        }

    elif phase == "recon":
        try:
            extra_files = await write_recon_artifacts(
                store,
                workspace_root=workspace_root,
                workspace=workspace,
                run_id=run_id,
                repo_path=repo_path,
                url=url,
                effective_config_path=effective_config_path,
            )
        except ApplicationError:
            raise
        except Exception as exc:
            raise to_activity_error(exc) from exc
        recon_payload = json.loads(extra_files[0].read_text(encoding="utf-8"))
        phase_summary = (
            f"Recon mapped {len(recon_payload['endpoints'])} endpoints, "
            f"{len(recon_payload['privilege_roles'])} roles, and "
            f"{len(recon_payload['authz_candidates'])} authz candidates."
        )
        phase_data["agent_runtime"] = {
            "status": "completed",
            "agent_name": "adversa-recon",
            "middleware": agent_execution.middleware,
            "executed": True,
            "runner": "deepagents",
        }
        evidence = [
            EvidenceRef(
                id="recon-baseline",
                path="recon/evidence/baseline.json",
                note="Recon baseline with endpoints, input vectors, network map, and authz candidates.",
            )
        ]
        phase_data["recon"] = {
            "endpoints": recon_payload["endpoints"],
            "input_vectors": recon_payload["input_vectors"],
            "network_entities": recon_payload["network_entities"],
            "privilege_roles": recon_payload["privilege_roles"],
            "authz_candidates": recon_payload["authz_candidates"],
            "live_observations": recon_payload["live_observations"],
            "warnings": recon_payload["warnings"],
        }

    elif phase == "vuln":
        try:
            extra_files = await write_vuln_artifacts(
                store,
                workspace_root=workspace_root,
                workspace=workspace,
                run_id=run_id,
                repo_path=repo_path,
                url=url,
                effective_config_path=effective_config_path,
            )
        except ApplicationError:
            raise
        except Exception as exc:
            raise to_activity_error(exc) from exc
        vuln_payload = json.loads(extra_files[0].read_text(encoding="utf-8"))
        all_findings = (
            vuln_payload.get("injection", {}).get("findings", [])
            + vuln_payload.get("xss", {}).get("findings", [])
            + vuln_payload.get("ssrf", {}).get("findings", [])
            + vuln_payload.get("auth", {}).get("findings", [])
            + vuln_payload.get("authz", {}).get("findings", [])
        )
        critical_count = sum(1 for f in all_findings if f.get("severity") == "critical")
        high_count = sum(1 for f in all_findings if f.get("severity") == "high")
        phase_summary = (
            f"Found {len(all_findings)} findings across 5 analyzers "
            f"({critical_count} critical, {high_count} high)."
        )
        phase_data["agent_runtime"] = {
            "status": "completed",
            "agent_name": "adversa-vuln",
            "middleware": agent_execution.middleware,
            "executed": True,
            "runner": "deepagents-parallel",
        }
        evidence = [
            EvidenceRef(
                id="vuln-baseline",
                path="vuln/evidence/baseline.json",
                note="Vulnerability analysis baseline with all findings and secure vectors.",
            )
        ]
        phase_data["vuln"] = {
            "injection_count": len(vuln_payload.get("injection", {}).get("findings", [])),
            "xss_count": len(vuln_payload.get("xss", {}).get("findings", [])),
            "ssrf_count": len(vuln_payload.get("ssrf", {}).get("findings", [])),
            "auth_count": len(vuln_payload.get("auth", {}).get("findings", [])),
            "authz_count": len(vuln_payload.get("authz", {}).get("findings", [])),
            "total_findings": len(all_findings),
            "critical_count": critical_count,
            "high_count": high_count,
            "warnings": vuln_payload.get("warnings", []),
        }

    _report_result: dict = {}
    if phase == "report":
        try:
            extra_files, _report_result = await asyncio.to_thread(
                write_report_artifacts,
                store,
                workspace_root=workspace_root,
                workspace=workspace,
                run_id=run_id,
                repo_path=repo_path,
                url=url,
                effective_config_path=effective_config_path,
            )
        except ApplicationError:
            raise
        except Exception as exc:
            raise to_activity_error(exc) from exc
        retest_plan = _report_result["retest_plan"]
        fs = _report_result["findings_summary"]
        critical_count = fs["critical"]
        high_count = fs["high"]
        phase_summary = (
            f"Report generated: {fs['total']} findings "
            f"({critical_count} critical, {high_count} high). "
            f"Retest plan: {len(retest_plan.retest_steps)} steps."
        )
        phase_data["agent_runtime"] = {
            "status": "completed",
            "agent_name": "adversa-report",
            "middleware": agent_execution.middleware,
            "executed": True,
            "runner": "llm-synthesis",
        }
        evidence = [
            EvidenceRef(
                id="report-baseline",
                path="report/evidence/baseline.json",
                note="Report baseline with all findings, retest plan, and secure vectors.",
            )
        ]
        phase_data["report"] = {
            "total_findings": fs["total"],
            "critical_count": critical_count,
            "high_count": high_count,
            "retest_step_count": len(retest_plan.retest_steps),
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

    # Overwrite the stub coverage.json with real phase-specific data
    if phase == "prerecon":
        prerecon_payload = json.loads(extra_files[0].read_text(encoding="utf-8"))
        files["coverage"].write_text(
            json.dumps(
                {
                    "phase": "prerecon",
                    "status": "complete",
                    "framework_signal_count": len(prerecon_payload["framework_signals"]),
                    "candidate_route_count": len(prerecon_payload["candidate_routes"]),
                    "auth_signal_count": len(prerecon_payload["auth_signals"]),
                    "schema_file_count": len(prerecon_payload["schema_files"]),
                    "vulnerability_sink_count": len(prerecon_payload["vulnerability_sinks"]),
                    "data_flow_pattern_count": len(prerecon_payload["data_flow_patterns"]),
                    "warnings": prerecon_payload["warnings"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    elif phase == "netdisc":
        netdisc_payload = json.loads(extra_files[0].read_text(encoding="utf-8"))
        files["coverage"].write_text(
            json.dumps(
                {
                    "phase": "netdisc",
                    "status": "complete",
                    "discovered_host_count": len(netdisc_payload["discovered_hosts"]),
                    "service_fingerprint_count": len(netdisc_payload["service_fingerprints"]),
                    "tls_observation_count": len(netdisc_payload["tls_observations"]),
                    "port_service_count": len(netdisc_payload["port_services"]),
                    "passive_discovery_enabled": netdisc_payload["passive_discovery_enabled"],
                    "active_scanning_enabled": netdisc_payload["active_scanning_enabled"],
                    "warnings": netdisc_payload["warnings"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    elif phase == "recon":
        recon_payload = json.loads(extra_files[0].read_text(encoding="utf-8"))
        files["coverage"].write_text(
            json.dumps(
                {
                    "phase": "recon",
                    "status": "complete",
                    "endpoint_count": len(recon_payload["endpoints"]),
                    "input_vector_count": len(recon_payload["input_vectors"]),
                    "network_entity_count": len(recon_payload["network_entities"]),
                    "privilege_role_count": len(recon_payload["privilege_roles"]),
                    "authz_candidate_count": len(recon_payload["authz_candidates"]),
                    "high_priority_authz_count": sum(
                        1 for c in recon_payload["authz_candidates"] if c.get("priority") == "high"
                    ),
                    "live_observation_count": len(recon_payload["live_observations"]),
                    "warnings": recon_payload["warnings"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    elif phase == "vuln":
        vuln_payload = json.loads(extra_files[0].read_text(encoding="utf-8"))
        _all = (
            vuln_payload.get("injection", {}).get("findings", [])
            + vuln_payload.get("xss", {}).get("findings", [])
            + vuln_payload.get("ssrf", {}).get("findings", [])
            + vuln_payload.get("auth", {}).get("findings", [])
            + vuln_payload.get("authz", {}).get("findings", [])
        )
        files["coverage"].write_text(
            json.dumps(
                {
                    "phase": "vuln",
                    "status": "complete",
                    "injection_count": len(vuln_payload.get("injection", {}).get("findings", [])),
                    "xss_count": len(vuln_payload.get("xss", {}).get("findings", [])),
                    "ssrf_count": len(vuln_payload.get("ssrf", {}).get("findings", [])),
                    "auth_count": len(vuln_payload.get("auth", {}).get("findings", [])),
                    "authz_count": len(vuln_payload.get("authz", {}).get("findings", [])),
                    "total_findings": len(_all),
                    "critical_count": sum(1 for f in _all if f.get("severity") == "critical"),
                    "high_count": sum(1 for f in _all if f.get("severity") == "high"),
                    "externally_exploitable_count": sum(1 for f in _all if f.get("externally_exploitable")),
                    "warnings": vuln_payload.get("warnings", []),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    elif phase == "report" and _report_result:
        fs = _report_result["findings_summary"]
        retest_plan = _report_result["retest_plan"]
        files["coverage"].write_text(
            json.dumps(
                {
                    "phase": "report",
                    "status": "complete",
                    "total_findings": fs["total"],
                    "critical_count": fs["critical"],
                    "high_count": fs["high"],
                    "medium_count": fs["medium"],
                    "low_count": fs["low"],
                    "info_count": fs["info"],
                    "externally_exploitable_count": fs["externally_exploitable"],
                    "retest_step_count": len(retest_plan.retest_steps),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    evidence_path = store.phase_dir(phase) / "evidence" / "stub.txt"
    if phase not in _REAL_PHASES:
        evidence_path.write_text("evidence", encoding="utf-8")
    if phase not in _REAL_PHASES:
        extra_files = _write_extra_phase_artifacts(
            store,
            phase,
            cfg=cfg,
            url=url,
            repo_path=repo_path,
            safe_mode=cfg.safety.safe_mode,
            workspace=workspace,
        )
    index_paths = [*files.values(), *extra_files]
    if phase not in _REAL_PHASES:
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
    heartbeat_task.cancel()
    return {"phase": phase, "status": "completed"}


# Per-phase activity wrappers — each has a distinct registered name so the
# Temporal UI shows "run_prerecon_activity" instead of the generic
# "run_phase_activity" for every phase.

@activity.defn(name="run_intake_activity")
async def run_intake_activity(workspace_root: str, workspace: str, run_id: str, repo_path: str, url: str, force: bool, effective_config_path: str = "adversa.toml") -> dict:
    return await _run_phase_impl(workspace_root, workspace, run_id, repo_path, url, "intake", force, effective_config_path)


@activity.defn(name="run_prerecon_activity")
async def run_prerecon_activity(workspace_root: str, workspace: str, run_id: str, repo_path: str, url: str, force: bool, effective_config_path: str = "adversa.toml") -> dict:
    return await _run_phase_impl(workspace_root, workspace, run_id, repo_path, url, "prerecon", force, effective_config_path)


@activity.defn(name="run_netdisc_activity")
async def run_netdisc_activity(workspace_root: str, workspace: str, run_id: str, repo_path: str, url: str, force: bool, effective_config_path: str = "adversa.toml") -> dict:
    return await _run_phase_impl(workspace_root, workspace, run_id, repo_path, url, "netdisc", force, effective_config_path)


@activity.defn(name="run_recon_activity")
async def run_recon_activity(workspace_root: str, workspace: str, run_id: str, repo_path: str, url: str, force: bool, effective_config_path: str = "adversa.toml") -> dict:
    return await _run_phase_impl(workspace_root, workspace, run_id, repo_path, url, "recon", force, effective_config_path)


@activity.defn(name="run_vuln_activity")
async def run_vuln_activity(workspace_root: str, workspace: str, run_id: str, repo_path: str, url: str, force: bool, effective_config_path: str = "adversa.toml") -> dict:
    return await _run_phase_impl(workspace_root, workspace, run_id, repo_path, url, "vuln", force, effective_config_path)


@activity.defn(name="run_report_activity")
async def run_report_activity(workspace_root: str, workspace: str, run_id: str, repo_path: str, url: str, force: bool, effective_config_path: str = "adversa.toml") -> dict:
    return await _run_phase_impl(workspace_root, workspace, run_id, repo_path, url, "report", force, effective_config_path)


# Keep old name registered for backwards compatibility with in-flight workflows
@activity.defn
async def run_phase_activity(workspace_root: str, workspace: str, run_id: str, repo_path: str, url: str, phase: str, force: bool, effective_config_path: str = "adversa.toml") -> dict:
    return await _run_phase_impl(workspace_root, workspace, run_id, repo_path, url, phase, force, effective_config_path)


@activity.defn
async def provider_health_check(effective_config_path: str) -> None:
    cfg = load_config(effective_config_path)
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
    if any(k in msg for k in ["429", "timeout", "temporarily unavailable", "structured_response", "1210", "invalid api parameter", "badrequest", "not found in the current page snapshot", "try capturing new snapshot", "500", "server_error", "internalservererror", "unknown error in the model inference"]):
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
