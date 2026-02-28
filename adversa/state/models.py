from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


class EvidenceRef(BaseModel):
    id: str = Field(description="Stable identifier for the evidence item within a phase output.")
    path: str = Field(description="Workspace-relative path to the evidence artifact on disk.")
    note: str | None = Field(default=None, description="Optional human-readable context about why this evidence matters.")


class PhaseOutput(BaseModel):
    phase: Literal["intake", "prerecon", "recon", "vuln", "report"] = Field(
        description="Lifecycle phase that produced this output."
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this phase output was generated.",
    )
    summary: str = Field(description="Short narrative summary of the phase result.")
    evidence: list[EvidenceRef] = Field(
        default_factory=list,
        description="Evidence references that support the phase summary and data.",
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured phase-specific payload written alongside the summary.",
    )


class PlanBudget(BaseModel):
    time_budget_minutes: int = Field(description="Maximum wall-clock budget allocated to the run plan in minutes.")
    token_budget: int = Field(description="Maximum model token budget allocated to the run plan.")
    cost_budget_usd: float = Field(description="Maximum provider spend budget allocated to the run plan in USD.")
    tool_call_budget: int = Field(description="Maximum number of tool invocations allowed across the run plan.")


class PhaseExpectation(BaseModel):
    phase: Literal["intake", "prerecon", "recon", "vuln", "report"] = Field(
        description="Phase this execution expectation applies to."
    )
    selected_analyzers: list[str] = Field(
        default_factory=list,
        description="Deterministically selected analyzers planned for this phase.",
    )
    required_artifacts: list[str] = Field(
        default_factory=list,
        description="Schema-valid artifacts the phase is expected to emit.",
    )
    goals: list[str] = Field(
        default_factory=list,
        description="Operator-readable goals that explain what the phase should accomplish.",
    )
    constraints: list[str] = Field(
        default_factory=list,
        description="Constraints that the phase must respect during execution.",
    )


class PlanWarning(BaseModel):
    code: str = Field(description="Stable machine-readable warning code.")
    message: str = Field(description="Operator-readable warning emitted during planning.")


class RunPlan(BaseModel):
    phases: list[Literal["intake", "prerecon", "recon", "vuln", "report"]] = Field(
        default_factory=list,
        description="Ordered lifecycle phases that the run intends to execute.",
    )
    phase_expectations: list[PhaseExpectation] = Field(
        default_factory=list,
        description="Per-phase execution contract including analyzers, artifacts, goals, and constraints.",
    )
    budgets: PlanBudget = Field(description="Safe-mode execution budgets for time, tokens, cost, and tool usage.")
    max_concurrent_pipelines: int = Field(
        description="Maximum number of concurrent execution pipelines allowed by the plan."
    )
    constraints: list[str] = Field(
        default_factory=list,
        description="Global execution constraints that apply to the entire run.",
    )
    warnings: list[PlanWarning] = Field(
        default_factory=list,
        description="Actionable planner warnings about blocked phases, empty analyzer sets, or unsupported combinations.",
    )
    rationale: str = Field(description="Operator-readable explanation of how this plan was derived.")
    safe_mode: bool = Field(description="Whether the plan is constrained to safe verification mode.")


class ScopeContract(BaseModel):
    target_url: str = Field(description="Normalized authorized target URL for this run.")
    repo_path: str = Field(description="Authorized repository path under the local repos root.")
    workspace: str = Field(description="Workspace name used to group this run.")
    authorized: bool = Field(description="Whether the operator explicitly acknowledged authorization.")
    safe_mode: bool = Field(description="Whether execution remains constrained to safe mode.")
    source_precedence: list[str] = Field(
        default_factory=list,
        description="Ordered sources used to derive this scope contract.",
    )
    normalized_host: str = Field(description="Normalized host extracted from the authorized target URL.")
    normalized_path: str = Field(description="Normalized path extracted from the authorized target URL.")
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Hosts explicitly allowed for this run.",
    )
    allowed_subdomains: list[str] = Field(
        default_factory=list,
        description="Subdomains explicitly allowed for this run.",
    )
    allowed_paths: list[str] = Field(
        default_factory=list,
        description="Path prefixes or concrete paths explicitly allowed for this run.",
    )
    exclusions: list[str] = Field(
        default_factory=list,
        description="Operator-provided out-of-scope targets or exclusions.",
    )
    capability_constraints: list[str] = Field(
        default_factory=list,
        description="Execution capability constraints derived from safety mode and config.",
    )
    repo_root_validated: bool = Field(description="Whether the repository path passed repo-root enforcement checks.")
    evidence_expectations: list[str] = Field(
        default_factory=list,
        description="Evidence requirements downstream phases should preserve.",
    )
    notes: list[str] = Field(
        default_factory=list,
        description="Operator-provided notes that should accompany the scope contract.",
    )
    rules_summary: dict[str, list[dict[str, str]]] = Field(
        default_factory=dict,
        description="Summary of focus/avoid rules resolved from intake or config with type/value/source metadata.",
    )
    confidence_gaps: list[str] = Field(
        default_factory=list,
        description="Scope ambiguities that later phases should preserve as warnings.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Structured normalization warnings that should remain visible to operators and later phases.",
    )


class IntakeCoverage(BaseModel):
    phase: Literal["intake"] = Field(description="Coverage artifact phase identifier.")
    status: Literal["complete", "incomplete"] = Field(description="Whether intake gathered enough information to proceed.")
    answered_fields: list[str] = Field(
        default_factory=list,
        description="Fields that were explicitly answered during the interactive intake flow.",
    )
    pending_fields: list[str] = Field(
        default_factory=list,
        description="Fields still missing or deferred after intake completion.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Operator-facing intake warnings captured during scope clarification.",
    )


class PreReconReport(BaseModel):
    target_url: str = Field(description="Authorized target URL evaluated during prerecon.")
    canonical_url: str = Field(description="Normalized canonical URL used for prerecon baselining.")
    host: str = Field(description="Normalized host extracted from the target URL.")
    path: str = Field(description="Normalized path extracted from the target URL.")
    repo_path: str = Field(description="Authorized repository path inspected during prerecon.")
    repo_root_validated: bool = Field(description="Whether the repository path passed repo-root validation before inspection.")
    repo_top_level_entries: list[str] = Field(
        default_factory=list,
        description="Deterministically sorted top-level files and directories discovered in the target repository.",
    )
    framework_signals: list[str] = Field(
        default_factory=list,
        description="Detected framework and runtime signals inferred from repository files.",
    )
    candidate_routes: list[str] = Field(
        default_factory=list,
        description="Potential application route paths inferred from repository and target inputs.",
    )
    scope_inputs: dict[str, Any] = Field(
        default_factory=dict,
        description="Key normalized intake scope inputs consumed by prerecon.",
    )
    plan_inputs: dict[str, Any] = Field(
        default_factory=dict,
        description="Relevant planner expectations consumed by prerecon.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Operator-facing prerecon warnings and confidence gaps that downstream recon should preserve.",
    )
    remediation_hints: list[str] = Field(
        default_factory=list,
        description="Actionable next steps when prerecon inputs are incomplete or weak.",
    )


class ArtifactEntry(BaseModel):
    path: str = Field(description="Run-relative path to a generated artifact file.")
    sha256: str = Field(description="SHA-256 digest of the artifact contents for reproducibility checks.")


class ArtifactIndex(BaseModel):
    files: list[ArtifactEntry] = Field(
        default_factory=list,
        description="Deterministically sorted list of generated artifacts and their content hashes.",
    )


class ManifestState(BaseModel):
    workspace: str = Field(description="Workspace root or workspace key used to store this run.")
    run_id: str = Field(description="Unique identifier for this run within the workspace.")
    url: str = Field(description="Target URL associated with the run.")
    repo_path: str = Field(description="Repository path for the authorized target under the local repos directory.")
    workflow_id: str | None = Field(default=None, description="Temporal workflow identifier associated with this run.")
    current_phase: str | None = Field(default=None, description="Phase currently executing or most recently executed.")
    completed_phases: list[str] = Field(
        default_factory=list,
        description="Ordered list of phases that completed successfully for this run.",
    )
    waiting_for_config: bool = Field(
        default=False,
        description="Whether execution is blocked pending operator configuration updates.",
    )
    waiting_reason: str | None = Field(default=None, description="Operator-facing explanation for the current waiting state.")
    paused: bool = Field(default=False, description="Whether execution is intentionally paused by operator signal.")
    canceled: bool = Field(default=False, description="Whether the run has been canceled and should not continue.")
    last_error: str | None = Field(default=None, description="Most recent terminal or non-retryable error message, if any.")


class WorkflowInput(BaseModel):
    workspace: str = Field(description="Workspace root or workspace key where run artifacts should be stored.")
    repo_path: str = Field(description="Authorized target repository path under the local repos directory.")
    url: str = Field(description="Target URL for the Adversa run.")
    effective_config_path: str = Field(description="Resolved configuration file path used for this execution.")
    safe_mode: bool = Field(description="Whether the run is restricted to non-destructive safe-mode behavior.")
    run_id: str = Field(description="Unique identifier assigned to this workflow run.")
    force: bool = Field(default=False, description="Whether to re-run phases even when valid artifacts already exist.")


class WorkflowStatus(BaseModel):
    current_phase: str | None = Field(default=None, description="Phase currently executing or most recently executed.")
    completed_phases: list[str] = Field(
        default_factory=list,
        description="Ordered list of phases that have completed or been deterministically skipped.",
    )
    artifact_index_path: str | None = Field(
        default=None,
        description="Workspace-relative path to the artifact index for this run.",
    )
    last_error: str | None = Field(default=None, description="Most recent terminal or non-retryable error message, if any.")
    waiting_reason: str | None = Field(default=None, description="Operator-facing explanation for why the workflow is waiting.")
    waiting_for_config: bool = Field(
        default=False,
        description="Whether the workflow is blocked pending configuration changes.",
    )
    paused: bool = Field(default=False, description="Whether the workflow is paused by signal and waiting to resume.")
    canceled: bool = Field(default=False, description="Whether the workflow has been canceled.")


PHASES = ["intake", "prerecon", "recon", "vuln", "report"]


def schema_export(target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    for model in [
        EvidenceRef,
        PhaseOutput,
        PlanBudget,
        PhaseExpectation,
        PlanWarning,
        RunPlan,
        ScopeContract,
        IntakeCoverage,
        PreReconReport,
        ArtifactIndex,
        ManifestState,
        WorkflowInput,
        WorkflowStatus,
    ]:
        path = target_dir / f"{model.__name__}.json"
        path.write_text(json.dumps(model.model_json_schema(), indent=2, sort_keys=True), encoding="utf-8")
