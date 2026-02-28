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
    for model in [EvidenceRef, PhaseOutput, ArtifactIndex, ManifestState, WorkflowInput, WorkflowStatus]:
        path = target_dir / f"{model.__name__}.json"
        path.write_text(json.dumps(model.model_json_schema(), indent=2, sort_keys=True), encoding="utf-8")
